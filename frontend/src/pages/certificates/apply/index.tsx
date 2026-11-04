import {
  PageContainer,
  ProForm,
  ProFormGroup,
  type ProFormInstance,
  ProFormSelect,
  ProFormSwitch,
  ProFormText,
  StepsForm,
} from '@ant-design/pro-components';
import { history } from '@umijs/max';
import { Alert, AutoComplete, Card, Descriptions } from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import {
  providerNames,
  useCloudAccounts,
  useResultMessage,
} from '@/components/ssl-manager';
import {
  accountApi,
  certificateApi,
  domainApi,
} from '@/services/ssl-manager/api';
import {
  acmeDirectories,
  dnsZoneLabel,
  matchingDnsZones,
} from '@/services/ssl-manager/certificatePresentation';
import type {
  ApplyCertificate,
  AliyunCertificateInstanceOption,
  DnsZone,
  ValidationMode,
} from '@/services/ssl-manager/types';

const validationNames = {
  NativeAutoDns: '自动 DNS 验证',
  ManagedDns: '本平台托管 DNS 验证',
  ManualDns: '手动 DNS 验证',
  File: '文件验证',
};

const domainLabelPattern = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

function composeDomain(prefixValue: unknown, suffixValue: unknown) {
  const prefix = String(prefixValue ?? '')
    .trim()
    .toLowerCase()
    .replace(/\.+$/, '');
  const suffix = String(suffixValue ?? '')
    .trim()
    .toLowerCase()
    .replace(/\.+$/, '');
  const domain = prefix ? `${prefix}.${suffix}` : suffix;
  if (!suffix) return { domain: '', error: '请选择证书绑定域名后缀。' };
  if (domain.includes('*')) {
    return { domain: '', error: '免费证书申请不支持泛域名，请填写单个域名。' };
  }
  const valid =
    domain.length <= 253 &&
    domain.includes('.') &&
    domain
      .split('.')
      .every((label) => label.length <= 63 && domainLabelPattern.test(label));
  return valid
    ? { domain }
    : {
        domain: '',
        error: '请输入有效的域名前缀，不能包含协议、路径或非法字符。',
      };
}

export default function Apply() {
  const showResult = useResultMessage();
  const { accounts, error: accountError } = useCloudAccounts();
  const [draft, setDraft] = useState<Partial<ApplyCertificate>>({
    autoCleanup: true,
    apiVersion: 'V2',
  });
  const [mode, setMode] = useState<ValidationMode>('ManagedDns');
  const [zones, setZones] = useState<DnsZone[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<string>();
  const [aliyunInstances, setAliyunInstances] = useState<
    AliyunCertificateInstanceOption[]
  >([]);
  const [loadingAliyunInstances, setLoadingAliyunInstances] = useState(false);
  const [error, setError] = useState('');
  const validationFormRef = useRef<ProFormInstance>(undefined);
  const loadZones = async () => {
    const all: DnsZone[] = [];
    let page = 1;
    let total = 0;
    do {
      const result = await domainApi.list({ page, pageSize: 100 });
      if (!result.success || !result.data) {
        setError(result.message || '域名加载失败');
        setZones([]);
        return;
      }
      all.push(...result.data.items);
      total = result.data.total;
      if (all.length < total && result.data.items.length === 0) {
        setError('域名分页数据不完整，请重新同步');
        setZones([]);
        return;
      }
      page += 1;
    } while (all.length < total);
    setZones(all);
    setError('');
  };
  useEffect(() => {
    loadZones();
  }, []);
  const accountId = selectedAccountId || draft.accountId;
  const selectedAccount = accounts.find((item) => item.id === accountId);
  const acme = selectedAccount?.provider === 'Acme';
  const staging =
    acme && selectedAccount.acmeDirectoryUrl === acmeDirectories.staging;
  const accountZones = zones.filter((zone) => zone.status !== 'NotPresent');
  const availableDnsZones = matchingDnsZones(
    zones,
    accounts,
    draft.domain || '',
  );
  const selectedDnsZone = zones.find((zone) => zone.id === draft.dnsZoneId);
  const isAliyunAccount = selectedAccount?.provider === 'Aliyun';
  useEffect(() => {
    // 切换签发平台时清除旧验证参数，避免把原生自动 DNS 或旧区域带给新平台。
    const validationMode = 'ManagedDns';
    setMode(validationMode);
    setDraft((previous) => ({
      ...previous,
      validationMode,
      dnsZoneId: undefined,
      autoCleanup: true,
    }));
    validationFormRef.current?.setFieldsValue({
      validationMode,
      dnsZoneId: undefined,
      autoCleanup: true,
    });
  }, [accountId, selectedAccount?.provider]);
  useEffect(() => {
    let active = true;
    setAliyunInstances([]);
    setLoadingAliyunInstances(false);
    if (!accountId || !isAliyunAccount) return undefined;
    setLoadingAliyunInstances(true);
    accountApi.aliyunInstances(String(accountId)).then((result) => {
      if (!active) return;
      setLoadingAliyunInstances(false);
      if (result.success) {
        setAliyunInstances(result.data ?? []);
        setError('');
      } else {
        setError(result.message || '阿里云免费证书实例加载失败');
      }
    });
    return () => {
      active = false;
    };
  }, [accountId, isAliyunAccount]);
  const accountDomainOptions = accountZones
    .map((zone) => zone.name || zone.domain || '')
    .filter((name, index, values) => name && values.indexOf(name) === index)
    .map((name) => ({ label: name, value: name }));
  const automatic = mode === 'NativeAutoDns' || mode === 'ManagedDns';
  return (
    <PageContainer
      title="申请免费 SSL 证书"
      onBack={() => history.push('/certificates')}
    >
      <Card>
        {(error || accountError) && (
          <Alert
            title={error || accountError}
            type="error"
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}
        <StepsForm<ApplyCertificate>
          onFinish={async () => {
            if (!draft.accountId || !draft.domain || !draft.validationMode)
              return false;
            const result = await certificateApi.apply(
              draft as ApplyCertificate,
            );
            if (!showResult(result, '申请已提交，请在证书列表中查看审核进度'))
              return false;
            // 证书详情在列表中使用对话框展示，申请完成后回到列表即可继续查看状态。
            history.replace('/certificates');
            return true;
          }}
        >
          <StepsForm.StepForm
            title="选择账号与域名"
            onFinish={async (values) => {
              const accountValue = String(values.accountId || '');
              if (!accountValue) {
                setError('请选择证书申请账号。');
                return false;
              }
              const composed = composeDomain(
                values.domainPrefix,
                values.domainSuffix,
              );
              if (composed.error || !values.accountId) {
                setError(composed.error || '请选择证书申请账号。');
                return false;
              }
              const valuesForDraft = { ...values } as Record<string, unknown>;
              delete valuesForDraft.domainPrefix;
              delete valuesForDraft.domainSuffix;
              const accountChanged =
                selectedAccountId !== String(values.accountId);
              setSelectedAccountId(String(values.accountId));
              if (accountChanged) {
                setAliyunInstances([]);
              }
              setDraft((previous) => ({
                ...previous,
                ...(accountChanged ? { instanceId: undefined } : {}),
                ...valuesForDraft,
                domain: composed.domain,
                apiVersion: 'V2',
              }));
              setError('');
              return true;
            }}
          >
            <ProFormSelect
              name="accountId"
              label="证书申请账号"
              options={accounts
                .filter(
                  (item) =>
                    item.provider !== 'Cloudflare' &&
                    item.enabled &&
                    item.useForCertificates,
                )
                .map((item) => ({
                  label: `${providerNames[item.provider]} / ${item.name}`,
                  value: item.id,
                }))}
              rules={[{ required: true, message: '请选择证书账号' }]}
              fieldProps={{
                onChange: (value) => {
                  setSelectedAccountId(value ? String(value) : undefined);
                  setError('');
                },
              }}
            />
            <ProFormGroup>
              <ProFormText
                name="domainPrefix"
                label="绑定域名前缀"
                placeholder="例如 disk.nt；根域名可留空"
                extra="只填写后缀前面的部分，不要输入完整域名或协议。"
              />
              <ProForm.Item
                name="domainSuffix"
                label="绑定域名后缀"
                rules={[{ required: true, message: '请输入或选择域名后缀' }]}
                extra={
                  accountId && accountDomainOptions.length === 0
                    ? '暂无已同步域名，可直接手工输入，例如 example.com。'
                    : '可选择已同步域名，也可直接手工输入；DNS 账号可与证书账号不同。'
                }
              >
                <AutoComplete
                  options={accountDomainOptions}
                  placeholder={
                    accountId ? '请选择或输入域名后缀' : '请先选择证书申请账号'
                  }
                />
              </ProForm.Item>
            </ProFormGroup>
            <ProFormText name="alias" label="备注名称" />
            <Alert
              type="info"
              title="公网 CA 证书可使用独立 Cloudflare DNS 账号自动验证；请先同步 DNS 托管域。免费额度与有效期以签发平台为准。"
              showIcon
            />
          </StepsForm.StepForm>
          <StepsForm.StepForm
            title="设置验证与清理"
            formRef={validationFormRef}
            initialValues={{
              validationMode: mode,
              autoCleanup: true,
            }}
            onFinish={async (values) => {
              const dnsZoneId = String(values.dnsZoneId || '');
              if (
                mode === 'ManagedDns' &&
                dnsZoneId &&
                !availableDnsZones.some((zone) => zone.id === dnsZoneId)
              ) {
                setError('所选 DNS 托管域不可用或不覆盖申请域名，请重新选择。');
                return false;
              }
              if (acme && mode === 'ManagedDns' && !dnsZoneId) {
                setError('ACME 自动验证必须选择独立 DNS 托管域。');
                return false;
              }
              setDraft((previous) => ({
                ...previous,
                ...values,
                validationMode: mode,
                dnsZoneId:
                  mode === 'ManagedDns' ? dnsZoneId || undefined : undefined,
                autoCleanup: automatic && values.autoCleanup !== false,
              }));
              setError('');
              return true;
            }}
          >
            <ProFormSelect
              name="validationMode"
              label="域名验证方式"
              options={Object.entries(validationNames)
                .filter(
                  ([value]) =>
                    !acme || value === 'ManagedDns' || value === 'ManualDns',
                )
                .map(([value, label]) => ({
                  value,
                  label,
                }))}
              fieldProps={{
                onChange: (value) => setMode(value as ValidationMode),
              }}
              rules={[{ required: true }]}
            />
            {staging && (
              <Alert
                type="warning"
                showIcon
                title="当前为 Let’s Encrypt Staging 测试环境，签发证书不受公网信任，不能用于正式部署。"
                style={{ marginBottom: 16 }}
              />
            )}
            {mode === 'NativeAutoDns' && (
              <Alert
                title={
                  selectedAccount?.provider === 'TencentCloud'
                    ? '腾讯云会使用云平台自动 DNS 验证；签发成功后按自动清理选项处理验证记录。'
                    : '阿里云没有独立的自动清理开关，平台会按托管 DNS 写入验证记录；签发成功后按自动清理选项删除本次记录。'
                }
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
              />
            )}
            {mode === 'ManagedDns' && (
              <>
                <ProFormSelect
                  name="dnsZoneId"
                  label="DNS 托管域（可使用独立账号）"
                  options={availableDnsZones.map((zone) => ({
                    value: zone.id,
                    label: dnsZoneLabel(zone, accounts),
                  }))}
                  placeholder={
                    acme
                      ? '请选择用于 DNS-01 验证的托管域'
                      : '留空使用证书账号内最长匹配的托管域'
                  }
                  rules={
                    acme
                      ? [{ required: true, message: '请选择 DNS 托管域' }]
                      : []
                  }
                  fieldProps={{
                    showSearch: true,
                    optionFilterProp: 'label',
                    allowClear: true,
                  }}
                  extra="腾讯云签发、Cloudflare 托管 DNS 时，在此选择 Cloudflare 的域名区域。"
                />
                <Alert
                  type="info"
                  showIcon
                  title="系统将把签发平台返回的 DNS 验证内容写入所选托管域；只清理本次创建且内容仍匹配的记录。"
                  description="留空只匹配同一证书账号的托管域；独立 DNS 账号需要明确选择。"
                />
              </>
            )}
            {automatic && (
              <ProFormSwitch
                name="autoCleanup"
                label="签发成功后自动删除 DNS 验证记录"
                extra="只清理本次申请创建、并且仍与验证快照匹配的记录；清理失败可单独重试。"
              />
            )}
            {!automatic && (
              <Alert
                type="info"
                title={
                  mode === 'ManualDns'
                    ? '提交后请按证书详情中的记录手动添加 DNS 验证，不自动删除手工记录。'
                    : '提交后请按证书详情中的文件路径和内容部署验证文件。'
                }
                showIcon
              />
            )}
            {selectedAccount?.provider === 'Aliyun' && (
              <ProFormSelect
                name="instanceId"
                label="已有免费证书实例 ID"
                options={aliyunInstances.map((item) => ({
                  value: item.instanceId,
                  label: `${item.instanceId}${item.name ? ` · ${item.name}` : ''}`,
                }))}
                fieldProps={{
                  loading: loadingAliyunInstances,
                  showSearch: true,
                  optionFilterProp: 'label',
                  notFoundContent: loadingAliyunInstances
                    ? '正在加载未使用实例…'
                    : '没有可用的免费实例，请先在阿里云控制台领取并确认。',
                }}
                rules={[
                  {
                    required: true,
                    message: 'V2 申请必须选择一个未使用的免费证书实例。',
                  },
                ]}
                extra="仅显示当前账号已领取、免费规格且尚未绑定域名的 V2 实例。"
              />
            )}
          </StepsForm.StepForm>
          <StepsForm.StepForm title="确认申请">
            <Descriptions
              bordered
              column={1}
              items={[
                {
                  key: 'account',
                  label: '证书账号',
                  children: selectedAccount?.name,
                },
                { key: 'domain', label: '绑定域名', children: draft.domain },
                {
                  key: 'mode',
                  label: '验证方式',
                  children: draft.validationMode
                    ? validationNames[draft.validationMode]
                    : '—',
                },
                {
                  key: 'environment',
                  label: '签发环境',
                  children: staging
                    ? 'Staging 测试环境（不受公网信任）'
                    : '生产环境',
                },
                {
                  key: 'dns',
                  label: 'DNS 托管域',
                  children: selectedDnsZone
                    ? dnsZoneLabel(selectedDnsZone, accounts)
                    : '同账号自动匹配 / 手动验证',
                },
                {
                  key: 'cleanup',
                  label: '自动清理验证记录',
                  children: draft.autoCleanup
                    ? '开启：签发成功后清理本次创建的记录'
                    : '关闭',
                },
              ]}
            />
            <Alert
              type="warning"
              showIcon
              title="提交会调用真实签发平台申请接口，并可能占用免费额度。请确认域名、账号与验证方式。"
              style={{ marginTop: 24 }}
            />
          </StepsForm.StepForm>
        </StepsForm>
      </Card>
    </PageContainer>
  );
}
