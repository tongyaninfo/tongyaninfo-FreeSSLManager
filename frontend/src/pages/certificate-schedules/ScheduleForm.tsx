import {
  Alert,
  AutoComplete,
  Checkbox,
  DatePicker,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
} from 'antd';
import type { Dayjs } from 'dayjs';
import React, { useEffect, useRef, useState } from 'react';
import {
  providerNames,
  useCloudAccounts,
  useResultMessage,
} from '@/components/ssl-manager';
import { domainApi } from '@/services/ssl-manager/api';
import {
  acmeDirectories,
  dnsZoneLabel,
  matchingDnsZones,
} from '@/services/ssl-manager/certificatePresentation';
import {
  type CertificateSchedule,
  type CertificateScheduleInput,
  certificateScheduleApi,
} from '@/services/ssl-manager/certificateSchedule';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import { normalizeDeploymentDomain } from '@/services/ssl-manager/deploymentSource';
import type { DeploymentTarget } from '@/services/ssl-manager/deploymentTypes';
import type { DnsZone } from '@/services/ssl-manager/types';
import {
  defaultScheduleFirstRun,
  scheduleDate,
  scheduleUnitNames,
} from './presentation';

type FormValues = Omit<CertificateScheduleInput, 'firstRunAtUtc'> & {
  firstRunAt: Dayjs;
};

/** 保存即确定账号、域名、周期和目标清单，启用后后台无需浏览器持续打开。 */
export default function ScheduleForm({
  open,
  schedule,
  onClose,
  onSaved,
}: {
  open: boolean;
  schedule?: CertificateSchedule;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form] = Form.useForm<FormValues>();
  const { accounts, error: accountError } = useCloudAccounts();
  const showResult = useResultMessage();
  const [targets, setTargets] = useState<DeploymentTarget[]>([]);
  const [zones, setZones] = useState<DnsZone[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const sequence = useRef(0);
  const accountId = Form.useWatch('accountId', form);
  const domain = Form.useWatch('domain', form);
  const enabled = Form.useWatch('enabled', form);
  const revokeOld = Form.useWatch('revokeOldCertificates', form);
  const account = accounts.find((item) => item.id === accountId);
  const staging =
    account?.provider === 'Acme' &&
    account.acmeDirectoryUrl === acmeDirectories.staging;
  const validationMode = Form.useWatch('validationMode', form);
  const accountZones = zones.filter((item) => item.status !== 'NotPresent');
  const normalizedDomain = normalizeDeploymentDomain(domain);
  const dnsZones = matchingDnsZones(zones, accounts, normalizedDomain);
  const selectedIds = Form.useWatch('targetIds', form) || [];
  const supported = targets.filter((item) =>
    [
      'linux.files.ssh.v1',
      'safeline.ce.9.x',
      'synology.dsm.7.x',
      'harbor.compose.ssh.v1',
    ].includes(item.executorKey),
  );
  const targetOptions = supported.map((item) => {
    const mismatched =
      ['linux.files.ssh.v1', 'harbor.compose.ssh.v1'].includes(
        item.executorKey,
      ) &&
      (!item.configuration?.sourceDomain ||
        normalizeDeploymentDomain(item.configuration.sourceDomain) !==
          normalizedDomain);
    return {
      value: item.id,
      disabled: !item.enabled || mismatched,
      label: `${item.name} · ${item.endpoint}${!item.enabled ? ' · 已停用' : mismatched ? (item.configuration.sourceDomain ? ` · 绑定 ${item.configuration.sourceDomain}` : ' · 请先设置目标绑定域名') : ''}`,
    };
  });
  for (const id of selectedIds) {
    if (!targetOptions.some((item) => item.value === id))
      targetOptions.push({
        value: id,
        disabled: true,
        label: `已不可用目标：${id}`,
      });
  }

  useEffect(() => {
    if (!open) return;
    form.resetFields();
    setError('');
    form.setFieldsValue(
      schedule
        ? { ...schedule, firstRunAt: scheduleDate(schedule.firstRunAtUtc) }
        : {
            name: '',
            accountId: '',
            domain: '',
            alias: '',
            enabled: true,
            validationMode: 'ManagedDns',
            autoCleanup: true,
            revokeOldCertificates: true,
            intervalValue: 1,
            intervalUnit: 'month',
            firstRunAt: defaultScheduleFirstRun(),
            targetIds: [],
          },
    );
  }, [open, schedule, form]);

  useEffect(() => {
    const current = ++sequence.current;
    if (!open) return;
    setLoading(true);
    const load = async () => {
      const allTargets: DeploymentTarget[] = [];
      const allZones: DnsZone[] = [];
      const collectTargets = async () => {
        for (let page = 1; ; page++) {
          const result = await deploymentApi.targets({ page, pageSize: 200 });
          if (!result.success || !result.data)
            throw new Error(result.message || '部署目标加载失败');
          allTargets.push(...result.data.items);
          if (allTargets.length >= result.data.total) return;
          if (!result.data.items.length)
            throw new Error('部署目标分页不完整，请刷新后重试。');
        }
      };
      const collectZones = async () => {
        for (let page = 1; ; page++) {
          const result = await domainApi.list({ page, pageSize: 100 });
          if (!result.success || !result.data)
            throw new Error(result.message || '托管域加载失败');
          allZones.push(...result.data.items);
          if (allZones.length >= result.data.total) return;
          if (!result.data.items.length)
            throw new Error('托管域分页不完整，请刷新后重试。');
        }
      };
      try {
        await Promise.all([collectTargets(), collectZones()]);
        if (current !== sequence.current) return;
        setTargets(allTargets);
        setZones(allZones);
      } catch (exception) {
        if (current === sequence.current)
          setError(
            exception instanceof Error ? exception.message : '配置选项加载失败',
          );
      } finally {
        if (current === sequence.current) setLoading(false);
      }
    };
    void load();
    return () => {
      sequence.current++;
    };
  }, [open]);

  const save = async () => {
    try {
      const { firstRunAt, ...values } = await form.validateFields();
      setSaving(true);
      setError('');
      const result = await certificateScheduleApi.save(schedule?.id, {
        ...values,
        domain: normalizeDeploymentDomain(values.domain),
        firstRunAtUtc: firstRunAt.toISOString(),
        configRevision: schedule?.configRevision,
        dnsZoneId:
          values.validationMode === 'ManagedDns'
            ? values.dnsZoneId || null
            : null,
      });
      if (showResult(result, '计划任务已保存')) {
        onSaved();
        onClose();
      } else setError(result.message);
    } catch (exception) {
      // 表单校验错误由字段就地展示，不显示为服务器异常。
      if (exception instanceof Error) setError(exception.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      title={schedule ? '编辑计划任务' : '新建计划任务'}
      open={open}
      width={850}
      onCancel={onClose}
      onOk={save}
      okText="保存计划"
      cancelText="取消"
      confirmLoading={saving}
      okButtonProps={{ disabled: loading || !!accountError }}
    >
      {(error || accountError) && (
        <Alert
          type="error"
          showIcon
          title={error || accountError}
          style={{ marginBottom: 16 }}
        />
      )}
      <Form form={form} layout="vertical" name="certificate-schedule">
        <Space align="start" wrap>
          <Form.Item
            name="name"
            label="任务名称"
            rules={[
              { required: true, message: '请输入任务名称' },
              { max: 100 },
            ]}
          >
            <Input style={{ width: 450 }} />
          </Form.Item>
          <Form.Item name="enabled" label="启用计划" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Space>
        <Form.Item
          name="accountId"
          label="证书账号"
          rules={[{ required: true, message: '请选择证书账号' }]}
          extra="仅支持已启用且可管理证书的账号；同账号同域名只能启用一条申请计划。"
        >
          <Select
            showSearch={{ optionFilterProp: 'label' }}
            onChange={() => {
              form.setFieldsValue({
                validationMode: 'ManagedDns',
                autoCleanup: true,
                dnsZoneId: undefined,
              });
            }}
            options={accounts
              .filter(
                (item) =>
                  item.provider !== 'Cloudflare' &&
                  item.enabled &&
                  item.useForCertificates,
              )
              .map((item) => ({
                value: item.id,
                label: `${providerNames[item.provider]} / ${item.name}`,
              }))}
          />
        </Form.Item>
        <Form.Item
          name="domain"
          label="证书域名"
          rules={[
            { required: true, message: '请输入单个业务域名' },
            {
              validator: async (_, value: string) => {
                const text = (value || '')
                  .trim()
                  .toLowerCase()
                  .replace(/\.+$/, '');
                if (
                  text &&
                  (text.length > 253 ||
                    !text.includes('.') ||
                    !text
                      .split('.')
                      .every(
                        (label) =>
                          label.length <= 63 &&
                          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
                      ))
                )
                  throw new Error(
                    '请输入单个有效域名，不含协议、路径或通配符。',
                  );
              },
            },
          ]}
          extra={
            accountId
              ? `已同步托管域：${accountZones.map((item) => item.name || item.domain).join('、') || '暂无；请先同步 DNS 账号的域名。'}；可在下方选择独立 DNS 托管域。`
              : '先选择证书账号，再填写完整域名，例如 vpn.example.com。'
          }
        >
          <AutoComplete
            options={Array.from(
              new Set(
                accountZones.map((item) => item.name || item.domain || ''),
              ),
            )
              .filter(Boolean)
              .map((value) => ({ value }))}
            placeholder="例如 vpn.example.com"
          />
        </Form.Item>
        <Form.Item name="alias" label="备注名称" rules={[{ max: 100 }]}>
          <Input />
        </Form.Item>
        <Space align="start" wrap>
          <Form.Item
            name="validationMode"
            label="自动 DNS 验证方式"
            rules={[{ required: true }]}
          >
            <Select
              style={{ width: 260 }}
              options={[
                { value: 'ManagedDns', label: '本平台托管 DNS 验证' },
                ...(account?.provider === 'Acme'
                  ? []
                  : [
                      {
                        value: 'NativeAutoDns',
                        label: '云平台自动 DNS 验证',
                      },
                    ]),
              ]}
            />
          </Form.Item>
          <Form.Item
            name="autoCleanup"
            label="签发后清理验证记录"
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
        </Space>
        {validationMode === 'ManagedDns' && (
          <Form.Item
            name="dnsZoneId"
            label="DNS 托管域（可使用独立账号）"
            rules={[
              {
                required: account?.provider === 'Acme',
                message: 'ACME 计划必须选择 DNS 托管域',
              },
              {
                validator: async (_, value?: string) => {
                  if (value && !dnsZones.some((zone) => zone.id === value))
                    throw new Error('所选 DNS 托管域不可用或不覆盖证书域名。');
                },
              },
            ]}
            extra="可选 Cloudflare 等独立 DNS 账号；留空沿用证书账号内最长后缀匹配。"
          >
            <Select
              allowClear
              showSearch={{ optionFilterProp: 'label' }}
              options={dnsZones.map((zone) => ({
                value: zone.id,
                label: dnsZoneLabel(zone, accounts),
              }))}
            />
          </Form.Item>
        )}
        {staging && (
          <Alert
            type="warning"
            showIcon
            title="Staging 证书不受公网信任，不能保存带部署目标的周期计划；请改用生产环境账号。"
            style={{ marginBottom: 16 }}
          />
        )}
        {account?.provider === 'Aliyun' && (
          <Alert
            type="info"
            showIcon
            title="每轮自动选择可用的免费 TEST 实例；没有可用实例时标记需处理，不自动购买。"
            style={{ marginBottom: 16 }}
          />
        )}
        <Space align="start" wrap>
          <Form.Item
            name="intervalValue"
            label="间隔数"
            rules={[{ required: true }]}
          >
            <InputNumber min={1} max={1200} precision={0} />
          </Form.Item>
          <Form.Item
            name="intervalUnit"
            label="周期单位"
            rules={[{ required: true }]}
          >
            <Select
              style={{ width: 120 }}
              options={Object.entries(scheduleUnitNames).map(
                ([value, label]) => ({ value, label }),
              )}
            />
          </Form.Item>
          <Form.Item
            name="firstRunAt"
            label="首次执行时间（上海时区）"
            rules={[{ required: true, message: '请选择首次执行时间' }]}
          >
            <DatePicker
              showTime={{ format: 'HH:mm' }}
              format="YYYY-MM-DD HH:mm"
            />
          </Form.Item>
        </Space>
        <Form.Item
          name="targetIds"
          label="部署目标"
          rules={[
            { required: true, message: '请选择至少一个部署目标' },
            {
              validator: async (_, ids?: string[]) => {
                if (staging && ids?.length)
                  throw new Error(
                    'Staging 测试证书不能部署，请使用生产环境 ACME 账号。',
                  );
                if (
                  ids?.some(
                    (id) =>
                      !targetOptions.some(
                        (option) => option.value === id && !option.disabled,
                      ),
                  )
                )
                  throw new Error('部分目标已停用或绑定其他域名，请重新选择。');
              },
            },
          ]}
          extra="选择 1～20 个目标；仅向本次明确选择的目标部署，后来新增的目标不会自动加入。"
        >
          <Select
            mode="multiple"
            maxCount={20}
            showSearch={{ optionFilterProp: 'label' }}
            loading={loading}
            options={targetOptions}
          />
        </Form.Item>
        <Form.Item name="revokeOldCertificates" valuePropName="checked">
          <Checkbox>吊销删除老证书</Checkbox>
        </Form.Item>
        {revokeOld && (
          <Alert
            type="warning"
            showIcon
            title="所有目标部署成功后，才清理同账号同域名的旧证书。"
            description="旧证书未过期时先吊销，确认后再删除；已过期直接删除。需要 DNS 吊销验证且域名由本平台托管时会自动处理，旧证书删除后再清理本轮创建的验证记录。清理异常会单独记录，不改变已成功的部署结果。"
            style={{ marginBottom: 16 }}
          />
        )}
        {enabled && (
          <Alert
            type="info"
            showIcon
            title="保存并启用后，后台将按周期申请新证书，签发后自动向所选目标部署，并执行目标配置的验证、刷新或重启命令。"
          />
        )}
        <div style={{ marginTop: 12, color: '#666' }}>
          按首次执行时间保持周期锚点；月末不足时取当月最后一天。立即执行一次不改变周期，服务恢复后只补跑一轮。
        </div>
      </Form>
    </Modal>
  );
}
