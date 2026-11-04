import {
  EyeInvisibleOutlined,
  EyeOutlined,
  PlusOutlined,
} from '@ant-design/icons';
import {
  type ActionType,
  ModalForm,
  PageContainer,
  type ProColumns,
  ProFormDependency,
  ProFormDigit,
  ProFormGroup,
  type ProFormInstance,
  ProFormSelect,
  ProFormSwitch,
  ProFormText,
  ProFormTextArea,
  ProFormTimePicker,
  ProTable,
} from '@ant-design/pro-components';
import { useIntl } from '@umijs/max';
import {
  Alert,
  Button,
  Checkbox,
  Descriptions,
  Modal,
  Space,
  Tag,
  Typography,
} from 'antd';
import dayjs from 'dayjs';
import React, { useEffect, useRef, useState } from 'react';
import {
  dateText,
  providerNames,
  tableResult,
  useResultMessage,
  useTableKeyboardPagination,
  useTablePreferences,
} from '@/components/ssl-manager';
import { accountApi } from '@/services/ssl-manager/api';
import { acmeDirectories } from '@/services/ssl-manager/certificatePresentation';
import type {
  AcmeRegistrationView,
  AliyunContact,
  CloudAccount,
} from '@/services/ssl-manager/types';

const syncUnitNames: Record<string, string> = {
  minute: '分钟',
  hour: '小时',
  day: '天',
  month: '月',
};
const acmeAccountStatuses: Record<string, string> = {
  New: '待注册',
  Prepared: '待确认注册',
  Submitting: '注册提交中',
  Registered: '已注册',
  Unknown: '注册结果待核对',
  Failed: '注册失败',
  Provided: '已导入账户',
  Configured: '已配置账户',
};

/** 将时间选择器值转换为服务端约定的 HH:mm 字符串。 */
function formatLocalTime(value: unknown): string {
  if (typeof value === 'string') return value;
  if (
    value &&
    typeof (value as { format?: (format: string) => string }).format ===
      'function'
  ) {
    return (value as { format: (format: string) => string }).format('HH:mm');
  }
  return '02:00';
}

/** 将服务端返回的 HH:mm 转换为时间选择器值。 */
function parseLocalTime(value?: string) {
  const [hours, minutes] = (value || '02:00').split(':').map(Number);
  return dayjs()
    .hour(Number.isFinite(hours) ? hours : 2)
    .minute(Number.isFinite(minutes) ? minutes : 0)
    .second(0)
    .millisecond(0);
}

export default function CloudAccounts() {
  const intl = useIntl();
  const t = (id: string, fallback: string) =>
    intl.formatMessage({ id, defaultMessage: fallback });
  const actionRef = useRef<ActionType>(null);
  const pageState = useRef({ current: 1, pageSize: 20, total: 0 });
  const tablePreferences = useTablePreferences('cloud-accounts');
  const trackPage = useTableKeyboardPagination(actionRef, pageState);
  const showResult = useResultMessage();
  const [editing, setEditing] = useState<CloudAccount>();
  const [open, setOpen] = useState(false);
  const [testingId, setTestingId] = useState('');
  const [diagnostic, setDiagnostic] = useState<Record<string, unknown>>();
  const [registrationAccount, setRegistrationAccount] =
    useState<CloudAccount>();
  const [registrationResult, setRegistrationResult] =
    useState<AcmeRegistrationView>();
  const [registrationError, setRegistrationError] = useState('');
  const [agreeTerms, setAgreeTerms] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [revealed, setRevealed] = useState<{
    id: string;
    accessKeyId: string;
    accessKeySecret: string;
  }>();
  const [revealingId, setRevealingId] = useState('');
  const [aliyunContacts, setAliyunContacts] = useState<AliyunContact[]>([]);
  const [syncingContacts, setSyncingContacts] = useState(false);
  const formRef = useRef<ProFormInstance>(undefined);
  const revealSequence = useRef(0);
  // 关闭编辑/切换账号/卸载页面即丢弃明文，不写浏览器持久化存储。
  useEffect(
    () => () => {
      revealSequence.current += 1;
    },
    [],
  );
  const clearSecrets = () => {
    revealSequence.current += 1;
    setRevealed(undefined);
    setRevealingId('');
  };
  const toggleSecrets = async (id: string) => {
    if (revealed?.id === id) {
      clearSecrets();
      return;
    }
    const sequence = ++revealSequence.current;
    setRevealed(undefined);
    setRevealingId(id);
    const result = await accountApi.secrets(id);
    if (sequence !== revealSequence.current) return;
    setRevealingId('');
    if (showResult(result) && result.data) setRevealed({ id, ...result.data });
  };
  const columns: ProColumns<CloudAccount>[] = [
    { title: t('ssl.field.name', '配置名称'), dataIndex: 'name' },
    {
      title: t('ssl.field.provider', '云平台'),
      dataIndex: 'provider',
      valueEnum: providerNames,
    },
    {
      title: '账号标识 / Account URL',
      dataIndex: 'accessKeyIdMasked',
      search: false,
      render: (_, account) => (
        <Space>
          {account.provider === 'Acme' && (
            <Tag>
              {account.acmeDirectoryUrl === acmeDirectories.staging
                ? 'Staging 测试环境'
                : '生产环境'}
            </Tag>
          )}
          <span style={{ overflowWrap: 'anywhere' }}>
            {revealed?.id === account.id ? (
              revealed.accessKeyId
            ) : account.provider === 'Acme' ? (
              account.accountUrl ? (
                <Typography.Text copyable={{ text: account.accountUrl }}>
                  {account.accountUrl}
                </Typography.Text>
              ) : (
                account.accessKeyIdMasked || '尚未注册'
              )
            ) : (
              account.accessKeyIdMasked
            )}
          </span>
          <Button
            type="text"
            aria-label={
              revealed?.id === account.id ? '隐藏原始密钥' : '显示原始密钥'
            }
            icon={
              revealed?.id === account.id ? (
                <EyeInvisibleOutlined />
              ) : (
                <EyeOutlined />
              )
            }
            loading={revealingId === account.id}
            onClick={() => toggleSecrets(account.id)}
          />
        </Space>
      ),
    },
    {
      title: 'ACME 账户信息',
      search: false,
      render: (_, account) =>
        account.provider === 'Acme' ? (
          <Space direction="vertical" size={0}>
            <span>
              {account.acmeAccountMode === 'Automatic'
                ? '系统注册账户'
                : '已有账户'}{' '}
              ·{' '}
              {acmeAccountStatuses[account.acmeAccountStatus || ''] ||
                account.acmeAccountStatus ||
                '待配置'}
            </span>
            {account.publicKeyThumbprint && (
              <Typography.Text copyable={{ text: account.publicKeyThumbprint }}>
                公钥指纹：{account.publicKeyThumbprint}
              </Typography.Text>
            )}
            {account.registeredAtUtc && (
              <span>注册时间：{dateText(account.registeredAtUtc)}</span>
            )}
          </Space>
        ) : (
          '—'
        ),
    },
    {
      title: '认证凭据',
      search: false,
      render: (_, account) => (
        <span style={{ overflowWrap: 'anywhere' }}>
          {revealed?.id === account.id
            ? revealed.accessKeySecret
            : account.hasAccessKeySecret
              ? '••••••••••••'
              : '未配置'}
        </span>
      ),
    },
    {
      title: t('ssl.field.usage', '用途'),
      search: false,
      render: (_, account) => (
        <Space>
          {account.provider !== 'Cloudflare' && account.useForCertificates && (
            <Tag>证书</Tag>
          )}
          {account.useForDns && <Tag>DNS</Tag>}
        </Space>
      ),
    },
    {
      title: t('ssl.field.status', '状态'),
      dataIndex: 'enabled',
      valueEnum: {
        true: { text: '启用', status: 'Success' },
        false: { text: '停用', status: 'Default' },
      },
    },
    {
      title: t('ssl.field.lastSyncAt', '最近同步'),
      dataIndex: 'lastAutoSyncAtUtc',
      search: false,
      render: (_, account) => {
        // 最近同步由后台自动同步 Worker 写入 LastAutoSyncAtUtc；连接测试时间属于另一项诊断结果，不能混用。
        return dateText(account.lastAutoSyncAtUtc);
      },
    },
    {
      title: t('ssl.page.configuration.syncSchedules', '自动同步'),
      dataIndex: 'autoSyncEnabled',
      search: false,
      render: (_, account) =>
        account.autoSyncEnabled ? (
          <Space direction="vertical" size={0}>
            <Space size={4}>
              {account.provider !== 'Cloudflare' &&
                account.useForCertificates && (
                  <Tag color="processing">SSL 证书</Tag>
                )}
              {account.useForDns && <Tag color="processing">DNS</Tag>}
              {!account.useForCertificates && !account.useForDns && (
                <Tag color="warning">未启用用途</Tag>
              )}
            </Space>
            <span>
              每 {account.autoSyncIntervalValue || 6}
              {syncUnitNames[account.autoSyncIntervalUnit || 'hour'] ||
                account.autoSyncIntervalUnit}
              {account.autoSyncAtLocalTime
                ? ` · ${account.autoSyncAtLocalTime}`
                : ' · 02:00'}
            </span>
          </Space>
        ) : (
          <Tag>停用</Tag>
        ),
    },
    {
      title: t('ssl.page.configuration.syncSchedules', '下次同步'),
      dataIndex: 'nextSyncAtUtc',
      search: false,
      render: (_, account) =>
        dateText(
          account.autoSyncNextRunAtUtc ||
            account.nextSyncAtUtc ||
            account.nextAutoSyncAtUtc,
        ),
    },
    {
      title: t('ssl.column.actions', '操作'),
      valueType: 'option',
      render: (_, account) => [
        <Button
          type="link"
          key="edit"
          onClick={() => {
            clearSecrets();
            setEditing(account);
            setOpen(true);
          }}
        >
          编辑
        </Button>,
        <Button
          type="link"
          key="test"
          loading={testingId === account.id}
          onClick={async () => {
            setTestingId(account.id);
            const result = await accountApi.test(account.id);
            setTestingId('');
            if (showResult(result)) {
              setDiagnostic(result.data ?? {});
              actionRef.current?.reload();
            }
          }}
        >
          测试连接与权限
        </Button>,
        ...(account.provider === 'Acme' &&
        account.acmeAccountMode === 'Automatic' &&
        !['Registered', 'Configured', 'Provided'].includes(
          account.acmeAccountStatus || '',
        )
          ? [
              <Button
                key="register"
                type="link"
                disabled={account.acmeAccountStatus === 'Submitting'}
                onClick={() => {
                  setRegistrationAccount(account);
                  setRegistrationResult(undefined);
                  setRegistrationError('');
                  setAgreeTerms(false);
                }}
              >
                {account.acmeAccountStatus === 'Unknown'
                  ? '核对ACME注册结果'
                  : '注册ACME账户'}
              </Button>,
            ]
          : []),
      ],
    },
  ];
  return (
    <PageContainer
      title={intl.formatMessage({
        id: 'ssl.page.configuration.title',
        defaultMessage: '配置管理',
      })}
      subTitle={intl.formatMessage({
        id: 'ssl.page.configuration.subtitle',
        defaultMessage: '分别配置云平台账号、证书与 DNS 用途',
      })}
    >
      <Alert
        type="info"
        showIcon
        title="密钥只在保存时提交，读取配置仅显示掩码。编辑时留空表示保留原密钥；启停配置不会删除云端资源。"
        style={{ marginBottom: 16 }}
      />
      {loadError && (
        <Alert title={loadError} type="error" style={{ marginBottom: 16 }} />
      )}
      <ProTable<CloudAccount>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        {...tablePreferences}
        search={{ labelWidth: 90 }}
        scroll={{ x: 1000 }}
        request={async ({ current, pageSize, ...params }) => {
          clearSecrets();
          const result = await accountApi.list({
            ...params,
            search: params.name,
            page: current,
            pageSize,
          });
          setLoadError(result.success ? '' : result.message);
          trackPage(current, pageSize, result.data?.total);
          return tableResult(result);
        }}
        toolBarRender={() => [
          <Button
            key="new"
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              clearSecrets();
              setEditing(undefined);
              setOpen(true);
            }}
          >
            新增云平台配置
          </Button>,
        ]}
      />
      <ModalForm
        key={editing?.id || 'new'}
        formRef={formRef}
        title={editing ? '编辑云平台配置' : '新增云平台配置'}
        open={open}
        onOpenChange={(value) => {
          setOpen(value);
          if (!value) {
            clearSecrets();
            setAliyunContacts([]);
          }
        }}
        modalProps={{ destroyOnHidden: true }}
        initialValues={{
          provider: 'TencentCloud',
          enabled: true,
          ...editing,
          useForCertificates:
            editing?.provider === 'Cloudflare'
              ? false
              : (editing?.useForCertificates ?? true),
          useForDns:
            editing?.provider === 'Cloudflare'
              ? true
              : (editing?.useForDns ?? true),
          autoSyncEnabled: editing?.autoSyncEnabled ?? false,
          autoSyncIntervalUnit: editing?.autoSyncIntervalUnit ?? 'hour',
          autoSyncIntervalValue: editing?.autoSyncIntervalValue ?? 6,
          autoSyncAtLocalTime: parseLocalTime(editing?.autoSyncAtLocalTime),
          acmeDirectoryUrl:
            editing?.acmeDirectoryUrl || acmeDirectories.production,
          acmeAccountMode: editing?.acmeAccountMode || 'Existing',
        }}
        onValuesChange={(changedValues) => {
          // 切换云平台或修改密钥后，旧联系人列表不能跨账号复用。
          if (
            'provider' in changedValues ||
            'accessKeyId' in changedValues ||
            'accessKeySecret' in changedValues
          ) {
            setAliyunContacts([]);
            formRef.current?.setFieldValue('aliyunContactId', undefined);
          }
          if ('provider' in changedValues) {
            // 跨平台不复用刚填写的凭据；ACME 不提供 DNS 托管服务。
            formRef.current?.setFieldsValue({
              accessKeyId: '',
              accessKeySecret: '',
              useForDns: changedValues.provider !== 'Acme',
              useForCertificates: changedValues.provider !== 'Cloudflare',
            });
          }
        }}
        onFinish={async (values) => {
          const result = await accountApi.save(editing?.id, {
            ...values,
            ...(values.provider === 'Acme'
              ? {
                  useForDns: false,
                  ...(values.acmeAccountMode === 'Automatic'
                    ? { accessKeyId: '', accessKeySecret: '' }
                    : {}),
                }
              : {}),
            ...(values.provider === 'Cloudflare'
              ? { useForCertificates: false, useForDns: true }
              : {}),
            autoSyncAtLocalTime: formatLocalTime(values.autoSyncAtLocalTime),
          });
          if (!showResult(result, '配置已保存')) return false;
          clearSecrets();
          actionRef.current?.reload();
          return true;
        }}
      >
        {editing && (
          <>
            <Button
              style={{ marginBottom: 16 }}
              icon={
                revealed?.id === editing.id ? (
                  <EyeInvisibleOutlined />
                ) : (
                  <EyeOutlined />
                )
              }
              loading={revealingId === editing.id}
              onClick={() => toggleSecrets(editing.id)}
            >
              {revealed?.id === editing.id
                ? '隐藏已保存的原始密钥'
                : '查看已保存的原始密钥'}
            </Button>
            {revealed?.id === editing.id && (
              <Alert
                type="warning"
                showIcon
                title="已保存的原始密钥（关闭即隐藏）"
                description={
                  <div
                    style={{ overflowWrap: 'anywhere', whiteSpace: 'pre-wrap' }}
                  >
                    <div>
                      {editing.provider === 'Acme'
                        ? 'Account URL'
                        : editing.provider === 'Cloudflare'
                          ? 'Account ID'
                          : 'AccessKey ID'}
                      ：
                      <Typography.Text
                        copyable={{ text: revealed.accessKeyId }}
                      >
                        {revealed.accessKeyId || '未配置'}
                      </Typography.Text>
                    </div>
                    <div>
                      {editing.provider === 'Acme'
                        ? '账号私钥'
                        : editing.provider === 'Cloudflare'
                          ? 'API Token'
                          : 'AccessKey Secret'}
                      ：
                      <Typography.Text
                        copyable={{ text: revealed.accessKeySecret }}
                      >
                        {revealed.accessKeySecret}
                      </Typography.Text>
                    </div>
                  </div>
                }
                style={{ marginBottom: 16 }}
              />
            )}
          </>
        )}
        <ProFormGroup>
          <ProFormText
            name="name"
            label="配置名称"
            width="md"
            rules={[{ required: true, message: '请输入配置名称' }]}
          />
          <ProFormSelect
            name="provider"
            label="云平台"
            width="md"
            valueEnum={providerNames}
            disabled={Boolean(editing)}
            rules={[{ required: true }]}
          />
        </ProFormGroup>
        <ProFormDependency
          name={['provider', 'acmeDirectoryUrl', 'acmeAccountMode']}
        >
          {({ provider, acmeDirectoryUrl, acmeAccountMode }) =>
            provider === 'Acme' ? (
              <>
                <ProFormSelect
                  name="acmeAccountMode"
                  label="ACME 账户接入方式"
                  disabled={Boolean(editing)}
                  options={[
                    { value: 'Existing', label: '已有账户（默认）' },
                    { value: 'Automatic', label: '系统注册账户（需单独确认）' },
                  ]}
                  rules={[{ required: true, message: '请选择账户接入方式' }]}
                />
                <ProFormSelect
                  name="acmeDirectoryUrl"
                  label="Let’s Encrypt 环境"
                  disabled={Boolean(editing)}
                  options={[
                    {
                      value: acmeDirectories.production,
                      label: '生产环境（公网信任）',
                    },
                    {
                      value: acmeDirectories.staging,
                      label: 'Staging 测试环境（不受公网信任）',
                    },
                  ]}
                  rules={[{ required: true, message: '请选择 ACME 环境' }]}
                  extra="正式与 Staging 账户相互独立；已有配置更换环境时请新增账号。"
                />
                {acmeAccountMode === 'Automatic' ? (
                  <Alert
                    type="info"
                    showIcon
                    title="保存配置后，请在列表点击“注册ACME账户”，阅读并同意 CA 条款后再注册。"
                    description="连接测试和证书申请不会注册账户。注册完成后展示账号 URL、公钥指纹和注册时间，每次证书申请复用该账户。"
                    style={{ marginBottom: 16 }}
                  />
                ) : (
                  <>
                    <ProFormText
                      name="accessKeyId"
                      label="既有 ACME Account URL"
                      placeholder={
                        editing
                          ? '已配置；留空保留原账号 URL'
                          : 'https://acme-v02.api.letsencrypt.org/acme/acct/123456'
                      }
                      fieldProps={{ autoComplete: 'off' }}
                      rules={[
                        {
                          required: !editing,
                          message: '请输入已注册 ACME 账户的 Account URL',
                        },
                        {
                          validator: async (_rule: unknown, value?: string) => {
                            if (!value) return;
                            try {
                              const url = new URL(value);
                              const directory = new URL(
                                acmeDirectoryUrl || acmeDirectories.production,
                              );
                              if (
                                url.origin === directory.origin &&
                                !url.username &&
                                !url.password &&
                                !url.search &&
                                !url.hash &&
                                /^\/acme\/acct\/[^/]+$/.test(url.pathname)
                              )
                                return;
                            } catch {
                              /* 非 URL 凭据由字段就地提示，不发给签发服务。 */
                            }
                            throw new Error(
                              'Account URL 必须是所选 CA 返回的 /acme/acct/ 账户地址。',
                            );
                          },
                        },
                      ]}
                      extra="使用所选 CA 返回的账号资源 URL，不能填写用户名、密码或 API Key。"
                    />
                    <ProFormTextArea
                      name="accessKeySecret"
                      label="PEM 格式账号私钥"
                      placeholder={
                        editing
                          ? '留空保留原账号私钥'
                          : '-----BEGIN PRIVATE KEY-----\n粘贴已有 ACME 账号的私钥\n-----END PRIVATE KEY-----'
                      }
                      fieldProps={{
                        rows: 7,
                        autoComplete: 'off',
                        spellCheck: false,
                      }}
                      rules={[
                        {
                          required: !editing,
                          message: '请粘贴既有 ACME 账户的 PEM 私钥',
                        },
                        {
                          validator: async (_rule: unknown, value?: string) => {
                            if (
                              value &&
                              !/^\s*-----BEGIN (PRIVATE KEY|EC PRIVATE KEY|RSA PRIVATE KEY)-----[\s\S]+-----END \1-----\s*$/.test(
                                value,
                              )
                            )
                              throw new Error(
                                '请输入完整 PEM 格式账号私钥，不能使用密码或 API Token。',
                              );
                          },
                        },
                      ]}
                      extra={
                        editing
                          ? '留空保留原账号私钥；已有账号 URL 和私钥不可替换，更换账号请新增接入配置。'
                          : '使用账号私钥，不能使用网站证书私钥或 API Token；保存后由当前实例加密保管。'
                      }
                    />
                    <Alert
                      type="info"
                      showIcon
                      title="先用 ACME 客户端注册账号，导入账号 URL 与账号私钥；已有账户模式不会代注册。"
                      description="请在外部客户端维护账户。联系邮箱仅作可选展示；Staging 证书不受公网信任。"
                      style={{ marginBottom: 16 }}
                    />
                    <Space wrap style={{ marginBottom: 16 }}>
                      <Typography.Link
                        href="https://letsencrypt.org/getting-started/"
                        target="_blank"
                        rel="noreferrer"
                      >
                        Let’s Encrypt 官方接入指引
                      </Typography.Link>
                      <Typography.Link
                        href="https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3"
                        target="_blank"
                        rel="noreferrer"
                      >
                        RFC 8555 账户说明
                      </Typography.Link>
                    </Space>
                  </>
                )}
              </>
            ) : (
              <>
                <ProFormText
                  name="accessKeyId"
                  label={
                    provider === 'Cloudflare'
                      ? 'Cloudflare Account ID（可选）'
                      : 'AccessKey ID / SecretId'
                  }
                  placeholder={
                    editing
                      ? `${editing.accessKeyIdMasked || '已配置'}；留空保留`
                      : provider === 'Cloudflare'
                        ? '可留空；填写时请输入 Account ID'
                        : '请输入 AccessKey ID'
                  }
                  fieldProps={{ autoComplete: 'off' }}
                  rules={
                    editing || provider === 'Cloudflare'
                      ? []
                      : [{ required: true, message: '请输入 AccessKey ID' }]
                  }
                />
                <ProFormText.Password
                  name="accessKeySecret"
                  label={
                    provider === 'Cloudflare'
                      ? 'Cloudflare API Token'
                      : 'AccessKey Secret / SecretKey'
                  }
                  placeholder={
                    editing
                      ? '已配置；留空保留原密钥'
                      : provider === 'Cloudflare'
                        ? '请输入 API Token'
                        : '请输入 AccessKey Secret'
                  }
                  fieldProps={{ autoComplete: 'new-password' }}
                  rules={
                    editing
                      ? []
                      : [
                          {
                            required: true,
                            message:
                              provider === 'Cloudflare'
                                ? '请输入 API Token'
                                : '请输入 AccessKey Secret',
                          },
                        ]
                  }
                />
                {provider === 'Cloudflare' && (
                  <Alert
                    type="info"
                    showIcon
                    title="Cloudflare 账号用于域名同步和 DNS 验证记录管理。公网证书由腾讯云、阿里云或 Let’s Encrypt 签发，验证记录使用 DNS 解析模式。"
                    style={{ marginBottom: 16 }}
                  />
                )}
              </>
            )
          }
        </ProFormDependency>
        <ProFormGroup>
          <ProFormSwitch name="enabled" label="启用配置" />
          <ProFormDependency name={['provider']}>
            {({ provider }) => (
              <ProFormSwitch
                name="useForCertificates"
                label="用于证书管理"
                disabled={provider === 'Cloudflare'}
              />
            )}
          </ProFormDependency>
          <ProFormDependency name={['provider']}>
            {({ provider }) => (
              <ProFormSwitch
                name="useForDns"
                label="用于 DNS 管理"
                disabled={provider === 'Acme' || provider === 'Cloudflare'}
              />
            )}
          </ProFormDependency>
        </ProFormGroup>
        <ProFormGroup title="自动同步配置">
          <ProFormSwitch
            name="autoSyncEnabled"
            label="启用自动同步"
            extra="同步目标沿用上面的“用于证书管理”和“用于 DNS 管理”开关；关闭不会删除本地数据。"
          />
        </ProFormGroup>
        <ProFormGroup>
          <ProFormDigit
            name="autoSyncIntervalValue"
            label="同步间隔"
            min={1}
            max={366}
            width="sm"
            rules={[{ required: true, message: '请输入大于 0 的同步间隔' }]}
          />
          <ProFormSelect
            name="autoSyncIntervalUnit"
            label="间隔单位"
            valueEnum={syncUnitNames}
            width="sm"
            rules={[{ required: true, message: '请选择间隔单位' }]}
          />
          <ProFormTimePicker
            name="autoSyncAtLocalTime"
            label="执行时间"
            width="sm"
            fieldProps={{ format: 'HH:mm' }}
            rules={[{ required: true, message: '请选择执行时间' }]}
            extra="按 Asia/Shanghai 本地时间计算；分钟/小时间隔仍以间隔值为准。"
          />
        </ProFormGroup>
        <ProFormGroup>
          <ProFormText name="contactName" label="证书申请联系人姓名" />
          <ProFormDependency name={['provider', 'acmeAccountMode']}>
            {({ provider, acmeAccountMode }) => (
              <ProFormText
                name="contactEmail"
                label={
                  provider === 'Acme'
                    ? acmeAccountMode === 'Automatic'
                      ? '注册联系邮箱'
                      : '联系邮箱（可选展示）'
                    : '联系邮箱'
                }
                rules={[
                  {
                    required:
                      provider === 'Acme' && acmeAccountMode === 'Automatic',
                    message: '系统注册账户必须填写联系邮箱',
                  },
                  { type: 'email', message: '请输入有效邮箱' },
                ]}
              />
            )}
          </ProFormDependency>
          <ProFormText name="contactPhone" label="联系电话" />
        </ProFormGroup>
        <ProFormDependency name={['provider']}>
          {({ provider }) =>
            provider === 'Aliyun' ? (
              <>
                <Alert
                  type="info"
                  showIcon
                  title="阿里云证书申请联系人"
                  description="填写或保留密钥后同步阿里云联系人，选择已验证联系人保存。后续申请 V2 免费证书时会自动使用该联系人。"
                  style={{ marginBottom: 12 }}
                />
                <Space wrap style={{ marginBottom: 12 }}>
                  <Button
                    type="primary"
                    loading={syncingContacts}
                    onClick={async () => {
                      const values = formRef.current?.getFieldsValue?.() as
                        | Record<string, unknown>
                        | undefined;
                      setSyncingContacts(true);
                      const result = await accountApi.contacts({
                        accountId: editing?.id,
                        provider: 'Aliyun',
                        accessKeyId:
                          typeof values?.accessKeyId === 'string'
                            ? values.accessKeyId
                            : '',
                        accessKeySecret:
                          typeof values?.accessKeySecret === 'string'
                            ? values.accessKeySecret
                            : '',
                      });
                      setSyncingContacts(false);
                      if (showResult(result))
                        setAliyunContacts(result.data ?? []);
                    }}
                  >
                    同步阿里云联系人
                  </Button>
                  <Typography.Link
                    href="https://yundun.console.aliyun.com/?p=cas#/informationManagement/person/cn-hangzhou"
                    target="_blank"
                    rel="noreferrer"
                  >
                    打开阿里云联系人控制台
                  </Typography.Link>
                  <Typography.Link
                    href="https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-listcontact"
                    target="_blank"
                    rel="noreferrer"
                  >
                    查看 ListContact 文档
                  </Typography.Link>
                </Space>
                <ProFormSelect
                  name="aliyunContactId"
                  label="阿里云证书申请联系人（V2）"
                  placeholder="请先同步联系人后选择"
                  options={aliyunContacts.map((contact) => ({
                    value: contact.id,
                    label: `${contact.name || '未命名'} · ${contact.mobile || '无手机号'}${contact.mobileVerified ? '（手机已验证）' : '（手机未验证）'}`,
                  }))}
                  fieldProps={{ showSearch: true, optionFilterProp: 'label' }}
                  extra="只建议选择手机和邮箱均已验证的联系人。留空时申请流程仍会按联系人信息尝试匹配。"
                />
              </>
            ) : null
          }
        </ProFormDependency>
      </ModalForm>
      <Modal
        title="注册 ACME 账户"
        open={registrationAccount !== undefined}
        onCancel={() => {
          if (!registering) {
            setRegistrationAccount(undefined);
            setAgreeTerms(false);
            setRegistrationResult(undefined);
            setRegistrationError('');
          }
        }}
        closable={!registering}
        footer={
          <Space>
            <Button
              disabled={registering}
              onClick={() => {
                setRegistrationAccount(undefined);
                setAgreeTerms(false);
                setRegistrationResult(undefined);
                setRegistrationError('');
              }}
            >
              关闭
            </Button>
            {!registrationResult && !registrationError && (
              <Button
                type="primary"
                disabled={!agreeTerms || registering}
                loading={registering}
                onClick={async () => {
                  if (!registrationAccount || !agreeTerms || registering)
                    return;
                  setRegistering(true);
                  try {
                    const result = await accountApi.registerAcme(
                      registrationAccount.id,
                      { agreeTerms: true },
                    );
                    showResult(result, 'ACME 账户注册状态已更新');
                    // 失败回执也包含原密钥指纹和真实状态，不能丢弃后继续显示首次注册入口。
                    setRegistrationResult(result.data);
                    setRegistrationError(
                      result.success
                        ? ''
                        : result.message || 'ACME 账户注册未成功，请核对状态。',
                    );
                  } finally {
                    actionRef.current?.reload();
                    setRegistering(false);
                  }
                }}
              >
                {registrationAccount?.acmeAccountStatus === 'Unknown'
                  ? '核对原注册结果'
                  : '确认注册账户'}
              </Button>
            )}
          </Space>
        }
      >
        {registrationError && (
          <Alert
            type="error"
            showIcon
            title="ACME 账户注册未成功"
            description={registrationError}
            style={{ marginBottom: 16 }}
          />
        )}
        {registrationResult ? (
          <>
            <Alert
              type={
                registrationResult.status === 'Failed'
                  ? 'error'
                  : registrationResult.status === 'Unknown'
                    ? 'warning'
                    : registrationResult.status === 'Registered' &&
                        !registrationError
                      ? 'success'
                      : 'info'
              }
              showIcon
              title={
                acmeAccountStatuses[registrationResult.status] ||
                registrationResult.status
              }
              style={{ marginBottom: 16 }}
            />
            <Descriptions
              column={1}
              items={[
                {
                  key: 'url',
                  label: 'Account URL',
                  children: (
                    <Typography.Text
                      copyable={{ text: registrationResult.accountUrl }}
                    >
                      {registrationResult.accountUrl || '待 CA 返回'}
                    </Typography.Text>
                  ),
                },
                {
                  key: 'directory',
                  label: 'CA 目录',
                  children: registrationResult.directoryUrl,
                },
                {
                  key: 'fingerprint',
                  label: '公钥指纹',
                  children: (
                    <Typography.Text
                      copyable={{
                        text: registrationResult.publicKeyThumbprint,
                      }}
                    >
                      {registrationResult.publicKeyThumbprint}
                    </Typography.Text>
                  ),
                },
                {
                  key: 'date',
                  label: '注册时间',
                  children: dateText(
                    registrationResult.registeredAtUtc || undefined,
                  ),
                },
              ]}
            />
            {registrationResult.status === 'Registered' &&
            !registrationError ? (
              <p>
                每次证书申请复用该账户；需在其他工具使用时，可在账号编辑中主动查看并复制账号
                URL 和私钥。
              </p>
            ) : (
              <p>
                {registrationResult.status === 'Unknown' ||
                registrationResult.status === 'Submitting'
                  ? '已保留原账户密钥。关闭后重新打开可核对同一账户，结果未知时不会再次注册。'
                  : '已保留原账户密钥。请根据错误信息检查配置，关闭后重新打开可显式重试，重试会先核对同一账户。'}
              </p>
            )}
          </>
        ) : (
          <>
            <p>账号：{registrationAccount?.name}</p>
            <p>CA 目录：{registrationAccount?.acmeDirectoryUrl}</p>
            <Alert
              type="info"
              showIcon
              title="此操作会使用保存的联系邮箱向 CA 注册账户；结果未知时保留原密钥核对，不另建账户。"
              style={{ marginBottom: 16 }}
            />
            <Checkbox
              checked={agreeTerms}
              onChange={(event) => setAgreeTerms(event.target.checked)}
            >
              我已阅读并同意 CA 当前的服务条款
            </Checkbox>
            <p>
              <Typography.Link
                href="https://letsencrypt.org/repository/"
                target="_blank"
                rel="noreferrer"
              >
                查看 Let’s Encrypt 当前服务条款
              </Typography.Link>
            </p>
          </>
        )}
      </Modal>
      <Modal
        title="连接与权限检测结果"
        open={diagnostic !== undefined}
        onCancel={() => setDiagnostic(undefined)}
        footer={<Button onClick={() => setDiagnostic(undefined)}>关闭</Button>}
      >
        <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
          {JSON.stringify(diagnostic, null, 2)}
        </pre>
      </Modal>
    </PageContainer>
  );
}
