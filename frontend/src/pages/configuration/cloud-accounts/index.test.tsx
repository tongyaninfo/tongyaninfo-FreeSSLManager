import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { accountApi } from '@/services/ssl-manager/api';
import { acmeDirectories } from '@/services/ssl-manager/certificatePresentation';
import CloudAccounts from './index';

const mocks = vi.hoisted(() => ({ rows: [] as any[], reload: vi.fn() }));
vi.mock('@umijs/max', () => ({
  useIntl: () => ({
    formatMessage: ({ defaultMessage }: any) => defaultMessage,
  }),
}));
vi.mock('@/components/ssl-manager', () => ({
  dateText: () => '—',
  providerNames: {
    TencentCloud: '腾讯云',
    Aliyun: '阿里云',
    Cloudflare: 'Cloudflare',
    Acme: 'ACME',
  },
  tableResult: (result: any) => ({ data: result.data?.items || [] }),
  useTableKeyboardPagination: () => vi.fn(),
  useTablePreferences: () => ({}),
  useResultMessage: () => (result: { success: boolean }) => result.success,
}));
vi.mock('@/services/ssl-manager/api', () => ({
  accountApi: {
    list: vi.fn(),
    save: vi.fn(),
    secrets: vi.fn(),
    test: vi.fn(),
    registerAcme: vi.fn(),
    contacts: vi.fn(),
  },
}));
vi.mock('@ant-design/pro-components', async () => {
  // 复用真实 Ant Design 表单和校验，隔离 Pro 包在 Node 环境中的 locale 入口。
  const { Form, Input, InputNumber, Select, Switch, Button } = await import(
    'antd'
  );
  const Text: any = ({
    name,
    label,
    rules,
    extra,
    placeholder,
    fieldProps,
  }: any) => (
    <Form.Item name={name} label={label} rules={rules} extra={extra}>
      <Input placeholder={placeholder} {...fieldProps} />
    </Form.Item>
  );
  Text.Password = ({
    name,
    label,
    rules,
    extra,
    placeholder,
    fieldProps,
  }: any) => (
    <Form.Item name={name} label={label} rules={rules} extra={extra}>
      <Input.Password placeholder={placeholder} {...fieldProps} />
    </Form.Item>
  );
  const TimeInput = ({ value, onChange }: any) => (
    <Input
      value={value?.format?.('HH:mm') || value || ''}
      onChange={onChange}
    />
  );
  return {
    PageContainer: ({ children }: any) => <div>{children}</div>,
    ProTable: ({ toolBarRender, columns, actionRef }: any) => {
      actionRef.current = { reload: mocks.reload };
      return (
        <div>
          {toolBarRender?.()}
          {mocks.rows.map((row) => (
            <div key={row.id}>
              {columns.map((column: any) => (
                <div key={column.dataIndex || column.title}>
                  {column.render
                    ? column.render(undefined, row)
                    : row[column.dataIndex]}
                </div>
              ))}
            </div>
          ))}
        </div>
      );
    },
    ModalForm: ({
      open,
      title,
      children,
      initialValues,
      onFinish,
      onValuesChange,
      onOpenChange,
      formRef,
    }: any) => {
      const [form] = Form.useForm();
      formRef.current = form;
      if (!open) return null;
      return (
        <div role="dialog" aria-label={title}>
          <Form
            form={form}
            initialValues={initialValues}
            onValuesChange={onValuesChange}
            onFinish={async (values) => {
              if (await onFinish(values)) onOpenChange(false);
            }}
          >
            {children}
            <Button htmlType="submit">保存</Button>
            <Button onClick={() => onOpenChange(false)}>关闭配置</Button>
          </Form>
        </div>
      );
    },
    ProFormDependency: ({ children }: any) => (
      <Form.Item noStyle shouldUpdate>
        {(form) => children(form.getFieldsValue(true))}
      </Form.Item>
    ),
    ProFormGroup: ({ children }: any) => <div>{children}</div>,
    ProFormText: Text,
    ProFormTextArea: ({
      name,
      label,
      rules,
      extra,
      placeholder,
      fieldProps,
    }: any) => (
      <Form.Item name={name} label={label} rules={rules} extra={extra}>
        <Input.TextArea placeholder={placeholder} {...fieldProps} />
      </Form.Item>
    ),
    ProFormSelect: ({
      name,
      label,
      rules,
      extra,
      options,
      valueEnum,
      disabled,
    }: any) => (
      <Form.Item name={name} label={label} rules={rules} extra={extra}>
        <Select
          disabled={disabled}
          options={
            options ||
            Object.entries(valueEnum || {}).map(([value, text]) => ({
              value,
              label: text,
            }))
          }
        />
      </Form.Item>
    ),
    ProFormSwitch: ({ name, label, disabled }: any) => (
      <Form.Item name={name} label={label} valuePropName="checked">
        <Switch disabled={disabled} />
      </Form.Item>
    ),
    ProFormDigit: ({ name, label, rules }: any) => (
      <Form.Item name={name} label={label} rules={rules}>
        <InputNumber />
      </Form.Item>
    ),
    ProFormTimePicker: ({ name, label, rules }: any) => (
      <Form.Item name={name} label={label} rules={rules}>
        <TimeInput />
      </Form.Item>
    ),
  };
});

const accountUrl = 'https://acme-v02.api.letsencrypt.org/acme/acct/123456';
const accountKey =
  '-----BEGIN PRIVATE KEY-----\nU3ludGhldGljVGVzdEtleQ==\n-----END PRIVATE KEY-----';

async function createAcmeForm() {
  render(<CloudAccounts />);
  fireEvent.click(screen.getByRole('button', { name: /新增云平台配置/ }));
  fireEvent.mouseDown(screen.getByLabelText('云平台'));
  fireEvent.click(await screen.findByText('ACME'));
  fireEvent.change(screen.getByLabelText('配置名称'), {
    target: { value: '已有ACME账户' },
  });
}

describe('既有 ACME 账户接入', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.rows = [];
    vi.mocked(accountApi.save).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
    });
    vi.mocked(accountApi.secrets).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: { accessKeyId: accountUrl, accessKeySecret: accountKey },
    });
    vi.mocked(accountApi.test).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: {},
    });
    vi.mocked(accountApi.registerAcme).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: {
        accountUrl,
        directoryUrl: acmeDirectories.production,
        publicKeyThumbprint: 'synthetic-public-thumbprint',
        status: 'Registered',
        registeredAtUtc: '2026-11-04T00:00:00Z',
      },
    });
  });

  it('未提供既有账户URL和账号私钥时禁止保存，邮箱为可选展示', async () => {
    await createAcmeForm();
    expect(
      screen.getByText(
        '先用 ACME 客户端注册账号，导入账号 URL 与账号私钥；已有账户模式不会代注册。',
      ),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('联系邮箱（可选展示）')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /注册/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Let’s Encrypt 官方接入指引' }),
    ).toHaveAttribute('href', 'https://letsencrypt.org/getting-started/');
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }));
    await screen.findByText('请输入已注册 ACME 账户的 Account URL');
    await screen.findByText('请粘贴既有 ACME 账户的 PEM 私钥');
    expect(accountApi.save).not.toHaveBeenCalled();
  });

  it('使用既有URL和多行PEM私钥保存，保留原始换行且不要求邮箱', async () => {
    await createAcmeForm();
    fireEvent.change(screen.getByLabelText('既有 ACME Account URL'), {
      target: { value: accountUrl },
    });
    fireEvent.change(screen.getByLabelText('PEM 格式账号私钥'), {
      target: { value: accountKey },
    });
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }));
    await waitFor(() => expect(accountApi.save).toHaveBeenCalledOnce());
    expect(accountApi.save).toHaveBeenCalledWith(
      undefined,
      expect.objectContaining({
        provider: 'Acme',
        accessKeyId: accountUrl,
        accessKeySecret: accountKey,
        acmeDirectoryUrl: acmeDirectories.production,
        useForDns: false,
      }),
    );
  });

  it('系统注册模式保存时只要求邮箱，保存动作不注册账户', async () => {
    await createAcmeForm();
    fireEvent.mouseDown(screen.getByLabelText('ACME 账户接入方式'));
    fireEvent.click(await screen.findByText('系统注册账户（需单独确认）'));
    expect(
      screen.queryByLabelText('既有 ACME Account URL'),
    ).not.toBeInTheDocument();
    expect(screen.queryByLabelText('PEM 格式账号私钥')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }));
    await screen.findByText('系统注册账户必须填写联系邮箱');
    expect(accountApi.save).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('注册联系邮箱'), {
      target: { value: 'owner@example.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }));
    await waitFor(() => expect(accountApi.save).toHaveBeenCalledOnce());
    expect(accountApi.save).toHaveBeenCalledWith(
      undefined,
      expect.objectContaining({
        acmeAccountMode: 'Automatic',
        contactEmail: 'owner@example.test',
        accessKeyId: '',
        accessKeySecret: '',
      }),
    );
    expect(accountApi.registerAcme).not.toHaveBeenCalled();
  });

  it('注册只由明确条款确认触发，结果展示可复用公开信息且不默认显示私钥', async () => {
    mocks.rows = [
      {
        id: 'automatic-acme',
        name: '待注册账户',
        provider: 'Acme',
        acmeAccountMode: 'Automatic',
        acmeAccountStatus: 'New',
        enabled: true,
        useForCertificates: true,
        useForDns: false,
        contactEmail: 'owner@example.test',
        acmeDirectoryUrl: acmeDirectories.production,
      },
    ];
    render(<CloudAccounts />);
    fireEvent.click(screen.getByRole('button', { name: '注册ACME账户' }));
    const dialog = await screen.findByRole('dialog', {
      name: '注册 ACME 账户',
    });
    const submit = within(dialog).getByRole('button', { name: '确认注册账户' });
    expect(submit).toBeDisabled();
    expect(accountApi.registerAcme).not.toHaveBeenCalled();
    fireEvent.click(
      within(dialog).getByRole('checkbox', {
        name: '我已阅读并同意 CA 当前的服务条款',
      }),
    );
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    await waitFor(() =>
      expect(accountApi.registerAcme).toHaveBeenCalledExactlyOnceWith(
        'automatic-acme',
        { agreeTerms: true },
      ),
    );
    expect(await within(dialog).findByText(accountUrl)).toBeInTheDocument();
    expect(
      within(dialog).getByText('synthetic-public-thumbprint'),
    ).toBeInTheDocument();
    expect(
      within(dialog).queryByRole('button', { name: '确认注册账户' }),
    ).not.toBeInTheDocument();
    expect(accountApi.secrets).not.toHaveBeenCalled();
    expect(mocks.reload).toHaveBeenCalledOnce();
  });

  it.each([
    {
      status: 'Unknown',
      statusText: '注册结果待核对',
      error: '原注册结果仍未知，仅核对同一账户；未重复注册。',
      action: '核对ACME注册结果',
      submit: '核对原注册结果',
      guidance:
        '已保留原账户密钥。关闭后重新打开可核对同一账户，结果未知时不会再次注册。',
    },
    {
      status: 'Failed',
      statusText: '注册失败',
      error: 'CA 拒绝账户注册，请检查联系邮箱。',
      action: '注册ACME账户',
      submit: '确认注册账户',
      guidance:
        '已保留原账户密钥。请根据错误信息检查配置，关闭后重新打开可显式重试，重试会先核对同一账户。',
    },
  ])('注册失败 $status 仍展示原密钥指纹及状态，并要求重新打开后显式操作', async ({
    status,
    statusText,
    error,
    action,
    submit,
    guidance,
  }) => {
    mocks.rows = [
      {
        id: 'automatic-acme',
        name: '待注册账户',
        provider: 'Acme',
        acmeAccountMode: 'Automatic',
        acmeAccountStatus: 'New',
        enabled: true,
        useForCertificates: true,
        useForDns: false,
        acmeDirectoryUrl: acmeDirectories.production,
      },
    ];
    vi.mocked(accountApi.registerAcme).mockImplementationOnce(async () => {
      mocks.rows = [{ ...mocks.rows[0], acmeAccountStatus: status }];
      return {
        success: false,
        code: 'ACME_REJECTED',
        message: error,
        data: {
          accountUrl: '',
          directoryUrl: acmeDirectories.production,
          publicKeyThumbprint: 'synthetic-retained-thumbprint',
          status,
        },
      };
    });
    render(<CloudAccounts />);
    fireEvent.click(screen.getByRole('button', { name: '注册ACME账户' }));
    const dialog = await screen.findByRole('dialog', {
      name: '注册 ACME 账户',
    });
    fireEvent.click(
      within(dialog).getByRole('checkbox', {
        name: '我已阅读并同意 CA 当前的服务条款',
      }),
    );
    fireEvent.click(
      within(dialog).getByRole('button', { name: '确认注册账户' }),
    );
    expect(await within(dialog).findByText(error)).toBeInTheDocument();
    expect(within(dialog).getByText(statusText)).toBeInTheDocument();
    expect(
      within(dialog).getByText('synthetic-retained-thumbprint'),
    ).toBeInTheDocument();
    expect(within(dialog).getByText(guidance)).toBeInTheDocument();
    expect(
      within(dialog).queryByText(/每次证书申请复用该账户/),
    ).not.toBeInTheDocument();
    expect(
      within(dialog).queryByRole('button', { name: '确认注册账户' }),
    ).not.toBeInTheDocument();
    expect(mocks.reload).toHaveBeenCalledOnce();
    expect(accountApi.registerAcme).toHaveBeenCalledExactlyOnceWith(
      'automatic-acme',
      { agreeTerms: true },
    );
    expect(accountApi.secrets).not.toHaveBeenCalled();

    fireEvent.click(within(dialog).getByRole('button', { name: /^关\s*闭$/ }));
    fireEvent.click(screen.getByRole('button', { name: action }));
    const reopened = await screen.findByRole('dialog', {
      name: '注册 ACME 账户',
    });
    expect(
      within(reopened).getByRole('button', { name: submit }),
    ).toBeDisabled();
    expect(within(reopened).queryByText(error)).not.toBeInTheDocument();
    expect(accountApi.registerAcme).toHaveBeenCalledOnce();
  });

  it('连接测试不隐式注册系统账户', async () => {
    mocks.rows = [
      {
        id: 'automatic-acme',
        name: '待注册账户',
        provider: 'Acme',
        acmeAccountMode: 'Automatic',
        acmeAccountStatus: 'New',
        enabled: true,
        useForCertificates: true,
        useForDns: false,
        acmeDirectoryUrl: acmeDirectories.production,
      },
    ];
    render(<CloudAccounts />);
    fireEvent.click(screen.getByRole('button', { name: '测试连接与权限' }));
    await waitFor(() =>
      expect(accountApi.test).toHaveBeenCalledExactlyOnceWith('automatic-acme'),
    );
    expect(accountApi.registerAcme).not.toHaveBeenCalled();
  });

  it('导入的系统账户已有URL和私钥时展示已配置状态，不再提供注册动作', () => {
    mocks.rows = [
      {
        id: 'imported-acme',
        name: '导入账户',
        provider: 'Acme',
        acmeAccountMode: 'Automatic',
        acmeAccountStatus: 'Configured',
        accountUrl,
        publicKeyThumbprint: 'imported-public-thumbprint',
        enabled: false,
        useForCertificates: true,
        useForDns: false,
        hasAccessKeySecret: true,
        acmeDirectoryUrl: acmeDirectories.production,
      },
    ];
    render(<CloudAccounts />);
    expect(screen.getByText(accountUrl)).toBeInTheDocument();
    expect(screen.getByText(/已配置账户/)).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: '注册ACME账户' }),
    ).not.toBeInTheDocument();
  });

  it.each([
    [
      'https://acme-staging-v02.api.letsencrypt.org/acme/acct/123456',
      accountKey,
      'Account URL 必须是所选 CA 返回的 /acme/acct/ 账户地址。',
    ],
    [
      accountUrl,
      'synthetic-api-token',
      '请输入完整 PEM 格式账号私钥，不能使用密码或 API Token。',
    ],
  ])('拒绝不匹配CA地址或密码/API Token形式的账号凭据', async (url, key, error) => {
    await createAcmeForm();
    fireEvent.change(screen.getByLabelText('既有 ACME Account URL'), {
      target: { value: url },
    });
    fireEvent.change(screen.getByLabelText('PEM 格式账号私钥'), {
      target: { value: key },
    });
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }));
    await screen.findByText(error);
    expect(accountApi.save).not.toHaveBeenCalled();
  });

  it('编辑留空保留原账户凭据，只有管理员主动查看时才读取明文', async () => {
    mocks.rows = [
      {
        id: 'existing-acme',
        name: '已有ACME账户',
        provider: 'Acme',
        enabled: true,
        useForCertificates: true,
        useForDns: false,
        hasAccessKeySecret: true,
        accessKeyIdMasked: 'https:********3456',
        acmeDirectoryUrl: acmeDirectories.production,
      },
    ];
    render(<CloudAccounts />);
    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }));
    expect(accountApi.secrets).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole('button', { name: /查看已保存的原始密钥/ }),
    );
    await waitFor(() =>
      expect(accountApi.secrets).toHaveBeenCalledExactlyOnceWith(
        'existing-acme',
      ),
    );
    const dialog = screen.getByRole('dialog', { name: '编辑云平台配置' });
    await waitFor(() =>
      expect(dialog).toHaveTextContent('U3ludGhldGljVGVzdEtleQ=='),
    );
    expect(within(dialog).getByLabelText('既有 ACME Account URL')).toHaveValue(
      '',
    );
    expect(within(dialog).getByLabelText('PEM 格式账号私钥')).toHaveValue('');
    fireEvent.click(within(dialog).getByRole('button', { name: /^保\s*存$/ }));
    await waitFor(() => expect(accountApi.save).toHaveBeenCalledOnce());
    const saved = vi.mocked(accountApi.save).mock.calls[0][1] as Record<
      string,
      unknown
    >;
    expect(saved.accessKeyId || '').toBe('');
    expect(saved.accessKeySecret || '').toBe('');
    expect(
      screen.queryByText(/U3ludGhldGljVGVzdEtleQ==/),
    ).not.toBeInTheDocument();
  });
});
