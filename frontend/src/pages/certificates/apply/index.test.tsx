import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { certificateApi, domainApi } from '@/services/ssl-manager/api';
import Apply from './index';

vi.mock('@umijs/max', () => ({ history: { push: vi.fn(), replace: vi.fn() } }));
vi.mock('@ant-design/pro-components', async () => {
  // 使用真实 Ant Design 字段验证页面提交行为，避免 Pro 组件包的 Node ESM locale 入口问题。
  const ReactModule = await import('react');
  const { Form, Input, Select, Switch, Button } = await import('antd');
  const Context = ReactModule.createContext<any>(undefined);
  const Steps: any = ({ children, onFinish }: any) => {
    const [step, setStep] = ReactModule.useState(0);
    return (
      <Context.Provider
        value={{
          step,
          next: () => setStep((value: number) => value + 1),
          onFinish,
        }}
      >
        {ReactModule.Children.toArray(children)[step]}
      </Context.Provider>
    );
  };
  Steps.StepForm = ({ children, initialValues, onFinish, formRef }: any) => {
    const [form] = Form.useForm();
    const context = ReactModule.useContext(Context);
    if (formRef) formRef.current = form;
    return (
      <Form
        form={form}
        initialValues={initialValues}
        onFinish={async (values) => {
          if (onFinish && !(await onFinish(values))) return;
          if (context.step === 2) await context.onFinish();
          else context.next();
        }}
      >
        {children}
        <Button htmlType="submit">
          {context.step === 2 ? '提交' : '下一步'}
        </Button>
      </Form>
    );
  };
  return {
    PageContainer: ({ children }: any) => <div>{children}</div>,
    StepsForm: Steps,
    ProForm: { Item: Form.Item },
    ProFormGroup: ({ children }: any) => <div>{children}</div>,
    ProFormText: ({ name, label, rules, placeholder, extra }: any) => (
      <Form.Item name={name} label={label} rules={rules} extra={extra}>
        <Input placeholder={placeholder} />
      </Form.Item>
    ),
    ProFormSelect: ({
      name,
      label,
      rules,
      options,
      fieldProps,
      placeholder,
      extra,
    }: any) => (
      <Form.Item name={name} label={label} rules={rules} extra={extra}>
        <Select options={options} placeholder={placeholder} {...fieldProps} />
      </Form.Item>
    ),
    ProFormSwitch: ({ name, label, extra }: any) => (
      <Form.Item
        name={name}
        label={label}
        valuePropName="checked"
        extra={extra}
      >
        <Switch />
      </Form.Item>
    ),
  };
});
vi.mock('@/components/ssl-manager', () => ({
  providerNames: {
    TencentCloud: '腾讯云',
    Cloudflare: 'Cloudflare',
    Acme: 'ACME',
  },
  useResultMessage: () => (result: { success: boolean }) => result.success,
  useCloudAccounts: () => ({
    accounts: [
      {
        id: 'tencent',
        name: '腾讯签发',
        provider: 'TencentCloud',
        enabled: true,
        useForCertificates: true,
        useForDns: false,
      },
      {
        id: 'cf',
        name: 'CF托管',
        provider: 'Cloudflare',
        enabled: true,
        useForCertificates: true,
        useForDns: true,
      },
      {
        id: 'acme',
        name: 'ACME测试',
        provider: 'Acme',
        enabled: true,
        useForCertificates: true,
        useForDns: false,
        acmeDirectoryUrl:
          'https://acme-staging-v02.api.letsencrypt.org/directory',
      },
    ],
    error: '',
  }),
}));
vi.mock('@/services/ssl-manager/api', () => ({
  accountApi: { aliyunInstances: vi.fn() },
  certificateApi: { apply: vi.fn() },
  domainApi: { list: vi.fn() },
}));

async function selectOption(label: string, option: string) {
  fireEvent.mouseDown(screen.getByLabelText(label));
  fireEvent.click(await screen.findByText(option));
}

async function fillDomain(account: string) {
  await selectOption('证书申请账号', account);
  fireEvent.change(screen.getByLabelText('绑定域名前缀'), {
    target: { value: 'testssl' },
  });
  fireEvent.change(screen.getByLabelText('绑定域名后缀'), {
    target: { value: 'example.com' },
  });
  fireEvent.click(screen.getByRole('button', { name: /下一步/ }));
}

describe('跨平台证书申请表单', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(domainApi.list).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: {
        items: [
          {
            id: 'cf-zone',
            accountId: 'cf',
            name: 'example.com',
            provider: 'Cloudflare',
          },
        ],
        total: 1,
        page: 1,
        pageSize: 100,
      },
    });
    vi.mocked(certificateApi.apply).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
    });
  });

  it('腾讯云申请使用独立Cloudflare托管域', async () => {
    render(<Apply />);
    await fillDomain('腾讯云 / 腾讯签发');
    await screen.findByLabelText('DNS 托管域（可使用独立账号）');
    await selectOption(
      'DNS 托管域（可使用独立账号）',
      'example.com · CF托管 / Cloudflare',
    );
    fireEvent.click(screen.getByRole('button', { name: /下一步/ }));
    fireEvent.click(await screen.findByRole('button', { name: /提\s*交/ }));
    await waitFor(() => expect(certificateApi.apply).toHaveBeenCalledOnce());
    expect(certificateApi.apply).toHaveBeenCalledWith(
      expect.objectContaining({
        accountId: 'tencent',
        domain: 'testssl.example.com',
        dnsZoneId: 'cf-zone',
        validationMode: 'ManagedDns',
      }),
    );
  });

  it('Cloudflare 只作为 DNS 账号，不出现在证书申请账号选项中', async () => {
    render(<Apply />);
    fireEvent.mouseDown(screen.getByLabelText('证书申请账号'));
    expect(await screen.findByText('腾讯云 / 腾讯签发')).toBeInTheDocument();
    expect(screen.queryByText('Cloudflare / CF托管')).not.toBeInTheDocument();
    expect(certificateApi.apply).not.toHaveBeenCalled();
  });

  it('ACME测试环境显示非信任提示且不允许原生自动或文件验证', async () => {
    render(<Apply />);
    await fillDomain('ACME / ACME测试');
    await screen.findByText(/当前为 Let’s Encrypt Staging/);
    fireEvent.mouseDown(screen.getByLabelText('域名验证方式'));
    expect(screen.queryByText('文件验证')).not.toBeInTheDocument();
    expect(screen.queryByText('自动 DNS 验证')).not.toBeInTheDocument();
    expect(await screen.findByText('手动 DNS 验证')).toBeInTheDocument();
  });
});
