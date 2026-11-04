import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import type { DeploymentPlan } from '@/services/ssl-manager/deploymentTypes';
import DeployModal from './DeployModal';

vi.mock('@umijs/max', () => ({ history: { push: vi.fn() } }));
vi.mock('@/components/ssl-manager', () => ({
  useResultMessage: () => vi.fn(),
}));
vi.mock('@/services/ssl-manager/deployment', () => ({
  deploymentApi: {
    targets: vi.fn(),
    plan: vi.fn(),
    submit: vi.fn(),
    batch: vi.fn(),
  },
}));
vi.mock('./BatchPanel', () => ({ default: () => <div>后台任务已接收</div> }));
vi.mock('antd', () => ({
  Modal: ({ open, children, footer }: any) =>
    open ? (
      <div>
        {children}
        {footer}
      </div>
    ) : null,
  Alert: ({ title, description }: any) => (
    <div>
      {title}
      {description}
    </div>
  ),
  Button: ({ children, onClick, disabled }: any) => (
    <button type="button" onClick={onClick} disabled={disabled}>
      {children}
    </button>
  ),
  Space: ({ children }: any) => <div>{children}</div>,
  Tag: ({ children }: any) => <span>{children}</span>,
  Descriptions: () => null,
  Table: () => <div>部署计划预览</div>,
  Select: ({ value, onChange, options, disabled, ...props }: any) => (
    <select
      aria-label={props['aria-label']}
      multiple
      value={value}
      disabled={disabled}
      onChange={(event) =>
        onChange(
          Array.from(
            event.currentTarget.selectedOptions,
            (option) => option.value,
          ),
        )
      }
    >
      {options.map((option: any) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  ),
}));

const certificate = {
  id: 'certificate-1',
  accountId: 'account-1',
  provider: 'Aliyun' as const,
  domain: 'example.com',
  status: 'Issued',
};
const plan: DeploymentPlan = {
  batchId: 'batch-1',
  planRevision: 1,
  expiresAtUtc: '2030-01-01T00:00:00Z',
  certificate: {
    certificateId: certificate.id,
    domain: certificate.domain,
    domains: ['example.com'],
    fingerprint: 'fingerprint',
    materialDigest: 'digest',
    notBeforeUtc: '2026-01-01T00:00:00Z',
    notAfterUtc: '2027-01-01T00:00:00Z',
  },
  targets: [],
};
const success = <T,>(data: T) => ({
  success: true,
  code: 'OK',
  message: '',
  data,
});

async function selectTarget(value: string) {
  const select = await screen.findByRole('listbox', { name: '选择部署目标' });
  await waitFor(() =>
    expect(select.querySelectorAll('option')).toHaveLength(2),
  );
  for (const option of Array.from(select.querySelectorAll('option')))
    option.selected = option.value === value;
  fireEvent.change(select);
}

describe('证书部署计划和提交', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(deploymentApi.targets).mockResolvedValue(
      success({
        items: [
          {
            id: 'target-1',
            name: '目标一',
            endpoint: 'https://waf.example.com',
            enabled: true,
          },
          {
            id: 'target-2',
            name: '目标二',
            endpoint: 'https://other.example.com',
            enabled: true,
          },
          {
            id: 'disabled-target',
            name: '停用目标',
            endpoint: 'https://disabled.example.com',
            enabled: false,
          },
        ],
        total: 3,
        page: 1,
        pageSize: 200,
      }) as any,
    );
    vi.mocked(deploymentApi.plan).mockResolvedValue(success(plan));
  });

  it('仅列出启用目标，变更目标选择会使旧部署计划失效', async () => {
    render(<DeployModal certificate={certificate} onClose={vi.fn()} />);
    await selectTarget('target-1');
    fireEvent.click(screen.getByRole('button', { name: '生成部署计划' }));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: '确认部署' }),
      ).not.toBeDisabled(),
    );
    expect(deploymentApi.plan).toHaveBeenCalledWith(certificate.id, [
      { targetId: 'target-1' },
    ]);
    expect(screen.queryByText(/停用目标/)).not.toBeInTheDocument();
    await selectTarget('target-2');
    expect(screen.getByRole('button', { name: '确认部署' })).toBeDisabled();
    expect(screen.queryByText('部署计划预览')).not.toBeInTheDocument();
  });

  it('续签证书按归一化域名复用目标，过滤异域并保留通用目标', async () => {
    vi.mocked(deploymentApi.targets).mockResolvedValue(
      success({
        items: [
          {
            id: 'legacy',
            name: '旧目标',
            endpoint: '192.0.2.1',
            enabled: true,
          },
          {
            id: 'matching',
            name: '当前来源',
            endpoint: '192.0.2.2',
            enabled: true,
            configuration: {
              sourceDomain: ' EXAMPLE.COM. ',
              sourceCertificateId: 'old-certificate-id',
              sourceFormat: 'nginx',
            },
          },
          {
            id: 'other',
            name: '其他来源',
            endpoint: '192.0.2.3',
            enabled: true,
            configuration: {
              sourceDomain: 'other.example.com',
              sourceCertificateId: certificate.id,
              sourceFormat: 'nginx',
            },
          },
        ],
        total: 3,
        page: 1,
        pageSize: 200,
      }) as any,
    );
    render(<DeployModal certificate={certificate} onClose={vi.fn()} />);
    await selectTarget('matching');
    expect(screen.queryByText(/其他来源/)).not.toBeInTheDocument();
    expect(screen.getByText(/旧目标/)).toBeInTheDocument();
    expect(screen.getByText(/当前来源.*绑定域名/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '生成部署计划' }));
    await waitFor(() =>
      expect(deploymentApi.plan).toHaveBeenCalledWith(certificate.id, [
        { targetId: 'matching' },
      ]),
    );
  });

  it('提交网络失败后沿用相同幂等键，避免重复执行部署命令', async () => {
    vi.mocked(deploymentApi.submit)
      .mockResolvedValueOnce({
        success: false,
        code: 'NETWORK_ERROR',
        message: '连接暂时中断',
      })
      .mockResolvedValueOnce(
        success({ id: 'batch-1', status: 'Succeeded', tasks: [] }) as any,
      );
    render(<DeployModal certificate={certificate} onClose={vi.fn()} />);
    await selectTarget('target-1');
    fireEvent.click(screen.getByRole('button', { name: '生成部署计划' }));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: '确认部署' }),
      ).not.toBeDisabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '确认部署' }));
    await screen.findByText('连接暂时中断');
    fireEvent.click(screen.getByRole('button', { name: '确认部署' }));
    await screen.findByText('后台任务已接收');
    const calls = vi.mocked(deploymentApi.submit).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls[0]).toEqual(calls[1]);
    expect(calls[0][2]).not.toBe('');
  });

  it('服务端提示计划过期后必须重新生成计划', async () => {
    vi.mocked(deploymentApi.submit).mockResolvedValue({
      success: false,
      code: 'PLAN_STALE',
      message: '目标配置已经变化',
    });
    render(<DeployModal certificate={certificate} onClose={vi.fn()} />);
    await selectTarget('target-1');
    fireEvent.click(screen.getByRole('button', { name: '生成部署计划' }));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: '确认部署' }),
      ).not.toBeDisabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '确认部署' }));
    await screen.findByText('目标配置已经变化');
    expect(screen.getByRole('button', { name: '确认部署' })).toBeDisabled();
  });
});
