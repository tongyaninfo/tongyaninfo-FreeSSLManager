import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { domainApi } from '@/services/ssl-manager/api';
import {
  type CertificateSchedule,
  certificateScheduleApi,
} from '@/services/ssl-manager/certificateSchedule';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import type { DeploymentTarget } from '@/services/ssl-manager/deploymentTypes';
import { defaultScheduleFirstRun, scheduleDate } from './presentation';
import ScheduleForm from './ScheduleForm';

vi.mock('@/components/ssl-manager', () => ({
  useCloudAccounts: () => ({
    accounts: [
      {
        id: 'account',
        name: '测试账号',
        provider: 'TencentCloud',
        enabled: true,
        useForCertificates: true,
        useForDns: true,
      },
      {
        id: 'cf',
        name: 'Cloudflare DNS',
        provider: 'Cloudflare',
        enabled: true,
        useForCertificates: true,
        useForDns: true,
      },
      {
        id: 'acme',
        name: 'ACME生产',
        provider: 'Acme',
        enabled: true,
        useForCertificates: true,
        useForDns: false,
        acmeDirectoryUrl: 'https://acme-v02.api.letsencrypt.org/directory',
      },
      {
        id: 'staging',
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
  providerNames: {
    TencentCloud: '腾讯云',
    Cloudflare: 'Cloudflare',
    Acme: 'ACME',
  },
  useResultMessage: () => (result: { success: boolean }) => result.success,
}));
vi.mock('@/services/ssl-manager/api', () => ({ domainApi: { list: vi.fn() } }));
vi.mock('@/services/ssl-manager/deployment', () => ({
  deploymentApi: { targets: vi.fn() },
}));
vi.mock('@/services/ssl-manager/certificateSchedule', () => ({
  certificateScheduleApi: { save: vi.fn() },
}));

const target = {
  id: 'target',
  name: 'VPN服务器',
  endpoint: '192.0.2.10',
  enabled: true,
  executorKey: 'linux.files.ssh.v1',
  configuration: { sourceDomain: 'vpn.example.com' },
} as DeploymentTarget;
const success = <T,>(data: T) => ({
  success: true,
  code: 'OK',
  message: '',
  data,
});
const schedule: CertificateSchedule = {
  id: 'schedule',
  name: 'VPN续签',
  accountId: 'account',
  accountName: '测试账号',
  domain: 'vpn.example.com',
  alias: 'VPN',
  validationMode: 'ManagedDns',
  autoCleanup: true,
  revokeOldCertificates: true,
  targetIds: [target.id],
  intervalValue: 1,
  intervalUnit: 'month',
  firstRunAtUtc: '2027-01-30T18:00:00Z',
  enabled: true,
  configRevision: 3,
  nextRunAtUtc: '2027-02-27T18:00:00Z',
  createdAtUtc: '2026-11-01T00:00:00Z',
  updatedAtUtc: '2026-11-01T00:00:00Z',
};

describe('证书计划表单与上海时间', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(deploymentApi.targets).mockResolvedValue(
      success({ items: [target], total: 1, page: 1, pageSize: 200 }),
    );
    vi.mocked(domainApi.list).mockResolvedValue(
      success({
        items: [
          {
            id: 'zone',
            accountId: 'account',
            name: 'example.com',
            provider: 'TencentCloud',
            zoneId: 'zone',
          },
        ],
        total: 1,
        page: 1,
        pageSize: 100,
      }),
    );
    vi.mocked(certificateScheduleApi.save).mockResolvedValue(success(schedule));
  });

  it('新建默认每1月、下个月同日上海02:00，勾选吊销删除老证书', async () => {
    render(<ScheduleForm open onClose={vi.fn()} onSaved={vi.fn()} />);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '保存计划' })).toBeEnabled(),
    );
    expect(screen.getByLabelText('间隔数')).toHaveValue('1');
    expect(screen.getByText('月')).toBeInTheDocument();
    expect(
      screen.getByRole('checkbox', { name: '吊销删除老证书' }),
    ).toBeChecked();
    expect(screen.getByLabelText('首次执行时间（上海时区）')).toHaveValue(
      defaultScheduleFirstRun().format('YYYY-MM-DD HH:mm'),
    );
    expect(
      screen.getByText(/全部目标部署成功|所有目标部署成功/),
    ).toBeInTheDocument();
    expect(screen.queryByText('手动 DNS 验证')).not.toBeInTheDocument();
    expect(screen.queryByText('文件验证')).not.toBeInTheDocument();
    expect(certificateScheduleApi.save).not.toHaveBeenCalled();
  });

  it('编辑保存保留明确目标、清理选项和修订，并把上海时间转换成UTC', async () => {
    const onSaved = vi.fn();
    const onClose = vi.fn();
    render(
      <ScheduleForm
        open
        schedule={schedule}
        onClose={onClose}
        onSaved={onSaved}
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '保存计划' })).toBeEnabled(),
    );
    expect(screen.getByLabelText('首次执行时间（上海时区）')).toHaveValue(
      '2027-01-31 02:00',
    );
    fireEvent.click(screen.getByRole('button', { name: '保存计划' }));
    await waitFor(() =>
      expect(certificateScheduleApi.save).toHaveBeenCalledOnce(),
    );
    expect(certificateScheduleApi.save).toHaveBeenCalledWith(
      schedule.id,
      expect.objectContaining({
        accountId: 'account',
        domain: 'vpn.example.com',
        targetIds: [target.id],
        intervalValue: 1,
        intervalUnit: 'month',
        revokeOldCertificates: true,
        firstRunAtUtc: '2027-01-30T18:00:00.000Z',
        configRevision: 3,
      }),
    );
    expect(onSaved).toHaveBeenCalledOnce();
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('ACME 计划保存独立 Cloudflare DNS 区域，不要求证书账号有DNS用途', async () => {
    vi.mocked(domainApi.list).mockResolvedValue(
      success({
        items: [
          {
            id: 'cf-zone',
            accountId: 'cf',
            provider: 'Cloudflare',
            name: 'example.com',
          },
        ],
        total: 1,
        page: 1,
        pageSize: 100,
      }),
    );
    render(
      <ScheduleForm
        open
        schedule={{
          ...schedule,
          accountId: 'acme',
          dnsZoneId: 'cf-zone',
        }}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '保存计划' })).toBeEnabled(),
    );
    expect(
      screen.getByLabelText('DNS 托管域（可使用独立账号）'),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '保存计划' }));
    await waitFor(() =>
      expect(certificateScheduleApi.save).toHaveBeenCalledOnce(),
    );
    expect(certificateScheduleApi.save).toHaveBeenCalledWith(
      schedule.id,
      expect.objectContaining({
        accountId: 'acme',
        dnsZoneId: 'cf-zone',
        validationMode: 'ManagedDns',
      }),
    );
  });

  it('Cloudflare DNS 账号不出现在周期证书申请账号选项中', async () => {
    render(<ScheduleForm open onClose={vi.fn()} onSaved={vi.fn()} />);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '保存计划' })).toBeEnabled(),
    );
    fireEvent.mouseDown(screen.getByLabelText('证书账号'));
    expect(await screen.findByText('腾讯云 / 测试账号')).toBeInTheDocument();
    expect(
      screen.queryByText('Cloudflare / Cloudflare DNS'),
    ).not.toBeInTheDocument();
    expect(certificateScheduleApi.save).not.toHaveBeenCalled();
  });

  it('Staging计划阻止部署且不提交给后端', async () => {
    render(
      <ScheduleForm
        open
        schedule={{ ...schedule, accountId: 'staging' }}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '保存计划' })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '保存计划' }));
    await screen.findByText(
      'Staging 测试证书不能部署，请使用生产环境 ACME 账号。',
    );
    expect(certificateScheduleApi.save).not.toHaveBeenCalled();
  });

  it.each([
    'linux.files.ssh.v1',
    'harbor.compose.ssh.v1',
  ])('%s 目标域名不匹配时阻止保存，不自动更换或增加部署目标', async (executorKey) => {
    vi.mocked(deploymentApi.targets).mockResolvedValue(
      success({
        items: [{ ...target, executorKey }],
        total: 1,
        page: 1,
        pageSize: 200,
      }),
    );
    render(
      <ScheduleForm
        open
        schedule={{ ...schedule, domain: 'other.example.com' }}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '保存计划' })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '保存计划' }));
    await screen.findByText('部分目标已停用或绑定其他域名，请重新选择。');
    expect(certificateScheduleApi.save).not.toHaveBeenCalled();
  });

  it('允许保存绑定相同域名的 Harbor 续签部署目标', async () => {
    vi.mocked(deploymentApi.targets).mockResolvedValue(
      success({
        items: [{ ...target, executorKey: 'harbor.compose.ssh.v1' }],
        total: 1,
        page: 1,
        pageSize: 200,
      }),
    );
    render(
      <ScheduleForm
        open
        schedule={schedule}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '保存计划' })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '保存计划' }));
    await waitFor(() =>
      expect(certificateScheduleApi.save).toHaveBeenCalledOnce(),
    );
    expect(certificateScheduleApi.save).toHaveBeenCalledWith(
      schedule.id,
      expect.objectContaining({
        targetIds: [target.id],
        domain: 'vpn.example.com',
      }),
    );
  });

  it('月末默认时间按上海日期取下月末，UTC无时区后缀仍按UTC读入', () => {
    expect(
      defaultScheduleFirstRun(new Date('2027-01-31T04:00:00Z')).toISOString(),
    ).toBe('2027-02-27T18:00:00.000Z');
    expect(
      defaultScheduleFirstRun(new Date('2028-01-31T04:00:00Z')).toISOString(),
    ).toBe('2028-02-28T18:00:00.000Z');
    expect(scheduleDate('2027-01-30 18:00:00').format('YYYY-MM-DD HH:mm')).toBe(
      '2027-01-31 02:00',
    );
  });
});
