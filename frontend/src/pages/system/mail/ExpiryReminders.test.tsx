import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { mailApi } from '@/services/ssl-manager/mail';
import type {
  ExpiryReminderAlert,
  ExpiryReminderSettingsSummary,
} from '@/services/ssl-manager/mailTypes';
import type { ApiResult, PageResult } from '@/services/ssl-manager/types';
import ExpiryReminders from './ExpiryReminders';
import MailManagement from './index';

const permission = vi.hoisted(() => ({ admin: true }));
vi.mock('@ant-design/pro-components', () => ({
  PageContainer: ({ children }: { children: React.ReactNode }) => (
    <main>{children}</main>
  ),
}));
vi.mock('./Messages', () => ({ default: () => <div>发件记录测试入口</div> }));
vi.mock('./Settings', () => ({ default: () => <div>邮箱设置测试入口</div> }));
vi.mock('@umijs/max', () => ({
  useAccess: () => ({ canAdmin: permission.admin }),
}));
vi.mock('@/components/ssl-manager', () => ({
  dateText: (value?: string) => value || '—',
}));
vi.mock('@/services/ssl-manager/mail', () => ({
  mailApi: {
    expiryReminderSettings: vi.fn(),
    saveExpiryReminderSettings: vi.fn(),
    expiryReminderAlerts: vi.fn(),
    ignoreExpiryReminderAlert: vi.fn(),
    send: vi.fn(),
    probe: vi.fn(),
  },
}));

const summary: ExpiryReminderSettingsSummary = {
  configured: true,
  enabled: true,
  daysBeforeExpiry: 30,
  repeatIntervalDays: 1,
  recipients: ['ops@example.com'],
  smtpConfigured: true,
  smtpEnabled: true,
  updatedAtUtc: '2026-11-02T10:00:00Z',
};
const alert: ExpiryReminderAlert = {
  id: 'alert-1',
  certificateId: 'certificate-1',
  accountName: '测试云账号',
  domain: 'expiry.example.com',
  alias: '业务证书',
  notAfterUtc: '2026-11-20T00:00:00Z',
  status: 'Active',
  firstDetectedAtUtc: '2026-11-01T00:00:00Z',
  lastAttemptAtUtc: '2026-11-02T00:00:00Z',
  nextReminderAtUtc: '2026-11-03T00:00:00Z',
  lastMailStatus: 'Accepted',
  message: '邮件服务器已受理',
};
const ok = <T,>(data: T): ApiResult<T> => ({
  success: true,
  code: 'OK',
  message: '',
  data,
});
const page = (
  items: ExpiryReminderAlert[] = [alert],
  total = items.length,
  current = 1,
): PageResult<ExpiryReminderAlert> => ({
  items,
  total,
  page: current,
  pageSize: 20,
});

async function ready() {
  await waitFor(() =>
    expect(screen.getByRole('button', { name: '保存提醒设置' })).toBeEnabled(),
  );
}
async function chooseStatus(label: string) {
  fireEvent.mouseDown(screen.getByRole('combobox', { name: '预警状态' }));
  fireEvent.click(
    await screen.findByText(label, {
      selector: '.ant-select-item-option-content',
    }),
  );
}

describe('证书到期提醒设置与预警', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    permission.admin = true;
    vi.mocked(mailApi.expiryReminderSettings).mockResolvedValue(ok(summary));
    vi.mocked(mailApi.saveExpiryReminderSettings).mockResolvedValue(
      ok(summary),
    );
    vi.mocked(mailApi.expiryReminderAlerts).mockResolvedValue(ok(page()));
    vi.mocked(mailApi.ignoreExpiryReminderAlert).mockResolvedValue(
      ok({ ...alert, status: 'Ignored' }),
    );
  });

  it('非管理员不可进入，且不读取规则和预警', () => {
    permission.admin = false;
    render(<ExpiryReminders />);
    expect(screen.getByText('无到期提醒管理权限')).toBeInTheDocument();
    expect(mailApi.expiryReminderSettings).not.toHaveBeenCalled();
    expect(mailApi.expiryReminderAlerts).not.toHaveBeenCalled();
  });

  it('邮件管理页通过到期提醒标签进入，切换时才读取提醒规则', async () => {
    render(<MailManagement />);
    expect(mailApi.expiryReminderSettings).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('tab', { name: '到期提醒' }));
    await ready();
    expect(await screen.findByText('expiry.example.com')).toBeInTheDocument();
    expect(mailApi.expiryReminderSettings).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole('tab', { name: '邮箱设置' }));
    await screen.findByText('邮箱设置测试入口');
    expect(screen.queryByText('expiry.example.com')).not.toBeInTheDocument();
  });

  it('读取现有规则和服务端分页预警，并解释重复及解除规则', async () => {
    render(<ExpiryReminders />);
    await ready();
    expect(screen.getByLabelText('提前提醒天数')).toHaveDisplayValue('30');
    expect(screen.getByLabelText('重复提醒间隔（天）')).toHaveDisplayValue('1');
    expect(screen.getByRole('switch')).toBeChecked();
    expect(await screen.findByText('expiry.example.com')).toBeInTheDocument();
    expect(
      screen.getByText(/未解除的预警在证书过期后仍继续提醒/),
    ).toBeInTheDocument();
    expect(screen.getByText('已提交邮件服务器')).toBeInTheDocument();
    expect(mailApi.expiryReminderAlerts).toHaveBeenCalledWith({
      page: 1,
      pageSize: 20,
      status: 'Active',
    });
    expect(mailApi.send).not.toHaveBeenCalled();
    expect(mailApi.probe).not.toHaveBeenCalled();
  });

  it.each([
    [false, false, '尚未配置 SMTP，提醒暂时无法发送。'],
    [true, false, '系统邮件发送已停用，提醒暂时无法发送。'],
  ])('SMTP configured=%s enabled=%s 时提示等待且允许保存规则', async (smtpConfigured, smtpEnabled, message) => {
    vi.mocked(mailApi.expiryReminderSettings).mockResolvedValue(
      ok({ ...summary, smtpConfigured, smtpEnabled }),
    );
    render(<ExpiryReminders />);
    await ready();
    expect(screen.getByText(message)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '保存提醒设置' }));
    await waitFor(() =>
      expect(mailApi.saveExpiryReminderSettings).toHaveBeenCalledOnce(),
    );
    expect(mailApi.send).not.toHaveBeenCalled();
  });

  it('保存支持仅首次提醒，收件人去空白去重，重复点击不重复保存或发信', async () => {
    const initial = {
      ...summary,
      repeatIntervalDays: 0,
      recipients: [' OPS@example.com ', 'ops@example.com'],
    };
    vi.mocked(mailApi.expiryReminderSettings).mockResolvedValue(ok(initial));
    let resolveSave!: (value: ApiResult<ExpiryReminderSettingsSummary>) => void;
    vi.mocked(mailApi.saveExpiryReminderSettings).mockReturnValue(
      new Promise((resolve) => {
        resolveSave = resolve;
      }),
    );
    render(<ExpiryReminders />);
    await ready();
    const save = screen.getByRole('button', { name: '保存提醒设置' });
    fireEvent.click(save);
    fireEvent.click(save);
    await waitFor(() =>
      expect(mailApi.saveExpiryReminderSettings).toHaveBeenCalledOnce(),
    );
    expect(mailApi.saveExpiryReminderSettings).toHaveBeenCalledWith({
      enabled: true,
      daysBeforeExpiry: 30,
      repeatIntervalDays: 0,
      recipients: ['OPS@example.com'],
    });
    await act(async () =>
      resolveSave(ok({ ...initial, recipients: ['OPS@example.com'] })),
    );
    await screen.findByText(
      '到期提醒设置已保存，后台将按规则检查；本次保存未发送邮件。',
    );
    expect(mailApi.send).not.toHaveBeenCalled();
    expect(mailApi.probe).not.toHaveBeenCalled();
  });

  it('停用提醒时允许不填收件人', async () => {
    vi.mocked(mailApi.expiryReminderSettings).mockResolvedValue(
      ok({ ...summary, enabled: false, recipients: [] }),
    );
    render(<ExpiryReminders />);
    await ready();
    fireEvent.click(screen.getByRole('button', { name: '保存提醒设置' }));
    await waitFor(() =>
      expect(mailApi.saveExpiryReminderSettings).toHaveBeenCalledWith(
        expect.objectContaining({ enabled: false, recipients: [] }),
      ),
    );
  });

  it('发送前取消的预警显示尚未提交 SMTP，不显示未知状态原文', async () => {
    vi.mocked(mailApi.expiryReminderAlerts).mockResolvedValue(
      ok(page([{ ...alert, lastMailStatus: 'NotSubmitted' }])),
    );
    render(<ExpiryReminders />);
    await screen.findByText('尚未提交 SMTP');
    expect(screen.queryByText('NotSubmitted')).not.toBeInTheDocument();
  });

  it.each([
    [[], '启用提醒时请至少填写一个收件邮箱'],
    [['invalid-address'], '请检查收件邮箱格式'],
    [
      Array.from({ length: 51 }, (_, index) => `ops${index}@example.com`),
      '最多填写 50 个收件邮箱',
    ],
  ])('收件人验证失败时阻止保存', async (recipients, message) => {
    vi.mocked(mailApi.expiryReminderSettings).mockResolvedValue(
      ok({ ...summary, recipients }),
    );
    render(<ExpiryReminders />);
    await ready();
    fireEvent.click(screen.getByRole('button', { name: '保存提醒设置' }));
    await screen.findByText(message);
    expect(mailApi.saveExpiryReminderSettings).not.toHaveBeenCalled();
  });

  it.each([
    ['daysBeforeExpiry', 0, '提前天数须为 1～365 的整数'],
    ['daysBeforeExpiry', 366, '提前天数须为 1～365 的整数'],
    ['repeatIntervalDays', -1, '重复间隔须为 0～365 的整数'],
    ['repeatIntervalDays', 366, '重复间隔须为 0～365 的整数'],
  ])('%s=%s 时阻止保存', async (field, value, message) => {
    vi.mocked(mailApi.expiryReminderSettings).mockResolvedValue(
      ok({ ...summary, [field]: value }),
    );
    render(<ExpiryReminders />);
    await ready();
    fireEvent.click(screen.getByRole('button', { name: '保存提醒设置' }));
    await screen.findByText(message);
    expect(mailApi.saveExpiryReminderSettings).not.toHaveBeenCalled();
  });

  it('忽略须明确确认，取消不提交，重复确认只写一次并刷新列表', async () => {
    vi.mocked(mailApi.expiryReminderAlerts)
      .mockResolvedValueOnce(ok(page()))
      .mockResolvedValueOnce(ok(page([])));
    let resolveIgnore!: (value: ApiResult<unknown>) => void;
    vi.mocked(mailApi.ignoreExpiryReminderAlert).mockReturnValue(
      new Promise((resolve) => {
        resolveIgnore = resolve;
      }),
    );
    render(<ExpiryReminders />);
    await ready();
    fireEvent.click(await screen.findByRole('button', { name: /^忽\s*略$/ }));
    expect(screen.getByText(/仅停止后续提醒/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /^取\s*消$/ }));
    expect(mailApi.ignoreExpiryReminderAlert).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: /^忽\s*略$/ }));
    const confirm = screen.getByRole('button', { name: '确认忽略' });
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    expect(mailApi.ignoreExpiryReminderAlert).toHaveBeenCalledOnce();
    expect(mailApi.ignoreExpiryReminderAlert).toHaveBeenCalledWith('alert-1');
    await act(async () => resolveIgnore(ok({ ...alert, status: 'Ignored' })));
    await screen.findByText('已忽略该预警，后续提醒已停止。');
    await waitFor(() =>
      expect(screen.queryByText('expiry.example.com')).not.toBeInTheDocument(),
    );
  });

  it('状态过滤和翻页都请求服务端，切换状态重置页码', async () => {
    vi.mocked(mailApi.expiryReminderAlerts).mockResolvedValue(
      ok(page([alert], 41)),
    );
    render(<ExpiryReminders />);
    await ready();
    await screen.findByText('expiry.example.com');
    await waitFor(() =>
      expect(screen.getByTitle('Next Page')).not.toHaveAttribute(
        'aria-disabled',
        'true',
      ),
    );
    fireEvent.click(screen.getByTitle('Next Page'));
    await waitFor(() =>
      expect(mailApi.expiryReminderAlerts).toHaveBeenLastCalledWith({
        page: 2,
        pageSize: 20,
        status: 'Active',
      }),
    );
    await chooseStatus('全部状态');
    await waitFor(() =>
      expect(mailApi.expiryReminderAlerts).toHaveBeenLastCalledWith({
        page: 1,
        pageSize: 20,
        status: undefined,
      }),
    );
  });

  it('切换状态后迟到的旧列表响应不能覆盖当前结果', async () => {
    let resolveOld!: (
      value: ApiResult<PageResult<ExpiryReminderAlert>>,
    ) => void;
    vi.mocked(mailApi.expiryReminderAlerts)
      .mockReturnValueOnce(
        new Promise((resolve) => {
          resolveOld = resolve;
        }),
      )
      .mockResolvedValueOnce(
        ok(
          page([
            {
              ...alert,
              id: 'resolved',
              domain: 'resolved.example.com',
              status: 'Resolved',
            },
          ]),
        ),
      );
    render(<ExpiryReminders />);
    await ready();
    await chooseStatus('已解除');
    await screen.findByText('resolved.example.com');
    await act(async () => resolveOld(ok(page())));
    expect(screen.queryByText('expiry.example.com')).not.toBeInTheDocument();
    expect(screen.getByText('resolved.example.com')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /^忽\s*略$/ }),
    ).not.toBeInTheDocument();
  });

  it('读取规则失败后可重新加载，未加载成功前不能保存', async () => {
    vi.mocked(mailApi.expiryReminderSettings)
      .mockResolvedValueOnce({
        success: false,
        code: 'SYSTEM_ERROR',
        message: '读取失败',
      })
      .mockResolvedValueOnce(ok(summary));
    render(<ExpiryReminders />);
    await screen.findByText('读取失败');
    expect(screen.getByRole('button', { name: '保存提醒设置' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: '重新加载规则' }));
    await ready();
    expect(screen.queryByText('读取失败')).not.toBeInTheDocument();
  });

  it('忽略请求结果不明时停止提交并提示刷新核验', async () => {
    vi.mocked(mailApi.ignoreExpiryReminderAlert).mockResolvedValue({
      success: false,
      code: 'NETWORK_ERROR',
      message: '连接中断',
    });
    render(<ExpiryReminders />);
    await ready();
    fireEvent.click(await screen.findByRole('button', { name: /^忽\s*略$/ }));
    fireEvent.click(screen.getByRole('button', { name: '确认忽略' }));
    await screen.findByText('忽略请求结果暂时无法确认，请刷新预警列表核对。');
    expect(mailApi.ignoreExpiryReminderAlert).toHaveBeenCalledOnce();
    expect(
      screen.queryByRole('button', { name: '确认忽略' }),
    ).not.toBeInTheDocument();
  });

  it.each([
    'settings',
    'alerts',
    'save',
    'ignore',
  ] as const)('%s接口返回403时清除规则收件人与预警', async (operation) => {
    const forbidden = {
      success: false,
      code: 'FORBIDDEN',
      message: '无管理权限',
    };
    if (operation === 'settings')
      vi.mocked(mailApi.expiryReminderSettings).mockResolvedValue(forbidden);
    if (operation === 'alerts')
      vi.mocked(mailApi.expiryReminderAlerts).mockResolvedValue(forbidden);
    if (operation === 'save')
      vi.mocked(mailApi.saveExpiryReminderSettings).mockResolvedValue(
        forbidden,
      );
    if (operation === 'ignore')
      vi.mocked(mailApi.ignoreExpiryReminderAlert).mockResolvedValue(forbidden);
    render(<ExpiryReminders />);
    if (operation === 'save') {
      await ready();
      fireEvent.click(screen.getByRole('button', { name: '保存提醒设置' }));
    }
    if (operation === 'ignore') {
      await ready();
      fireEvent.click(await screen.findByRole('button', { name: /^忽\s*略$/ }));
      fireEvent.click(screen.getByRole('button', { name: '确认忽略' }));
    }
    await screen.findByText('登录或管理权限已失效，已清除到期提醒信息。');
    expect(screen.queryByText('ops@example.com')).not.toBeInTheDocument();
    expect(screen.queryByText('expiry.example.com')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: '确认忽略' }),
    ).not.toBeInTheDocument();
  });

  it('会话失效后清除信息，迟到的规则和列表响应不会恢复页面', async () => {
    let resolveSettings!: (
      value: ApiResult<ExpiryReminderSettingsSummary>,
    ) => void;
    let resolveAlerts!: (
      value: ApiResult<PageResult<ExpiryReminderAlert>>,
    ) => void;
    vi.mocked(mailApi.expiryReminderSettings).mockReturnValue(
      new Promise((resolve) => {
        resolveSettings = resolve;
      }),
    );
    vi.mocked(mailApi.expiryReminderAlerts).mockReturnValue(
      new Promise((resolve) => {
        resolveAlerts = resolve;
      }),
    );
    render(<ExpiryReminders />);
    act(() => window.dispatchEvent(new Event('ssl-auth-expired')));
    await act(async () => {
      resolveSettings(ok(summary));
      resolveAlerts(ok(page()));
    });
    expect(
      screen.getByText('登录或管理权限已失效，已清除到期提醒信息。'),
    ).toBeInTheDocument();
    expect(screen.queryByText('ops@example.com')).not.toBeInTheDocument();
    expect(screen.queryByText('expiry.example.com')).not.toBeInTheDocument();
  });
});
