import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { App } from 'antd';
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mailApi } from '@/services/ssl-manager/mail';
import type { MailSettingsDto } from '@/services/ssl-manager/mailTypes';
import ComposeMail from './Compose';
import MailSettings from './Settings';

vi.mock('@/components/ssl-manager', () => ({
  useResultMessage: () => (result: { success: boolean }) => result.success,
}));
vi.mock('@/services/ssl-manager/mail', () => ({
  mailApi: {
    settings: vi.fn(),
    saveSettings: vi.fn(),
    probe: vi.fn(),
    send: vi.fn(),
  },
}));

const settings: MailSettingsDto = {
  configured: true,
  host: 'smtp.example.com',
  port: 465,
  security: 'SslOnConnect',
  username: 'notice@example.com',
  fromAddress: 'notice@example.com',
  fromName: '系统通知',
  hasPassword: true,
  enabled: true,
};

describe('邮件配置与发送结果', () => {
  afterEach(() => vi.unstubAllGlobals());
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(mailApi.settings).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: settings,
    });
    vi.mocked(mailApi.saveSettings).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: settings,
    });
    vi.mocked(mailApi.probe).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '连接与认证成功',
    });
  });

  it('已保存密码不回填，留空保存时使用发送邮箱作为默认登录账号', async () => {
    render(<MailSettings onTest={vi.fn()} onSaved={vi.fn()} />);
    await waitFor(() =>
      expect(screen.getByLabelText('发送邮箱')).toHaveValue(
        'notice@example.com',
      ),
    );
    expect(screen.getByLabelText('授权码 / 密码')).toHaveValue('');
    fireEvent.click(screen.getByRole('button', { name: '保存设置' }));
    await waitFor(() => expect(mailApi.saveSettings).toHaveBeenCalledOnce());
    expect(mailApi.saveSettings).toHaveBeenCalledWith(
      expect.objectContaining({
        username: 'notice@example.com',
        password: '',
        port: 465,
        security: 'SslOnConnect',
      }),
    );
  });

  it('检测已保存设置不发送邮件，修改配置后要求先保存', async () => {
    render(<MailSettings onTest={vi.fn()} onSaved={vi.fn()} />);
    const probe = screen.getByRole('button', { name: '检测连接' });
    await waitFor(() => expect(probe).toBeEnabled());
    fireEvent.click(probe);
    await screen.findByText('连接与认证成功');
    expect(mailApi.probe).toHaveBeenCalledWith();
    expect(mailApi.send).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('SMTP 服务器'), {
      target: { value: 'smtp.other.example.com' },
    });
    expect(probe).toBeDisabled();
    expect(screen.getByRole('button', { name: '发送测试邮件' })).toBeDisabled();
  });

  it('HTTP 环境缺少 randomUUID 时仍生成请求 ID，网络结果未知后停止提交', async () => {
    const secureRandom = vi.fn((bytes: Uint8Array) => bytes.fill(0));
    vi.stubGlobal('crypto', { getRandomValues: secureRandom });
    vi.mocked(mailApi.send).mockResolvedValue({
      success: false,
      code: 'NETWORK_ERROR',
      message: '网络中断',
    });
    const recorded = vi.fn();
    render(
      <App>
        <ComposeMail test onClose={vi.fn()} onRecorded={recorded} />
      </App>,
    );
    const recipient = screen.getByRole('combobox');
    fireEvent.change(recipient, { target: { value: 'recipient@example.com' } });
    fireEvent.keyDown(recipient, { key: 'Enter', code: 'Enter' });
    fireEvent.click(screen.getByRole('button', { name: /^发\s*送$/ }));
    const confirm = await screen.findByRole('button', {
      name: '确认发送',
    });
    expect(screen.getByText(/服务器受理不代表最终送达/)).toBeInTheDocument();
    fireEvent.click(confirm);
    await screen.findByText('发送结果待核验');
    expect(mailApi.send).toHaveBeenCalledOnce();
    expect(mailApi.send).toHaveBeenCalledWith(
      expect.objectContaining({
        requestId: expect.stringMatching(
          /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
        ),
        to: ['recipient@example.com'],
        subject: 'SSL 证书管理平台测试邮件',
      }),
    );
    expect(
      screen.queryByRole('button', { name: /^发\s*送$/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: '关闭并查看发件记录' }),
    ).toBeEnabled();
    expect(recorded).toHaveBeenCalledOnce();
    expect(secureRandom).toHaveBeenCalledOnce();
  });

  it('超过 50 个收件人时在发送前提示并阻止提交', async () => {
    render(
      <App>
        <ComposeMail test onClose={vi.fn()} onRecorded={vi.fn()} />
      </App>,
    );
    const recipient = screen.getByRole('combobox');
    const addresses = Array.from(
      { length: 51 },
      (_, index) => `recipient${index}@example.com`,
    );
    fireEvent.change(recipient, {
      target: { value: `${addresses.join(',')},` },
    });
    fireEvent.click(screen.getByRole('button', { name: /^发\s*送$/ }));
    await screen.findByText('每封邮件最多填写 50 个收件人');
    expect(mailApi.send).not.toHaveBeenCalled();
    expect(
      screen.queryByRole('button', { name: '确认发送' }),
    ).not.toBeInTheDocument();
  });
});
