import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import AgentConnection from './AgentConnection';
import {
  agentConnectionInstruction,
  copyMcpText,
  serviceBaseUrl,
  type AgentConnectionProfile,
} from './connectionInstructions';

const profile: AgentConnectionProfile = {
  systemName: '内网证书中心',
  instanceId: 'ssl-prod-1',
  mcpUrl: 'http://192.168.10.10:5001/mcp',
  authenticationType: 'ApiKey',
  clientId: 'agent-client',
};
const clipboardDescriptor = Object.getOwnPropertyDescriptor(
  navigator,
  'clipboard',
);
const commandDescriptor = Object.getOwnPropertyDescriptor(
  document,
  'execCommand',
);
const writeText = vi.fn();

describe('Agent 接入指令和 HTTP 复制', () => {
  beforeEach(() => {
    writeText.mockReset().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
    Object.defineProperty(document, 'execCommand', {
      configurable: true,
      value: vi.fn(() => false),
    });
  });
  afterEach(() => {
    if (clipboardDescriptor)
      Object.defineProperty(navigator, 'clipboard', clipboardDescriptor);
    else Reflect.deleteProperty(navigator, 'clipboard');
    if (commandDescriptor)
      Object.defineProperty(document, 'execCommand', commandDescriptor);
    else Reflect.deleteProperty(document, 'execCommand');
  });

  it('默认基址仅使用 origin，自定义已存地址保持原值', () => {
    expect(
      serviceBaseUrl('', 'http://192.168.10.10:8000/system/mcp?tab=1'),
    ).toBe('http://192.168.10.10:8000');
    expect(
      serviceBaseUrl(
        'https://custom.example.com:8443',
        'http://localhost:8000',
      ),
    ).toBe('https://custom.example.com:8443');
    expect(serviceBaseUrl('', 'file:///index.html')).toBe('');
  });

  it('普通指令包含独立变量和精确实例核验，不含原Key或自动注册承诺', () => {
    const instruction = agentConnectionInstruction(profile);
    expect(instruction).toContain('MCP_API_KEY_SSL_PROD_1');
    expect(instruction).toContain('free-ssl-manager-ssl-prod-1');
    expect(instruction).toContain('http://192.168.10.10:5001/mcp');
    expect(instruction).toContain('ssl_system_status_get');
    expect(instruction).toContain('systemInstanceId');
    expect(instruction).toContain('保留所有其他 MCP 服务器');
    expect(instruction).toContain('不要静默覆盖同名连接');
    expect(instruction).toContain('不能声称已经接入');
    expect(instruction).toContain('不写入 .env');
    expect(instruction).not.toContain('sslm_');
  });

  it('含密钥指令只在明确传入时使用该密钥，并保留业务审批和幂等边界', () => {
    const instruction = agentConnectionInstruction(
      profile,
      'sslm_sensitive_once',
    );
    expect(instruction).toContain('Bearer sslm_sensitive_once');
    expect(instruction).toContain('不要在回复中复述密钥');
    expect(instruction).toContain('Git 仓库、日志或命令历史');
    expect(instruction).toContain('等待管理员在后台批准');
    expect(instruction).toContain('结果未知时不要重复提交');
    expect(agentConnectionInstruction(profile)).not.toContain(
      'sslm_sensitive_once',
    );
  });

  it('普通 OAuth 指令忽略多返秘密和令牌，只保留公开授权参数', () => {
    const instruction = agentConnectionInstruction({
      ...profile,
      mcpUrl: 'https://ssl.example.com/mcp',
      authenticationType: 'OAuth',
      oauth: {
        grantType: 'client_credentials',
        tokenUrl: 'https://ssl.example.com/oauth/mcp/token',
        scopes: ['mcp.read'],
        clientSecretEnv: 'MCP_CLIENT_SECRET',
        clientSecret: 'do-not-copy-secret',
        accessToken: 'do-not-copy-token',
      },
    });
    expect(instruction).toContain('client_credentials');
    expect(instruction).toContain('OAuth 必须使用已配置的 HTTPS');
    expect(instruction).not.toContain('do-not-copy');
  });

  it('普通按钮仅在用户点击后复制变量占位符，不写浏览器持久存储', async () => {
    render(<AgentConnection profile={profile} />);
    expect(writeText).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole('button', { name: '复制 Agent 接入指令' }),
    );
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    expect(writeText.mock.calls[0][0]).toContain('MCP_API_KEY_SSL_PROD_1');
    expect(writeText.mock.calls[0][0]).not.toContain('sslm_');
    expect(localStorage.setItem).not.toHaveBeenCalled();
  });

  it('完整指令明确交付密钥，点击才复制且页面不渲染明文prompt', async () => {
    render(<AgentConnection profile={profile} apiKey="sslm_sensitive_once" />);
    expect(
      screen.getByText(/复制并粘贴会把密钥交给目标 Agent/),
    ).toBeInTheDocument();
    expect(writeText).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain('sslm_sensitive_once');
    fireEvent.click(
      screen.getByRole('button', { name: '复制完整接入指令（含本次密钥）' }),
    );
    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    expect(writeText.mock.calls[0][0]).toContain('Bearer sslm_sensitive_once');
    expect(localStorage.setItem).not.toHaveBeenCalled();
  });

  it('HTTP 无 Clipboard API 时回退复制，并立即清空和移除临时DOM', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: undefined,
    });
    const execCommand = vi.fn(() => {
      expect(document.querySelector('textarea')?.value).toBe('sslm_temporary');
      return true;
    });
    Object.defineProperty(document, 'execCommand', {
      configurable: true,
      value: execCommand,
    });
    await copyMcpText('sslm_temporary');
    expect(execCommand).toHaveBeenCalledWith('copy');
    expect(document.querySelector('textarea')).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain('sslm_temporary');
  });

  it('复制失败提示不包含原Key或浏览器异常中的敏感内容', async () => {
    writeText.mockRejectedValue(new Error('sslm_sensitive_once'));
    render(<AgentConnection profile={profile} apiKey="sslm_sensitive_once" />);
    fireEvent.click(
      screen.getByRole('button', { name: '复制完整接入指令（含本次密钥）' }),
    );
    expect(
      await screen.findByText('浏览器未允许复制，请检查剪贴板权限后重试。'),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('sslm_sensitive_once');
    expect(document.querySelector('textarea')).not.toBeInTheDocument();
  });

  it('未保存实例或OAuth使用HTTP时禁止生成接入指令', () => {
    const { rerender } = render(
      <AgentConnection profile={{ ...profile, instanceId: '' }} />,
    );
    expect(
      screen.getByRole('button', { name: '复制 Agent 接入指令' }),
    ).toBeDisabled();
    rerender(
      <AgentConnection profile={{ ...profile, authenticationType: 'OAuth' }} />,
    );
    expect(
      screen.getByRole('button', { name: '复制 Agent 接入指令' }),
    ).toBeDisabled();
    expect(screen.getByText(/当前地址不支持 OAuth 接入/)).toBeInTheDocument();
  });
});
