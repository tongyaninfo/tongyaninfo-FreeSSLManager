import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { Modal } from 'antd';
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { accountApi, userApi } from '@/services/ssl-manager/api';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import { mcpApi } from '@/services/ssl-manager/mcp';
import type {
  McpClient,
  McpApiKey,
  McpCallLog,
  McpOperation,
  McpSettings,
  McpTool,
} from '@/services/ssl-manager/mcpTypes';
import AllowRules from './AllowRules';
import CallLogs from './CallLogs';
import Clients, { connectionTemplate } from './Clients';
import ApiKeys, {
  apiKeyConnectionTemplate,
  apiKeyEnvironmentName,
} from './ApiKeys';
import AuditContext, { parseMcpContext } from './AuditContext';
import McpManagement from './index';
import { canApproveOperation, mcpDate, mcpLines } from './presentation';
import Settings from './Settings';

const permission = vi.hoisted(() => ({ admin: true }));
vi.mock('@umijs/max', () => ({
  useAccess: () => ({ canAdmin: permission.admin }),
}));
vi.mock('@ant-design/pro-components', () => ({
  PageContainer: ({ children }: { children: React.ReactNode }) => (
    <main>{children}</main>
  ),
}));
vi.mock('@/components/ssl-manager', () => ({
  useResultMessage: () => (result: { success: boolean }) => result.success,
}));
vi.mock('@/services/ssl-manager/mcp', () => ({
  mcpApi: {
    settings: vi.fn(),
    saveSettings: vi.fn(),
    status: vi.fn(),
    tools: vi.fn(),
    clients: vi.fn(),
    createClient: vi.fn(),
    updateClient: vi.fn(),
    clientStatus: vi.fn(),
    rotateSecret: vi.fn(),
    apiKeys: vi.fn(),
    createApiKey: vi.fn(),
    apiKeyStatus: vi.fn(),
    rotateApiKey: vi.fn(),
    revokeApiKey: vi.fn(),
    revokeClient: vi.fn(),
    rules: vi.fn(),
    saveRules: vi.fn(),
    connectionProfile: vi.fn(),
    callLogs: vi.fn(),
    callStatistics: vi.fn(),
    callLog: vi.fn(),
    operations: vi.fn(),
    operation: vi.fn(),
    approve: vi.fn(),
    reject: vi.fn(),
  },
}));
vi.mock('@/services/ssl-manager/api', () => ({
  accountApi: { options: vi.fn() },
  userApi: { list: vi.fn() },
}));
vi.mock('@/services/ssl-manager/deployment', () => ({
  deploymentApi: { targets: vi.fn() },
}));
const ok = <T,>(data: T) => ({ success: true, code: 'OK', message: '', data });
const page = <T,>(items: T[]) => ({
  items,
  total: items.length,
  page: 1,
  pageSize: 20,
});
const settings: McpSettings = {
  systemName: '生产证书中心',
  instanceId: 'ssl-instance-1',
  enabled: false,
  publicBaseUrl: '',
  mode: 'ReadOnly',
  allowedCidrs: [],
  allowedOrigins: [],
  allowedTools: [],
  rateLimitPerMinute: 60,
  maxConcurrentCalls: 4,
  logRetentionDays: 90,
  configRevision: 5,
};
const client: McpClient = {
  id: 'local-client',
  clientId: 'oauth-client',
  name: '自动化客户端',
  clientType: 'confidential',
  grantType: 'client_credentials',
  boundUserId: 'viewer-user',
  scopes: ['mcp.read'],
  redirectUris: [],
  enabled: false,
  configRevision: 3,
  createdAtUtc: '2026-11-02T00:00:00Z',
  updatedAtUtc: '2026-11-02T00:00:00Z',
};
const apiKey: McpApiKey = {
  id: 'key-1',
  clientId: client.clientId,
  name: '运维 Agent',
  prefix: 'sslm_test',
  enabled: true,
  configRevision: 3,
  createdAtUtc: '2026-11-04T00:00:00Z',
  updatedAtUtc: '2026-11-04T00:00:00Z',
};
const tool: McpTool = {
  name: 'ssl_certificates_list',
  title: '证书查询',
  description: '只读取已授权证书',
  readOnly: true,
  scopes: ['mcp.read'],
  resourceKinds: ['account', 'domain'],
  inputSchema: { type: 'object' },
};
const operation: McpOperation = {
  id: 'operation-1',
  kind: 'CertificateApplication',
  toolName: 'ssl_certificate_application_prepare',
  status: 'Prepared',
  idempotencyKey: 'client-key',
  effectiveUserId: 'original-user',
  preparedBy: 'original-user',
  approvedBy: '',
  approvalExpiresAtUtc: '2099-01-01T00:00:00Z',
  certificateId: '',
  certificateJobId: '',
  batchId: '',
  taskId: '',
  planRevision: 0,
  version: 7,
  createdAtUtc: '2026-11-02T10:00:00Z',
  updatedAtUtc: '2026-11-02T10:00:00Z',
  message: '',
  code: '',
  summaryJson: JSON.stringify({
    accountId: 'account-1',
    domain: 'harbor.example.com',
    free: true,
    dnsImpact: '创建临时 DNS 验证记录',
  }),
  canApprove: true,
};

describe('MCP 管理界面', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    permission.admin = true;
    vi.mocked(mcpApi.settings).mockResolvedValue(ok(settings));
    vi.mocked(mcpApi.status).mockResolvedValue(
      ok({
        supported: true,
        systemName: '生产证书中心',
        instanceId: 'ssl-instance-1',
        apiKeyReady: true,
        enabled: false,
        oAuthReady: true,
        state: 'Disabled',
        message: '服务已关闭',
        mcpUrl: '',
        protocolVersions: ['2026-07-28'],
        sdkVersion: '2.3.0',
      }),
    );
    vi.mocked(mcpApi.tools).mockResolvedValue(ok([tool]));
    vi.mocked(mcpApi.saveSettings).mockResolvedValue(
      ok({ ...settings, configRevision: 6 }),
    );
    vi.mocked(mcpApi.clients).mockResolvedValue(ok(page([client])));
    vi.mocked(mcpApi.rules).mockResolvedValue(
      ok({ rules: [], configRevision: 3 }),
    );
    vi.mocked(mcpApi.saveRules).mockResolvedValue(
      ok({ rules: [], configRevision: 4 }),
    );
    vi.mocked(mcpApi.callLogs).mockResolvedValue(ok(page([])));
    vi.mocked(mcpApi.callStatistics).mockResolvedValue(
      ok({
        fromUtc: '2026-11-01T00:00:00Z',
        toUtc: '2026-11-04T00:00:00Z',
        totalRequests: 0,
        toolCalls: 0,
        succeeded: 0,
        failed: 0,
        denied: 0,
        unknown: 0,
        averageDurationMilliseconds: null,
        trend: [],
      }),
    );
    vi.mocked(mcpApi.apiKeys).mockResolvedValue(ok([]));
    vi.mocked(mcpApi.operations).mockResolvedValue(ok(page([operation])));
    vi.mocked(mcpApi.operation).mockResolvedValue(ok(operation));
    vi.mocked(mcpApi.approve).mockResolvedValue(
      ok({
        ...operation,
        status: 'Approved',
        approvedBy: 'admin-user',
        canApprove: false,
      }),
    );
    vi.mocked(userApi.list).mockResolvedValue(
      ok(
        page([
          {
            id: 'viewer-user',
            username: 'viewer',
            displayName: '只读调用用户',
            role: 'viewer',
            enabled: true,
          },
        ]),
      ),
    );
    vi.mocked(accountApi.options).mockResolvedValue(ok([]));
    vi.mocked(deploymentApi.targets).mockResolvedValue(ok(page([])));
  });
  afterEach(() => Modal.destroyAll());

  it('查看者不挂载任何 MCP 管理内容或发起管理请求', () => {
    permission.admin = false;
    render(<McpManagement />);
    expect(screen.getByText('无 MCP 管理权限')).toBeInTheDocument();
    expect(mcpApi.settings).not.toHaveBeenCalled();
    expect(mcpApi.clients).not.toHaveBeenCalled();
  });

  it('保存设置保留空工具与来源白名单和修订，不隐式放开访问', async () => {
    render(<Settings />);
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: '保存 MCP 设置' }),
      ).toBeEnabled(),
    );
    expect(
      screen.getByRole('switch', { name: '启用 MCP 服务' }),
    ).not.toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: '保存 MCP 设置' }));
    await waitFor(() => expect(mcpApi.saveSettings).toHaveBeenCalledOnce());
    expect(mcpApi.saveSettings).toHaveBeenCalledWith(
      expect.objectContaining({
        enabled: false,
        allowedTools: [],
        allowedCidrs: [],
        allowedOrigins: [],
        configRevision: 5,
      }),
    );
  });

  it('空服务基址默认当前origin，内网HTTP可提交且不含后台路径', async () => {
    render(<Settings />);
    const input = await screen.findByLabelText('服务基址（HTTP / HTTPS）');
    await waitFor(() => expect(input).toHaveValue(window.location.origin));
    fireEvent.change(input, { target: { value: 'http://192.168.10.10:5001' } });
    expect(
      screen.getByText(
        'HTTP 仅用于受信任内网的 API Key 接入，OAuth 仍须 HTTPS。',
      ),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '保存 MCP 设置' }));
    await waitFor(() =>
      expect(mcpApi.saveSettings).toHaveBeenCalledWith(
        expect.objectContaining({ publicBaseUrl: 'http://192.168.10.10:5001' }),
      ),
    );
  });

  it('已保存的自定义服务基址不会被当前浏览器origin覆盖', async () => {
    vi.mocked(mcpApi.settings).mockResolvedValue(
      ok({ ...settings, publicBaseUrl: 'https://custom.example.com:8443' }),
    );
    render(<Settings />);
    await waitFor(() =>
      expect(screen.getByLabelText('服务基址（HTTP / HTTPS）')).toHaveValue(
        'https://custom.example.com:8443',
      ),
    );
  });

  it('服务基址拒绝后台路径，不把页面URL误作MCP服务地址', async () => {
    render(<Settings />);
    const input = await screen.findByLabelText('服务基址（HTTP / HTTPS）');
    await waitFor(() => expect(input).toBeEnabled());
    fireEvent.change(input, {
      target: { value: 'http://192.168.10.10:5001/system/mcp' },
    });
    fireEvent.click(screen.getByRole('button', { name: '保存 MCP 设置' }));
    expect(
      await screen.findByText(
        '请输入不含账号、路径、查询参数和片段的 HTTP / HTTPS 地址',
      ),
    ).toBeInTheDocument();
    expect(mcpApi.saveSettings).not.toHaveBeenCalled();
  });

  it('桌面等不支持环境禁止启用，已有配置也不能重新打开外部服务', async () => {
    vi.mocked(mcpApi.status).mockResolvedValue(
      ok({
        supported: false,
        systemName: '桌面证书中心',
        instanceId: 'desktop-instance',
        apiKeyReady: false,
        enabled: false,
        oAuthReady: false,
        state: 'Unsupported',
        message: '桌面模式不支持外部 MCP',
        mcpUrl: '',
        protocolVersions: [],
        sdkVersion: '2.3.0',
      }),
    );
    render(<Settings />);
    await screen.findByText('当前环境不支持');
    expect(
      screen.getByRole('switch', { name: '启用 MCP 服务' }),
    ).toBeDisabled();
    expect(
      screen.getAllByText('桌面模式不支持外部 MCP').length,
    ).toBeGreaterThan(0);
  });

  it('一次展示客户端秘密，会话失效立即卸载，秘密不会写入localStorage', async () => {
    vi.mocked(mcpApi.rotateSecret).mockResolvedValue(
      ok({ clientId: client.clientId, clientSecret: 'one-time-test-secret' }),
    );
    render(<McpManagement />);
    fireEvent.click(screen.getByRole('tab', { name: '接入客户端' }));
    fireEvent.click(await screen.findByRole('button', { name: '轮换秘密' }));
    fireEvent.click(
      within(await screen.findByRole('dialog')).getByRole('button', {
        name: '轮换秘密',
      }),
    );
    await waitFor(() =>
      expect(screen.getByLabelText('一次展示的客户端秘密')).toHaveValue(
        'one-time-test-secret',
      ),
    );
    expect(mcpApi.rotateSecret).toHaveBeenCalledWith(client.id);
    expect(localStorage.setItem).not.toHaveBeenCalled();
    await act(async () => {
      window.dispatchEvent(new Event('ssl-auth-expired'));
    });
    expect(
      screen.queryByLabelText('一次展示的客户端秘密'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('tab', { name: '接入客户端' }),
    ).not.toBeInTheDocument();
  });

  it('公开客户端仅提供PKCE流程，不提供机器秘密或机器流程', async () => {
    render(<Clients onConfigureRules={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: '新增客户端' }));
    fireEvent.mouseDown(screen.getByLabelText('授权流程'));
    expect(
      screen.queryByText('机器 client_credentials'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText('一次展示的客户端秘密'),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/管理员审批不会将调用身份提升为管理员/),
    ).toBeInTheDocument();
  });

  it('迁移后客户端必须先重绑本地用户，保存资料不会自动启用或修改角色', async () => {
    const imported = { ...client, boundUserId: '', enabled: false };
    vi.mocked(mcpApi.clients)
      .mockResolvedValueOnce(ok(page([imported])))
      .mockResolvedValue(ok(page([client])));
    vi.mocked(mcpApi.updateClient).mockResolvedValue(ok(client));
    render(<Clients onConfigureRules={vi.fn()} />);
    await screen.findByText('待重新绑定本地用户');
    expect(userApi.list).toHaveBeenCalledWith({ page: 1, pageSize: 100 });
    expect(screen.getByRole('button', { name: /^启用$/ })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: '编辑' }));
    await screen.findByText(
      '迁移后的客户端尚未绑定本地用户，不能启用或取得业务权限。',
    );
    fireEvent.mouseDown(screen.getByLabelText('绑定现有用户'));
    fireEvent.click(
      await screen.findByText('只读调用用户 · 只读用户', {
        selector: '.ant-select-item-option-content',
      }),
    );
    fireEvent.click(screen.getByRole('button', { name: '保存客户端' }));
    await waitFor(() =>
      expect(mcpApi.updateClient).toHaveBeenCalledWith(
        client.id,
        expect.objectContaining({
          boundUserId: 'viewer-user',
          configRevision: client.configRevision,
        }),
      ),
    );
    const input = vi.mocked(mcpApi.updateClient).mock.calls[0][1];
    expect(input).not.toHaveProperty('role');
    expect(input).not.toHaveProperty('enabled');
    expect(mcpApi.clientStatus).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^启用$/ })).toBeEnabled(),
    );
  });

  it('绑定用户跨页加载，第101位有效用户仍可编辑绑定并启用客户端', async () => {
    // UsersController 每页最多 100 条，第二页的绑定用户不能被误判为失效。
    const firstPage = Array.from({ length: 100 }, (_, index) => ({
      id: `first-page-user-${index}`,
      username: `viewer-${index}`,
      displayName: `第一页用户 ${index}`,
      role: 'viewer' as const,
      enabled: true,
    }));
    vi.mocked(userApi.list)
      .mockResolvedValueOnce(
        ok({ items: firstPage, total: 101, page: 1, pageSize: 100 }),
      )
      .mockResolvedValueOnce(
        ok({
          items: [
            {
              id: client.boundUserId,
              username: 'last-viewer',
              displayName: '第101位调用用户',
              role: 'viewer' as const,
              enabled: true,
            },
          ],
          total: 101,
          page: 2,
          pageSize: 100,
        }),
      );
    render(<Clients onConfigureRules={vi.fn()} />);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^启用$/ })).toBeEnabled(),
    );
    expect(userApi.list).toHaveBeenNthCalledWith(1, {
      page: 1,
      pageSize: 100,
    });
    expect(userApi.list).toHaveBeenNthCalledWith(2, {
      page: 2,
      pageSize: 100,
    });
    expect(userApi.list).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: '编辑' }));
    fireEvent.mouseDown(screen.getByLabelText('绑定现有用户'));
    fireEvent.change(screen.getByLabelText('绑定现有用户'), {
      target: { value: '第101位' },
    });
    expect(
      await screen.findByText('第101位调用用户 · 只读用户', {
        selector: '.ant-select-item-option-content',
      }),
    ).toBeInTheDocument();
    expect(mcpApi.clientStatus).not.toHaveBeenCalled();
  });

  it('空规则不自动授权，新草稿的全部资源选项均关闭', async () => {
    render(<AllowRules initialClientId={client.id} />);
    await screen.findByText('当前没有允许规则，此客户端的工具调用将被拒绝。');
    expect(mcpApi.saveRules).not.toHaveBeenCalled();
    expect(mcpApi.clients).toHaveBeenCalledWith({ page: 1, pageSize: 100 });
    fireEvent.click(screen.getByRole('button', { name: '添加允许规则' }));
    for (const name of [
      '显式允许全部云账号',
      '显式允许全部域名',
      '显式允许全部部署目标',
    ])
      expect(screen.getByRole('checkbox', { name })).not.toBeChecked();
    expect(screen.getByLabelText('本规则允许来源 IP / CIDR')).toHaveValue('');
  });

  it('审批发送原草稿版本，展示实际用户及DNS影响，批准不改变执行身份', async () => {
    render(<CallLogs />);
    fireEvent.click(screen.getByRole('tab', { name: '待确认与历史操作' }));
    fireEvent.click(
      await screen.findByRole('button', { name: '核对操作详情' }),
    );
    await screen.findByText('创建临时 DNS 验证记录');
    expect(
      screen.getByRole('region', { name: '审批内容摘要' }),
    ).toHaveTextContent('account-1');
    expect(screen.getAllByText('original-user').length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: '批准此操作' }));
    fireEvent.click(
      await screen.findByRole('button', { name: '核对无误，批准' }),
    );
    await waitFor(() =>
      expect(mcpApi.approve).toHaveBeenCalledWith(operation.id, 7, ''),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole('button', { name: '批准此操作' }),
      ).not.toBeInTheDocument(),
    );
    expect(screen.getAllByText('original-user').length).toBeGreaterThan(0);
  });

  it('连接模板逐字段导出，忽略服务器意外多返的秘密', () => {
    const output = connectionTemplate({
      mcpUrl: 'https://ssl.example.com/mcp',
      systemName: '生产证书中心',
      instanceId: 'ssl-instance-1',
      clientId: 'public-id',
      transport: 'streamable-http',
      grantType: 'client_credentials',
      scopes: ['mcp.read'],
      authorizationUrl: 'https://ssl.example.com/oauth/mcp/authorize',
      tokenUrl: 'https://ssl.example.com/oauth/mcp/token',
      clientSecret: 'do-not-export',
      accessToken: 'do-not-export-token',
    } as unknown as Parameters<typeof connectionTemplate>[0]);
    expect(JSON.stringify(output)).not.toContain('do-not-export');
    expect(output.oauth.clientSecretEnv).toBe('MCP_CLIENT_SECRET');
    const codeProfile = {
      systemName: '生产证书中心',
      instanceId: 'ssl-instance-1',
      mcpUrl: 'https://ssl.example.com/mcp',
      clientId: 'code-client',
      transport: 'streamable-http',
      grantType: 'authorization_code' as const,
      scopes: ['mcp.read'],
      authorizationUrl: 'https://ssl.example.com/oauth/mcp/authorize',
      tokenUrl: 'https://ssl.example.com/oauth/mcp/token',
    };
    expect(
      connectionTemplate(codeProfile, 'public').oauth.clientSecretEnv,
    ).toBeUndefined();
    expect(
      connectionTemplate(codeProfile, 'confidential').oauth.clientSecretEnv,
    ).toBe('MCP_CLIENT_SECRET');
  });

  it('时间使用上海时区，已过期或已提交操作不能再审批，空白名单保持空', () => {
    expect(mcpLines('  \n , ')).toEqual([]);
    expect(mcpLines('192.0.2.1\n192.0.2.1,2001:db8::1')).toEqual([
      '192.0.2.1',
      '2001:db8::1',
    ]);
    expect(mcpDate('2026-11-02T00:00:00Z')).toContain('08:00:00');
    expect(
      canApproveOperation({
        status: 'Prepared',
        approvalExpiresAtUtc: '2026-01-01T00:00:00Z',
      }),
    ).toBe(false);
    expect(
      canApproveOperation({
        status: 'Submitted',
        approvalExpiresAtUtc: '2099-01-01T00:00:00Z',
      }),
    ).toBe(false);
  });

  it('API Key 创建仅展示当前明文，切换标签后清除且不持久化', async () => {
    vi.mocked(mcpApi.createApiKey).mockResolvedValue(
      ok({ key: apiKey, apiKey: 'sslm_one-time-test' }),
    );
    render(<McpManagement />);
    fireEvent.click(screen.getByRole('tab', { name: '接入客户端' }));
    fireEvent.click(await screen.findByRole('button', { name: 'API Key' }));
    fireEvent.click(
      await screen.findByRole('button', { name: '创建 API Key' }),
    );
    fireEvent.change(screen.getByLabelText('密钥名称'), {
      target: { value: '运维 Agent' },
    });
    fireEvent.click(screen.getByRole('button', { name: '创建密钥' }));
    expect(await screen.findByLabelText('一次展示的 API Key')).toHaveValue(
      'sslm_one-time-test',
    );
    expect(mcpApi.createApiKey).toHaveBeenCalledWith(client.id, {
      name: '运维 Agent',
      expiresAtUtc: null,
    });
    expect(localStorage.setItem).not.toHaveBeenCalled();
    expect(
      screen.getByRole('button', { name: '复制完整接入指令（含本次密钥）' }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: '服务设置' }));
    await waitFor(() =>
      expect(
        screen.queryByLabelText('一次展示的 API Key'),
      ).not.toBeInTheDocument(),
    );
    expect(
      screen.queryByRole('button', { name: '复制完整接入指令（含本次密钥）' }),
    ).not.toBeInTheDocument();
  });

  it('API Key 明文在会话失效后立即卸载', async () => {
    vi.mocked(mcpApi.apiKeys).mockResolvedValue(ok([apiKey]));
    vi.mocked(mcpApi.rotateApiKey).mockResolvedValue(
      ok({ key: { ...apiKey, id: 'key-2' }, apiKey: 'sslm_rotated-test' }),
    );
    render(<McpManagement />);
    fireEvent.click(screen.getByRole('tab', { name: '接入客户端' }));
    fireEvent.click(await screen.findByRole('button', { name: 'API Key' }));
    fireEvent.click(await screen.findByRole('button', { name: '轮换密钥' }));
    fireEvent.click(
      await screen.findByRole('button', { name: '轮换 API Key' }),
    );
    expect(await screen.findByLabelText('一次展示的 API Key')).toHaveValue(
      'sslm_rotated-test',
    );
    expect(mcpApi.rotateApiKey).toHaveBeenCalledWith(
      apiKey.id,
      apiKey.configRevision,
    );
    await act(async () => window.dispatchEvent(new Event('ssl-auth-expired')));
    expect(
      screen.queryByLabelText('一次展示的 API Key'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: '复制完整接入指令（含本次密钥）' }),
    ).not.toBeInTheDocument();
  });

  it('密钥停用携带修订，已撤销密钥不能启用或轮换', async () => {
    vi.mocked(mcpApi.apiKeys).mockResolvedValue(
      ok([
        apiKey,
        {
          ...apiKey,
          id: 'revoked-key',
          name: '已撤销 Agent',
          revokedAtUtc: '2026-11-04T01:00:00Z',
          enabled: false,
        },
      ]),
    );
    vi.mocked(mcpApi.apiKeyStatus).mockResolvedValue(
      ok({ ...apiKey, enabled: false, configRevision: 4 }),
    );
    render(<ApiKeys client={client} onConfigureRules={vi.fn()} />);
    fireEvent.click(await screen.findByRole('button', { name: '停用密钥' }));
    await waitFor(() =>
      expect(mcpApi.apiKeyStatus).toHaveBeenCalledWith(apiKey.id, false, 3),
    );
    const row = screen.getByText('已撤销 Agent').closest('tr');
    if (!row) throw new Error('未找到已撤销密钥行');
    expect(
      within(row).getByRole('button', { name: '启用密钥' }),
    ).toBeDisabled();
    expect(
      within(row).getByRole('button', { name: '轮换密钥' }),
    ).toBeDisabled();
  });

  it('API Key 模板区分系统实例，只包含环境变量占位符', () => {
    const first = apiKeyConnectionTemplate(
      'https://production.example.com/mcp',
      '生产证书中心',
      'prod-1',
    );
    const second = apiKeyConnectionTemplate(
      'https://test.example.com/mcp',
      '测试证书中心',
      'test-1',
    );
    expect(Object.keys(first.mcpServers)).toEqual(['free-ssl-manager-prod-1']);
    expect(Object.keys(second.mcpServers)).toEqual(['free-ssl-manager-test-1']);
    expect(Object.keys(first)).toEqual(['mcpServers']);
    expect(apiKeyEnvironmentName('prod-1')).toBe('MCP_API_KEY_PROD_1');
    // biome-ignore lint/suspicious/noTemplateCurlyInString: 验证导出的是环境变量占位符。
    expect(JSON.stringify(first)).toContain('Bearer ${MCP_API_KEY_PROD_1}');
    // biome-ignore lint/suspicious/noTemplateCurlyInString: 不同实例不能共享同一个密钥变量。
    expect(JSON.stringify(second)).toContain('Bearer ${MCP_API_KEY_TEST_1}');
    expect(JSON.stringify(first)).not.toContain('sslm_');
  });

  it('OAuth 未就绪仍展示 API Key 就绪，并保存可识别的系统名称', async () => {
    vi.mocked(mcpApi.status).mockResolvedValue(
      ok({
        supported: true,
        enabled: false,
        apiKeyReady: true,
        oAuthReady: false,
        systemName: settings.systemName,
        instanceId: settings.instanceId,
        state: 'Disabled',
        message: '服务已关闭',
        mcpUrl: 'https://ssl.example.com/mcp',
        protocolVersions: [],
        sdkVersion: '2.3.0',
      }),
    );
    render(<Settings />);
    expect(
      await screen.findByText('可使用（无需 OAuth 证书）'),
    ).toBeInTheDocument();
    expect(screen.getByText('ssl-instance-1')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('系统名称'), {
      target: { value: '  测试证书中心  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: '保存 MCP 设置' }));
    await waitFor(() =>
      expect(mcpApi.saveSettings).toHaveBeenCalledWith(
        expect.objectContaining({ systemName: '测试证书中心' }),
      ),
    );
  });

  it('快捷创建 API Key 客户端预选机器身份且无需回调地址', async () => {
    render(<Clients onConfigureRules={vi.fn()} />);
    fireEvent.click(
      screen.getByRole('button', { name: '新增 API Key 客户端' }),
    );
    expect(
      await screen.findByText('先创建受限机器客户端，保存后继续创建 API Key。'),
    ).toBeInTheDocument();
    expect(screen.getByLabelText('回调地址')).toBeDisabled();
    expect(screen.getByText('机器 client_credentials')).toBeInTheDocument();
  });

  it('审计上下文展示调用时实例、客户端自报和截断入参，缺失快照不补录', () => {
    render(
      <AuditContext
        contextJson={JSON.stringify({
          systemName: '旧生产名称',
          instanceId: 'prod-1',
          clientName: '第三方 Agent',
          clientVersion: '1.0',
          transportScheme: 'http',
          input: { domain: 'example.com' },
          inputCaptured: true,
          outputCaptured: false,
          inputTruncated: true,
        })}
      />,
    );
    expect(screen.getByText('旧生产名称')).toBeInTheDocument();
    expect(screen.getByText('prod-1')).toBeInTheDocument();
    expect(screen.getByText('HTTP')).toBeInTheDocument();
    expect(screen.getByText('第三方 Agent / 1.0')).toBeInTheDocument();
    expect(screen.getByText('已截断')).toBeInTheDocument();
    expect(
      screen.getByText('本次调用未采集出参，历史日志不会补录。'),
    ).toBeInTheDocument();
    expect(parseMcpContext('invalid')).toBeUndefined();
    expect(parseMcpContext('[]')).toBeUndefined();
  });

  it('审计列表显示 Key 身份并在详情展示协议、业务结果和受控快照', async () => {
    const record = {
      id: 'log-1',
      traceId: 'trace-1',
      clientId: 'oauth-client',
      userId: 'viewer-user',
      method: 'tools/call',
      toolName: 'ssl_certificates_list',
      authenticationType: 'ApiKey',
      apiKeyId: 'key-1',
      apiKeyName: '运维 Agent',
      apiKeyPrefix: 'sslm_test',
      status: 'Succeeded',
      httpStatus: 200,
      code: 'OK',
      startedAtUtc: '2026-11-04T00:00:00Z',
      durationMilliseconds: 12,
      contextJson: JSON.stringify({
        systemName: '生产证书中心',
        instanceId: 'prod-1',
        input: { page: 1 },
        output: { success: true },
        inputCaptured: true,
        outputCaptured: true,
      }),
    } as McpCallLog;
    vi.mocked(mcpApi.callLogs).mockResolvedValue(ok(page([record])));
    vi.mocked(mcpApi.callLog).mockResolvedValue(ok(record));
    render(<CallLogs />);
    expect(await screen.findByText('API Key · 运维 Agent')).toBeInTheDocument();
    expect(
      screen.getByRole('region', { name: 'MCP 调用统计' }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '详情' }));
    expect(await screen.findByText('生产证书中心')).toBeInTheDocument();
    expect(
      screen.getByText('API Key / 运维 Agent · sslm_test… · key-1'),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('region', { name: 'MCP 入参快照' }),
    ).toBeInTheDocument();
    expect(mcpApi.callStatistics).toHaveBeenCalledWith(
      expect.objectContaining({
        fromUtc: expect.any(String),
        toUtc: expect.any(String),
      }),
    );
  });

  it('拒绝聚合行展示实际请求次数，统计不误用分页记录行数', async () => {
    vi.mocked(mcpApi.callLogs).mockResolvedValue(
      ok(
        page([
          {
            id: 'denied-1',
            traceId: '',
            clientId: '',
            status: 'Denied',
            code: 'UNAUTHORIZED',
            method: '',
            toolName: '',
            sourceIp: '',
            httpStatus: 401,
            occurrenceCount: 20,
            durationMilliseconds: 0,
            startedAtUtc: '2026-11-04T00:00:00Z',
          } as McpCallLog,
        ]),
      ),
    );
    vi.mocked(mcpApi.callStatistics).mockResolvedValue(
      ok({
        fromUtc: '2026-11-01T00:00:00Z',
        toUtc: '2026-11-04T00:00:00Z',
        totalRequests: 20,
        toolCalls: 0,
        succeeded: 0,
        failed: 0,
        denied: 20,
        unknown: 0,
        averageDurationMilliseconds: null,
        trend: [],
      }),
    );
    render(<CallLogs />);
    await screen.findByText('UNAUTHORIZED / 401');
    expect(screen.getAllByText('20')).toHaveLength(3);
    expect(screen.getByText(/统计按实际请求次数汇总/)).toBeInTheDocument();
  });
});
