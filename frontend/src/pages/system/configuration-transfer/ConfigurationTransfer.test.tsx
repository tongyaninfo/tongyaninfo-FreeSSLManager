import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { configurationTransferApi } from '@/services/ssl-manager/configurationTransfer';
import type {
  ConfigurationPackage,
  ConfigurationPreview,
} from '@/services/ssl-manager/configurationTransferTypes';
import type { ApiResult } from '@/services/ssl-manager/types';
import ConfigurationTransfer from './index';

const permission = vi.hoisted(() => ({ admin: true }));
vi.mock('@umijs/max', () => ({
  useAccess: () => ({ canAdmin: permission.admin }),
}));
vi.mock('@ant-design/pro-components', () => ({
  PageContainer: ({
    title,
    children,
  }: {
    title: string;
    children: React.ReactNode;
  }) => (
    <main>
      <h1>{title}</h1>
      {children}
    </main>
  ),
}));
vi.mock('@/services/ssl-manager/configurationTransfer', () => ({
  configurationTransferApi: {
    export: vi.fn(),
    preview: vi.fn(),
    import: vi.fn(),
  },
}));

// 仅使用虚构凭据，验证页面不把文件中的明文内容渲染到 DOM。
const packageData: ConfigurationPackage = {
  format: 'free-ssl-manager.configuration',
  version: 1,
  exportedAtUtc: '2026-11-02T08:00:00Z',
  cloudAccounts: [
    {
      sourceId: 'source-account',
      settings: { name: '测试云账号', accessKeySecret: 'fake-transfer-secret' },
    },
  ],
  deploymentTargets: [],
  certificateSchedules: [],
  mailSettings: null,
};
const previewData: ConfigurationPreview = {
  mode: 'CreateOnly',
  previewToken: 'test-preview-token',
  canImport: true,
  created: 1,
  updated: 0,
  conflicts: 0,
  items: [
    {
      kind: 'CloudAccount',
      sourceId: 'source-account',
      name: '测试云账号',
      action: 'Create',
    },
  ],
  errors: [],
};
const ok = <T,>(data: T): ApiResult<T> => ({
  success: true,
  code: 'OK',
  message: '',
  data,
});

function fileWithText(
  text: string,
  name = 'configuration.json',
  size?: number,
) {
  const file = new File([text], name, { type: 'application/json' });
  Object.defineProperty(file, 'text', {
    value: vi.fn().mockResolvedValue(text),
  });
  if (size !== undefined) Object.defineProperty(file, 'size', { value: size });
  return file;
}
async function chooseFile(
  container: HTMLElement,
  file = fileWithText(JSON.stringify(packageData)),
) {
  const input = container.querySelector<HTMLInputElement>('input[type="file"]');
  if (!input) throw new Error('File input missing');
  fireEvent.change(input, { target: { files: [file] } });
  await screen.findByText(`已选择：${file.name}`);
}
async function showPreview(container: HTMLElement) {
  await chooseFile(container);
  fireEvent.click(screen.getByRole('button', { name: /预览导入/ }));
  await screen.findByText('测试云账号');
  await waitFor(() =>
    expect(screen.getByRole('button', { name: /预览导入/ })).not.toHaveClass(
      'ant-btn-loading',
    ),
  );
}

describe('配置导入导出', () => {
  beforeEach(() => {
    permission.admin = true;
    vi.resetAllMocks();
    vi.mocked(configurationTransferApi.export).mockResolvedValue(
      ok(packageData),
    );
    vi.mocked(configurationTransferApi.preview).mockResolvedValue(
      ok(previewData),
    );
    vi.mocked(configurationTransferApi.import).mockResolvedValue(
      ok({ created: 1, updated: 0, importedAtUtc: '2026-11-02T08:01:00Z' }),
    );
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:configuration-test');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(
      () => undefined,
    );
  });
  afterEach(() => vi.restoreAllMocks());

  it('非管理员没有导入导出入口且不请求配置', () => {
    permission.admin = false;
    render(<ConfigurationTransfer />);
    expect(screen.getByText('无配置导入导出权限')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: '导出 JSON 配置' }),
    ).not.toBeInTheDocument();
    expect(configurationTransferApi.export).not.toHaveBeenCalled();
    expect(configurationTransferApi.preview).not.toHaveBeenCalled();
  });

  it('导出必须确认，取消不请求；确认后下载一次且不显示明文', async () => {
    render(<ConfigurationTransfer />);
    fireEvent.click(screen.getByRole('button', { name: '导出 JSON 配置' }));
    expect(configurationTransferApi.export).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: /^取\s*消$/ }));
    expect(configurationTransferApi.export).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: '导出 JSON 配置' }));
    fireEvent.click(screen.getByRole('button', { name: '确认导出并下载' }));
    await screen.findByText('配置文件已下载，文件包含明文凭据，请妥善保存。');
    expect(configurationTransferApi.export).toHaveBeenCalledOnce();
    expect(HTMLAnchorElement.prototype.click).toHaveBeenCalledOnce();
    expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:configuration-test');
    expect(screen.queryByText(/fake-transfer-secret/)).not.toBeInTheDocument();
  });

  it.each([
    [
      '错误MCP客户端结构',
      JSON.stringify({ ...packageData, mcpClients: {} }),
      'configuration.json',
      undefined,
      '配置文件格式或版本不受支持',
    ],
    [
      '错误MCP设置结构',
      JSON.stringify({ ...packageData, mcpSettings: [] }),
      'configuration.json',
      undefined,
      '配置文件格式或版本不受支持',
    ],
    [
      '无效JSON',
      'broken json',
      'configuration.json',
      undefined,
      '无法读取有效的 JSON 配置文件。',
    ],
    [
      '错误版本',
      JSON.stringify({ ...packageData, version: 2 }),
      'configuration.json',
      undefined,
      '配置文件格式或版本不受支持',
    ],
    [
      '超限',
      '{}',
      'configuration.json',
      5 * 1024 * 1024 + 1,
      '配置文件不能为空',
    ],
    [
      '错误扩展名',
      '{}',
      'configuration.txt',
      undefined,
      '请选择 JSON 配置文件。',
    ],
    [
      '过深嵌套',
      `${JSON.stringify(packageData).slice(0, -1)},"deep":${'['.repeat(70)}0${']'.repeat(70)}}`,
      'configuration.json',
      undefined,
      'JSON 嵌套层级过深',
    ],
  ])('%s 文件不会发送预览或导入请求', async (_name, text, name, size, message) => {
    const { container } = render(<ConfigurationTransfer />);
    const input =
      container.querySelector<HTMLInputElement>('input[type="file"]');
    if (!input) throw new Error('File input missing');
    fireEvent.change(input, {
      target: { files: [fileWithText(text, name, size)] },
    });
    await screen.findByText(new RegExp(message));
    expect(configurationTransferApi.preview).not.toHaveBeenCalled();
    expect(configurationTransferApi.import).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: /预览导入/ })).toBeDisabled();
  });

  it('冲突阻止导入，切换方式使旧预览失效并按新方式重新预览', async () => {
    vi.mocked(configurationTransferApi.preview)
      .mockResolvedValueOnce(
        ok({
          ...previewData,
          canImport: false,
          conflicts: 1,
          items: [{ ...previewData.items[0], action: 'Conflict' }],
        }),
      )
      .mockResolvedValueOnce(
        ok({ ...previewData, mode: 'UpdateByName', created: 0, updated: 1 }),
      );
    const { container } = render(<ConfigurationTransfer />);
    await showPreview(container);
    expect(screen.getByRole('button', { name: '确认导入配置' })).toBeDisabled();
    fireEvent.click(screen.getByRole('radio', { name: '按名称更新已有配置' }));
    expect(
      screen.queryByRole('button', { name: '确认导入配置' }),
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /预览导入/ }));
    await screen.findByText('预览：新增 0 项，更新 1 项，冲突 0 项。');
    expect(configurationTransferApi.preview).toHaveBeenLastCalledWith(
      expect.objectContaining({ mode: 'UpdateByName' }),
    );
    expect(configurationTransferApi.import).not.toHaveBeenCalled();
    expect(screen.queryByText(/fake-transfer-secret/)).not.toBeInTheDocument();
  });

  it('兼容MCP可移植配置，预览区分服务及客户端规则并提示本地重绑', async () => {
    const portable: ConfigurationPackage = {
      ...packageData,
      mcpSettings: {
        enabled: false,
        publicBaseUrl: '',
        mode: 'ReadOnly',
        allowedCidrs: [],
        allowedOrigins: [],
        allowedTools: [],
        rateLimitPerMinute: 60,
        maxConcurrentCalls: 4,
        logRetentionDays: 90,
      },
      mcpClients: [
        {
          sourceId: 'mcp-client-1',
          settings: {
            name: '测试迁移客户端',
            clientType: 'confidential',
            grantType: 'client_credentials',
            scopes: ['mcp.read'],
            redirectUris: [],
          },
          allowRules: [
            {
              toolNames: ['ssl_certificates_list'],
              accountIds: ['source-account'],
              domains: ['harbor.example.com'],
              targetIds: [],
              allowedCidrs: ['192.0.2.1/32'],
              scopes: ['mcp.read'],
              allAccounts: false,
              allDomains: false,
              allTargets: false,
              approvalMode: 'Manual',
              enabled: false,
            },
          ],
        },
      ],
    };
    vi.mocked(configurationTransferApi.preview).mockResolvedValue(
      ok({
        ...previewData,
        created: 3,
        items: [
          ...previewData.items,
          {
            kind: 'McpSettings',
            sourceId: 'mcp-settings',
            name: 'MCP 公开设置',
            action: 'Create',
          },
          {
            kind: 'McpClient',
            sourceId: 'mcp-client-1',
            name: '测试迁移客户端',
            action: 'Create',
          },
        ],
      }),
    );
    const { container } = render(<ConfigurationTransfer />);
    await chooseFile(container, fileWithText(JSON.stringify(portable)));
    fireEvent.click(screen.getByRole('button', { name: /预览导入/ }));
    await screen.findByText('MCP 客户端及调用规则');
    expect(screen.getByText('MCP 服务设置')).toBeInTheDocument();
    expect(screen.getByText('测试迁移客户端')).toBeInTheDocument();
    expect(
      screen.getByText(/不迁移 OAuth 客户端秘密、令牌、有效授权或调用历史/),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '确认导入配置' }));
    await screen.findByText(
      /MCP 客户端需在目标实例重新绑定用户，机密客户端需轮换新秘密/,
    );
    fireEvent.click(screen.getByRole('button', { name: '执行导入' }));
    await waitFor(() =>
      expect(configurationTransferApi.import).toHaveBeenCalledOnce(),
    );
    const submitted = vi.mocked(configurationTransferApi.import).mock
      .calls[0][0].package as ConfigurationPackage;
    expect(submitted.mcpClients?.[0].allowRules[0].accountIds).toEqual([
      'source-account',
    ]);
    expect(submitted.mcpClients?.[0].settings).not.toHaveProperty(
      'boundUserId',
    );
    expect(submitted.mcpClients?.[0].settings).not.toHaveProperty(
      'clientSecret',
    );
    expect(screen.queryByText(/fake-transfer-secret/)).not.toBeInTheDocument();
  });

  it('选择新文件后清除旧预览，不允许使用旧令牌提交', async () => {
    const { container } = render(<ConfigurationTransfer />);
    await showPreview(container);
    await chooseFile(
      container,
      fileWithText(JSON.stringify(packageData), 'another.json'),
    );
    expect(
      screen.queryByRole('button', { name: '确认导入配置' }),
    ).not.toBeInTheDocument();
    expect(configurationTransferApi.import).not.toHaveBeenCalled();
  });

  it('导入提交与预览相同的对象和令牌，重复点击只提交一次', async () => {
    let resolveImport!: (
      value: ApiResult<{
        created: number;
        updated: number;
        importedAtUtc: string;
      }>,
    ) => void;
    vi.mocked(configurationTransferApi.import).mockReturnValue(
      new Promise((resolve) => {
        resolveImport = resolve;
      }),
    );
    const { container } = render(<ConfigurationTransfer />);
    await showPreview(container);
    const selectedPackage = vi.mocked(configurationTransferApi.preview).mock
      .calls[0][0].package;
    fireEvent.click(screen.getByRole('button', { name: '确认导入配置' }));
    expect(configurationTransferApi.import).not.toHaveBeenCalled();
    const confirm = screen.getByRole('button', { name: '执行导入' });
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    expect(configurationTransferApi.import).toHaveBeenCalledOnce();
    expect(configurationTransferApi.import).toHaveBeenCalledWith({
      package: selectedPackage,
      mode: 'CreateOnly',
      previewToken: 'test-preview-token',
    });
    expect(
      vi.mocked(configurationTransferApi.import).mock.calls[0][0].package,
    ).toBe(selectedPackage);
    await act(async () =>
      resolveImport(
        ok({ created: 1, updated: 0, importedAtUtc: '2026-11-02T08:01:00Z' }),
      ),
    );
    await screen.findByText(/配置导入完成：新增 1 项/);
    expect(screen.getByText('尚未选择配置文件')).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: '确认导入配置' }),
    ).not.toBeInTheDocument();
  });

  it('预览失败不允许导入，网络结果不明后禁用再次提交', async () => {
    vi.mocked(configurationTransferApi.preview)
      .mockResolvedValueOnce({
        success: false,
        code: 'VALIDATION',
        message: '配置校验失败',
      })
      .mockResolvedValueOnce(ok(previewData));
    vi.mocked(configurationTransferApi.import).mockResolvedValue({
      success: false,
      code: 'NETWORK_ERROR',
      message: '连接中断',
    });
    const { container } = render(<ConfigurationTransfer />);
    await chooseFile(container);
    fireEvent.click(screen.getByRole('button', { name: /预览导入/ }));
    await screen.findByText('配置校验失败');
    expect(configurationTransferApi.import).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /预览导入/ })).not.toHaveClass(
        'ant-btn-loading',
      ),
    );
    fireEvent.click(screen.getByRole('button', { name: /预览导入/ }));
    await screen.findByText('测试云账号');
    fireEvent.click(screen.getByRole('button', { name: '确认导入配置' }));
    fireEvent.click(screen.getByRole('button', { name: '执行导入' }));
    await screen.findByText('导入结果待核验');
    expect(screen.getByRole('button', { name: /预览导入/ })).toBeDisabled();
    expect(
      screen.getByRole('button', { name: '选择 JSON 文件' }),
    ).toBeDisabled();
    expect(configurationTransferApi.import).toHaveBeenCalledOnce();
  });

  it('会话失效时关闭确认并清除文件、预览和待导入明文', async () => {
    const { container } = render(<ConfigurationTransfer />);
    await showPreview(container);
    fireEvent.click(screen.getByRole('button', { name: '确认导入配置' }));
    act(() => window.dispatchEvent(new Event('ssl-auth-expired')));
    expect(
      screen.getByText('登录已失效，已清除待导入配置，请重新登录。'),
    ).toBeInTheDocument();
    expect(screen.queryByText('测试云账号')).not.toBeInTheDocument();
    expect(screen.queryByText(/configuration.json/)).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: '执行导入' }),
    ).not.toBeInTheDocument();
    expect(configurationTransferApi.import).not.toHaveBeenCalled();
  });

  it('服务端拒绝导出时展示失败且不创建下载文件', async () => {
    vi.mocked(configurationTransferApi.export).mockResolvedValue({
      success: false,
      code: 'CONFIGURATION_UNAVAILABLE',
      message: '当前权限不足',
    });
    render(<ConfigurationTransfer />);
    fireEvent.click(screen.getByRole('button', { name: '导出 JSON 配置' }));
    fireEvent.click(screen.getByRole('button', { name: '确认导出并下载' }));
    await screen.findByText('当前权限不足');
    expect(URL.createObjectURL).not.toHaveBeenCalled();
    expect(HTMLAnchorElement.prototype.click).not.toHaveBeenCalled();
  });

  it('会话失效后迟到的导出响应不会继续下载明文文件', async () => {
    let resolveExport!: (value: ApiResult<ConfigurationPackage>) => void;
    vi.mocked(configurationTransferApi.export).mockReturnValue(
      new Promise((resolve) => {
        resolveExport = resolve;
      }),
    );
    render(<ConfigurationTransfer />);
    fireEvent.click(screen.getByRole('button', { name: '导出 JSON 配置' }));
    fireEvent.click(screen.getByRole('button', { name: '确认导出并下载' }));
    act(() => window.dispatchEvent(new Event('ssl-auth-expired')));
    await act(async () => resolveExport(ok(packageData)));
    expect(
      screen.getByText('登录已失效，已清除待导入配置，请重新登录。'),
    ).toBeInTheDocument();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
    expect(HTMLAnchorElement.prototype.click).not.toHaveBeenCalled();
  });

  it('凭据字符串中的引号、转义和括号不误判为嵌套结构', async () => {
    const withBraces = {
      ...packageData,
      cloudAccounts: [
        {
          sourceId: 'account',
          settings: { accessKeySecret: `${'{['.repeat(100)}"\\` },
        },
      ],
    };
    const { container } = render(<ConfigurationTransfer />);
    await chooseFile(container, fileWithText(JSON.stringify(withBraces)));
    fireEvent.click(screen.getByRole('button', { name: /预览导入/ }));
    await screen.findByText('测试云账号');
    expect(configurationTransferApi.preview).toHaveBeenCalledOnce();
    expect(screen.queryByText(/JSON 嵌套层级过深/)).not.toBeInTheDocument();
  });

  it('接近大小上限的配置使用紧凑 JSON 导出，下载后仍符合导入限额', async () => {
    const limit = 5 * 1024 * 1024;
    const nearLimit: ConfigurationPackage = {
      ...packageData,
      cloudAccounts: Array.from({ length: 1000 }, (_, index) => ({
        sourceId: `account-${index}`,
        settings: { name: `account-${index}`, accessKeySecret: '' },
      })),
    };
    const padding = Math.floor(
      (limit - 100 - JSON.stringify(nearLimit).length) / 1000,
    );
    for (const item of nearLimit.cloudAccounts)
      item.settings.accessKeySecret = 'x'.repeat(padding);
    expect(new Blob([JSON.stringify(nearLimit, null, 2)]).size).toBeGreaterThan(
      limit,
    );
    vi.mocked(configurationTransferApi.export).mockResolvedValue(ok(nearLimit));
    render(<ConfigurationTransfer />);
    fireEvent.click(screen.getByRole('button', { name: '导出 JSON 配置' }));
    fireEvent.click(screen.getByRole('button', { name: '确认导出并下载' }));
    await screen.findByText('配置文件已下载，文件包含明文凭据，请妥善保存。');
    const downloaded = vi.mocked(URL.createObjectURL).mock.calls[0][0];
    expect(downloaded).toBeInstanceOf(Blob);
    expect((downloaded as Blob).size).toBeLessThanOrEqual(limit);
  });

  it('恶意文件名、配置名称及校验路径只作为文本显示，不执行 HTML', async () => {
    const malicious = '<img src=x onerror=alert(1)>';
    vi.mocked(configurationTransferApi.preview).mockResolvedValue(
      ok({
        ...previewData,
        canImport: false,
        items: [{ ...previewData.items[0], name: malicious }],
        errors: [{ path: malicious, message: '字段无效' }],
      }),
    );
    const { container } = render(<ConfigurationTransfer />);
    await chooseFile(
      container,
      fileWithText(JSON.stringify(packageData), `${malicious}.json`),
    );
    fireEvent.click(screen.getByRole('button', { name: /预览导入/ }));
    await screen.findByText(malicious);
    expect(screen.getByText(`${malicious}：字段无效`)).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).toBeNull();
    expect(document.querySelector('[onerror]')).toBeNull();
    expect(screen.queryByText(/fake-transfer-secret/)).not.toBeInTheDocument();
  });

  it('预览请求期间禁止切换文件和模式，会话失效后的迟到预览不再显示', async () => {
    let resolvePreview!: (value: ApiResult<ConfigurationPreview>) => void;
    vi.mocked(configurationTransferApi.preview).mockReturnValue(
      new Promise((resolve) => {
        resolvePreview = resolve;
      }),
    );
    const { container } = render(<ConfigurationTransfer />);
    await chooseFile(container);
    fireEvent.click(screen.getByRole('button', { name: /预览导入/ }));
    expect(
      screen.getByRole('button', { name: '选择 JSON 文件' }),
    ).toBeDisabled();
    expect(
      screen.getByRole('radio', { name: '按名称更新已有配置' }),
    ).toBeDisabled();
    act(() => window.dispatchEvent(new Event('ssl-auth-expired')));
    await act(async () => resolvePreview(ok(previewData)));
    expect(
      screen.getByText('登录已失效，已清除待导入配置，请重新登录。'),
    ).toBeInTheDocument();
    expect(screen.queryByText('测试云账号')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: '确认导入配置' }),
    ).not.toBeInTheDocument();
  });

  it('管理员权限撤销后迟到的导出响应不会下载文件', async () => {
    let resolveExport!: (value: ApiResult<ConfigurationPackage>) => void;
    vi.mocked(configurationTransferApi.export).mockReturnValue(
      new Promise((resolve) => {
        resolveExport = resolve;
      }),
    );
    const { rerender } = render(<ConfigurationTransfer />);
    fireEvent.click(screen.getByRole('button', { name: '导出 JSON 配置' }));
    fireEvent.click(screen.getByRole('button', { name: '确认导出并下载' }));
    permission.admin = false;
    rerender(<ConfigurationTransfer />);
    await act(async () => resolveExport(ok(packageData)));
    expect(screen.getByText('无配置导入导出权限')).toBeInTheDocument();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });

  it.each([
    'export',
    'preview',
    'import',
  ] as const)('%s 返回403降权结果时清理明文和确认弹窗', async (operation) => {
    const forbidden = {
      success: false,
      code: 'FORBIDDEN',
      message: '当前用户无配置管理权限',
    };
    vi.mocked(configurationTransferApi[operation]).mockResolvedValue(forbidden);
    const { container } = render(<ConfigurationTransfer />);
    if (operation === 'export') {
      fireEvent.click(screen.getByRole('button', { name: '导出 JSON 配置' }));
      fireEvent.click(screen.getByRole('button', { name: '确认导出并下载' }));
    } else if (operation === 'preview') {
      await chooseFile(container);
      fireEvent.click(screen.getByRole('button', { name: /预览导入/ }));
    } else {
      await showPreview(container);
      fireEvent.click(screen.getByRole('button', { name: '确认导入配置' }));
      fireEvent.click(screen.getByRole('button', { name: '执行导入' }));
    }
    await screen.findByText('当前账号已无配置导入导出权限，已清除待导入配置。');
    expect(screen.queryByText('测试云账号')).not.toBeInTheDocument();
    expect(screen.queryByText(/configuration.json/)).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: '执行导入' }),
    ).not.toBeInTheDocument();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });

  it('未广播会话事件的UNAUTHORIZED结果仍清理待导入配置', async () => {
    vi.mocked(configurationTransferApi.preview).mockResolvedValue({
      success: false,
      code: 'UNAUTHORIZED',
      message: '请先登录',
    });
    const { container } = render(<ConfigurationTransfer />);
    await chooseFile(container);
    fireEvent.click(screen.getByRole('button', { name: /预览导入/ }));
    await screen.findByText('登录已失效，已清除待导入配置，请重新登录。');
    expect(screen.queryByText(/configuration.json/)).not.toBeInTheDocument();
    expect(configurationTransferApi.import).not.toHaveBeenCalled();
  });

  it('导入成功响应缺少结果时视为结果待核验，不能再次提交', async () => {
    vi.mocked(configurationTransferApi.import).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
    });
    const { container } = render(<ConfigurationTransfer />);
    await showPreview(container);
    fireEvent.click(screen.getByRole('button', { name: '确认导入配置' }));
    fireEvent.click(screen.getByRole('button', { name: '执行导入' }));
    await screen.findByText('导入结果待核验');
    expect(screen.getByRole('button', { name: /预览导入/ })).toBeDisabled();
    expect(configurationTransferApi.import).toHaveBeenCalledOnce();
  });
});
