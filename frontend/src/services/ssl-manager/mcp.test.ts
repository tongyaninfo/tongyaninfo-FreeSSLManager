import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetCsrfToken } from './api';
import { mcpApi } from './mcp';

const response = (data: unknown) => ({ status: 200, json: async () => data });
describe('MCP 管理API会话与修订契约', () => {
  const mockFetch = vi.fn();
  beforeEach(() => { resetCsrfToken(); mockFetch.mockReset(); vi.stubGlobal('fetch', mockFetch); });
  afterEach(() => vi.unstubAllGlobals());
  it('白名单整组更新带修订和CSRF，空规则不补成允许全部', async () => {
    mockFetch.mockResolvedValueOnce(response({ success: true, code: 'OK', message: '', data: { token: 'csrf-test' } })).mockResolvedValueOnce(response({ success: true, code: 'OK', message: '', data: { rules: [], configRevision: 8 } }));
    await mcpApi.saveRules('client/id', { rules: [], configRevision: 7 });
    expect(mockFetch).toHaveBeenLastCalledWith('/api/mcp/clients/client%2Fid/allow-rules', expect.objectContaining({ method: 'PUT', credentials: 'same-origin', cache: 'no-store', headers: expect.objectContaining({ 'X-CSRF-TOKEN': 'csrf-test' }), body: JSON.stringify({ rules: [], configRevision: 7 }) }));
  });
  it('审批只传操作版本，不允许前端替换实际调用用户或自行提交confirmed标志', async () => {
    mockFetch.mockResolvedValueOnce(response({ success: true, code: 'OK', message: '', data: { token: 'csrf-test' } })).mockResolvedValueOnce(response({ success: false, code: 'CONFLICT', message: '审批已失效' }));
    const result = await mcpApi.approve('operation/id', 4, '');
    expect(result.code).toBe('CONFLICT');
    expect(mockFetch).toHaveBeenCalledTimes(2);
    const [url, options] = mockFetch.mock.calls[1];
    expect(url).toBe('/api/mcp/operations/operation%2Fid/approve');
    expect(JSON.parse(options.body)).toEqual({ version: 4, note: '' });
  });
  it('轮换秘密走POST，结果只读当前响应，不放URL或浏览器存储', async () => {
    mockFetch.mockResolvedValueOnce(response({ success: true, code: 'OK', message: '', data: { token: 'csrf-test' } })).mockResolvedValueOnce(response({ success: true, code: 'OK', message: '', data: { clientId: 'client-1', clientSecret: 'one-time-secret' } }));
    const result = await mcpApi.rotateSecret('local-1');
    expect(result.data?.clientSecret).toBe('one-time-secret');
    expect(mockFetch).toHaveBeenLastCalledWith('/api/mcp/clients/local-1/rotate-secret', expect.objectContaining({ method: 'POST', body: undefined, cache: 'no-store' }));
  });
  it('API Key 创建复用会话与CSRF，明文不进入请求URL或持久存储', async () => {
    mockFetch.mockResolvedValueOnce(response({ success: true, code: 'OK', message: '', data: { token: 'csrf-test' } })).mockResolvedValueOnce(response({ success: true, code: 'OK', message: '', data: { key: { id: 'key-1' }, apiKey: 'sslm_once' } }));
    const result = await mcpApi.createApiKey('client/id', { name: 'Internal Agent', expiresAtUtc: null });
    expect(result.data?.apiKey).toBe('sslm_once');
    expect(mockFetch).toHaveBeenLastCalledWith('/api/mcp/clients/client%2Fid/api-keys', expect.objectContaining({ method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: expect.objectContaining({ 'X-CSRF-TOKEN': 'csrf-test' }), body: JSON.stringify({ name: 'Internal Agent', expiresAtUtc: null }) }));
  });
  it('Key 状态、轮换、撤销携带配置版本，冲突不自动重试', async () => {
    mockFetch.mockResolvedValueOnce(response({ success: true, code: 'OK', message: '', data: { token: 'csrf-test' } })).mockResolvedValue(response({ success: false, code: 'CONFLICT', message: '配置已变化' }));
    await mcpApi.apiKeyStatus('key/id', false, 7);
    expect(mockFetch).toHaveBeenLastCalledWith('/api/mcp/api-keys/key%2Fid/status', expect.objectContaining({ body: JSON.stringify({ enabled: false, configRevision: 7 }) }));
    await mcpApi.rotateApiKey('key/id', 8);
    expect(mockFetch).toHaveBeenLastCalledWith('/api/mcp/api-keys/key%2Fid/rotate', expect.objectContaining({ body: JSON.stringify({ configRevision: 8 }) }));
    await mcpApi.revokeApiKey('key/id', 9);
    expect(mockFetch).toHaveBeenLastCalledWith('/api/mcp/api-keys/key%2Fid/revoke', expect.objectContaining({ body: JSON.stringify({ configRevision: 9 }) }));
    expect(mockFetch).toHaveBeenCalledTimes(4);
  });
  it('调用统计仅发送公开的时间范围，不携带凭据', async () => {
    mockFetch.mockResolvedValue(response({ success: true, code: 'OK', message: '', data: {} }));
    await mcpApi.callStatistics({ fromUtc: '2026-11-01T00:00:00Z', toUtc: '2026-11-04T00:00:00Z' });
    expect(mockFetch).toHaveBeenCalledWith('/api/mcp/call-logs/statistics?fromUtc=2026-11-01T00%3A00%3A00Z&toUtc=2026-11-04T00%3A00%3A00Z', expect.objectContaining({ method: 'GET', cache: 'no-store' }));
  });
});
