import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { accountApi, api, resetCsrfToken } from './api';

const response = (data: unknown, status = 200) => ({ status, json: async () => data });
describe('真实 API 业务返回与防伪令牌', () => {
  const mockFetch = vi.fn();
  beforeEach(() => { resetCsrfToken(); mockFetch.mockReset(); vi.stubGlobal('fetch', mockFetch); });
  afterEach(() => vi.unstubAllGlobals());
  it('预期业务失败原样返回，不抛异常也不重试申请', async () => { mockFetch.mockResolvedValueOnce(response({ success: true, code: 'OK', message: '', data: { token: 'test-csrf' } })).mockResolvedValueOnce(response({ success: false, code: 'NO_QUOTA', message: '免费额度不足' })); const result = await api('/certificates/apply', 'POST', { domain: 'example.com' }); expect(result).toEqual({ success: false, code: 'NO_QUOTA', message: '免费额度不足' }); expect(mockFetch).toHaveBeenCalledTimes(2); expect(mockFetch.mock.calls[1][1].headers['X-CSRF-TOKEN']).toBe('test-csrf'); });
  it('获取令牌失败时不执行云资源写请求', async () => { mockFetch.mockResolvedValueOnce(response({ success: false, code: 'CSRF_UNAVAILABLE', message: '请刷新' })); const result = await api('/domains/1/records', 'POST', {}); expect(result.success).toBe(false); expect(mockFetch).toHaveBeenCalledTimes(1); });
  it('密钥仅按单账号读取，禁止 HTTP 缓存', async () => { mockFetch.mockResolvedValueOnce(response({ success: true, code: 'OK', message: '', data: { accessKeyId: 'test-id', accessKeySecret: 'test-secret' } })); await accountApi.secrets('account-1'); expect(mockFetch).toHaveBeenCalledWith('/api/cloud-accounts/account-1/secrets', expect.objectContaining({ cache: 'no-store', credentials: 'same-origin' })); expect(mockFetch).toHaveBeenCalledTimes(1); });
  it('云账号列表保留后台自动同步时间，页面不应误用连接检测时间', async () => {
    const lastAutoSyncAtUtc = '2026-10-16T03:04:05Z';
    mockFetch.mockResolvedValueOnce(response({
      success: true,
      code: 'OK',
      message: '',
      data: {
        items: [{ id: 'account-1', lastAutoSyncAtUtc, lastTestAtUtc: null }],
        total: 1,
        page: 1,
        pageSize: 20,
      },
    }));
    const result = await accountApi.list({ page: 1, pageSize: 20 });
    expect(result.data?.items[0].lastAutoSyncAtUtc).toBe(lastAutoSyncAtUtc);
    expect(result.data?.items[0].lastTestAtUtc).toBeNull();
  });
  it('协议不匹配返回系统失败而不是假成功', async () => { mockFetch.mockResolvedValueOnce(response({ items: [] })); expect((await api('/domains')).code).toBe('INVALID_RESPONSE'); });
  it('非 JSON 的 401 也立即通知页面清除待导入的明文配置', async () => {
    const expired = vi.fn();
    window.addEventListener('ssl-auth-expired', expired);
    try {
      mockFetch.mockResolvedValueOnce({ status: 401, json: async () => { throw new SyntaxError('invalid-json'); } });
      expect((await api('/configuration-transfer/export')).code).toBe('NETWORK_ERROR');
      expect(expired).toHaveBeenCalledTimes(1);
    } finally {
      window.removeEventListener('ssl-auth-expired', expired);
    }
  });
  it('登录失败的 401 不广播全局会话失效', async () => {
    const expired = vi.fn();
    window.addEventListener('ssl-auth-expired', expired);
    try {
      mockFetch.mockResolvedValueOnce(response({ success: false, code: 'UNAUTHORIZED', message: '登录失败' }, 401));
      expect((await api('/auth/current-user')).success).toBe(false);
      expect(expired).not.toHaveBeenCalled();
    } finally {
      window.removeEventListener('ssl-auth-expired', expired);
    }
  });
});
