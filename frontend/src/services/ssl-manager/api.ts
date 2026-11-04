import type { AcmeRegistrationView, AliyunCertificateInstanceOption, AliyunContact, ApiResult, ApplyCertificate, AuditLog, Certificate, CertificateDetail, CloudAccount, DnsRecord, DnsZone, ManagedUser, PageResult, User } from './types';

let csrfToken: string | undefined;
let csrfRequest: Promise<ApiResult<{ token: string }>> | undefined;

/** Cookie 登录与防伪令牌仅用于本平台，不在浏览器保存云平台密钥。 */
export async function api<T>(path: string, method = 'GET', body?: unknown): Promise<ApiResult<T>> {
  const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method);
  if (unsafe && !csrfToken) {
    csrfRequest ??= api<{ token: string }>('/auth/csrf');
    const csrf = await csrfRequest;
    csrfRequest = undefined;
    if (!csrf.success || !csrf.data?.token) return { success: false, code: csrf.code, message: csrf.message || '获取安全令牌失败，请刷新重试。' };
    csrfToken = csrf.data.token;
  }
  try {
    const response = await fetch(`/api${path}`, {
      method, credentials: 'same-origin', cache: 'no-store',
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(unsafe ? { 'X-CSRF-TOKEN': csrfToken ?? '' } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    // 先通知会话失效，协议异常或非 JSON 的 401 也必须及时清除页面内的明文配置。
    if (response.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new Event('ssl-auth-expired'));
    const result: ApiResult<T> = await response.json();
    if (typeof result.success !== 'boolean') return { success: false, code: 'INVALID_RESPONSE', message: '服务器返回格式不正确。' };
    return result;
  } catch {
    // 网络/协议异常转换为可展示的系统失败，业务失败本身不抛异常。
    return { success: false, code: 'NETWORK_ERROR', message: '请求失败，请检查服务连接后重试。' };
  }
}
export function resetCsrfToken() { csrfToken = undefined; csrfRequest = undefined; }
export function query(params: Record<string, unknown>) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => { if (value !== undefined && value !== null && value !== '') search.set(key, String(value)); });
  return search.toString();
}
/** 页面字段统一映射到服务端 search，保留 provider 等真正支持的过滤项。 */
function listQuery(params: Record<string, unknown>) {
  return query({ ...params, search: params.search ?? params.keyword ?? params.name ?? params.domain ?? params.username, keyword: undefined, name: undefined, domain: undefined, username: undefined, current: undefined });
}
export const authApi = {
  setupStatus: () => api<{ needsSetup: boolean }>('/auth/setup-status'),
  setup: (body: unknown) => api<User>('/auth/setup', 'POST', body),
  login: (body: unknown) => api<User>('/auth/login', 'POST', body),
  current: () => api<User>('/auth/current-user'),
  changePassword: (body: { currentPassword: string; newPassword: string }) => api<User>('/auth/change-password', 'POST', body),
  logout: () => api<void>('/auth/logout', 'POST'),
};
export const accountApi = {
  list: (params: Record<string, unknown>) => api<PageResult<CloudAccount>>(`/cloud-accounts?${listQuery(params)}`),
  options: () => api<CloudAccount[]>('/cloud-accounts/options'),
  save: (id: string | undefined, body: unknown) => api<CloudAccount>(`/cloud-accounts${id ? `/${encodeURIComponent(id)}` : ''}`, id ? 'PUT' : 'POST', body),
  secrets: (id: string) => api<{ accessKeyId: string; accessKeySecret: string }>(`/cloud-accounts/${encodeURIComponent(id)}/secrets`),
  test: (id: string) => api<Record<string, unknown>>(`/cloud-accounts/${encodeURIComponent(id)}/test`, 'POST'),
  registerAcme: (id: string, body: { agreeTerms: boolean }) => api<AcmeRegistrationView>(`/cloud-accounts/${encodeURIComponent(id)}/acme-registration`, 'POST', body),
  contacts: (body: { accountId?: string; provider: string; accessKeyId?: string; accessKeySecret?: string }) =>
    api<AliyunContact[]>('/cloud-accounts/aliyun-contacts', 'POST', body),
  aliyunInstances: (accountId: string) =>
    api<AliyunCertificateInstanceOption[]>(`/cloud-accounts/${encodeURIComponent(accountId)}/aliyun-instances`),
};
export const domainApi = {
  list: (params: Record<string, unknown>) => api<PageResult<DnsZone>>(`/domains?${listQuery(params)}`),
  sync: (accountId: string) => api<unknown>('/domains/sync', 'POST', { accountId }),
  records: (id: string) => api<DnsRecord[]>(`/domains/${encodeURIComponent(id)}/records`),
  saveRecord: (zoneId: string, recordId: string | undefined, body: unknown) => api<DnsRecord>(`/domains/${encodeURIComponent(zoneId)}/records${recordId ? `/${encodeURIComponent(recordId)}` : ''}`, recordId ? 'PUT' : 'POST', body),
  recordStatus: (zoneId: string, recordId: string, enabled: boolean) => api<void>(`/domains/${encodeURIComponent(zoneId)}/records/${encodeURIComponent(recordId)}/status`, 'PUT', { enabled }),
  deleteRecord: (zoneId: string, recordId: string) => api<void>(`/domains/${encodeURIComponent(zoneId)}/records/${encodeURIComponent(recordId)}`, 'DELETE'),
};
export const certificateApi = {
  list: (params: Record<string, unknown>) => api<PageResult<Certificate>>(`/certificates?${listQuery(params)}`),
  detail: (id: string) => api<CertificateDetail>(`/certificates/${encodeURIComponent(id)}`),
  sync: (accountId: string) => api<unknown>('/certificates/sync', 'POST', { accountId }),
  apply: (body: ApplyCertificate) => api<Certificate>('/certificates/apply', 'POST', body),
  delete: (ids: string[]) => api<Array<{ id: string; success: boolean; code: string; message: string }>>('/certificates', 'DELETE', { ids }),
  revoke: (id: string, reason: string) => api<void>(`/certificates/${encodeURIComponent(id)}/revoke`, 'POST', { reason }),
  cancel: (id: string) => api<void>(`/certificates/${encodeURIComponent(id)}/cancel`, 'POST'),
  retryCleanup: (id: string) => api<void>(`/certificates/${encodeURIComponent(id)}/cleanup-retry`, 'POST'),
};
export const userApi = {
  list: (params: Record<string, unknown>) => api<PageResult<ManagedUser>>(`/users?${listQuery(params)}`),
  save: (id: string | undefined, body: unknown) => api<ManagedUser>(`/users${id ? `/${encodeURIComponent(id)}` : ''}`, id ? 'PUT' : 'POST', body),
};
export const auditApi = { list: (params: Record<string, unknown>) => api<PageResult<AuditLog>>(`/audit-logs?${query(params)}`) };

/** 下载使用当前 Cookie 会话；错误仍按统一业务返回显示，不打开云平台下载地址。 */
export async function downloadCertificate(id: string, format: string, domain?: string): Promise<ApiResult<void>> {
  try {
    const response = await fetch(`/api/certificates/${encodeURIComponent(id)}/download?${query({ format })}`, { credentials: 'same-origin', cache: 'no-store' });
    if (response.headers.get('content-type')?.includes('json')) {
      const result: ApiResult<void> = await response.json();
      return result.success ? { success: false, code: 'DOWNLOAD_CONTENT_MISSING', message: '服务器未返回证书文件。' } : result;
    }
    if (!response.ok) return { success: false, code: `HTTP_${response.status}`, message: '下载失败，请检查权限或证书状态。' };
    const blob = await response.blob();
    if (blob.size === 0) return { success: false, code: 'DOWNLOAD_CONTENT_MISSING', message: '证书文件为空。' };
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const disposition = response.headers.get('content-disposition');
    const match = disposition?.match(/filename\*?=(?:UTF-8'')?"?([^";]+)/i);
    const safeDomain = (domain || 'certificate').trim().replace(/[^A-Za-z0-9._-]+/g, '_') || 'certificate';
    const date = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Shanghai' }).replace(/-/g, '');
    link.href = url; link.download = match ? decodeURIComponent(match[1]) : `${safeDomain}-${format}-${date}.zip`;
    link.click(); URL.revokeObjectURL(url);
    return { success: true, code: 'OK', message: '下载成功' };
  } catch { return { success: false, code: 'NETWORK_ERROR', message: '下载失败，请检查服务连接。' }; }
}
