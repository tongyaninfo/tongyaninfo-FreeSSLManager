/** 前后端统一业务返回值，失败通过 success/code/message 表达。 */
export interface ApiResult<T> { success: boolean; code: string; message: string; data?: T; }
export interface PageResult<T> { items: T[]; total: number; page: number; pageSize: number; }
export type Provider = 'TencentCloud' | 'Aliyun' | 'Cloudflare' | 'Acme';
export type AcmeAccountMode = 'Existing' | 'Automatic';
export interface AcmeRegistrationView { accountUrl: string; directoryUrl: string; publicKeyThumbprint: string; status: string; registeredAtUtc?: string | null; }
export interface AliyunContact {
  id: string;
  name: string;
  mobile?: string;
  mobileVerified: boolean;
  email?: string;
  emailVerified: boolean;
}
export interface AliyunCertificateInstanceOption {
  instanceId: string;
  name?: string;
  domain?: string;
  status?: string;
  spec?: string;
}
/** 当前会话使用 name；用户管理列表使用 displayName，保持后端 DTO 边界。 */
export interface User { id: string; username: string; name?: string; role: 'admin' | 'viewer'; }
export interface ManagedUser { id: string; username: string; displayName: string; role: 'admin' | 'viewer'; enabled: boolean; createdAtUtc?: string; updatedAtUtc?: string; }
export interface CloudAccount {
  id: string; name: string; provider: Provider; enabled: boolean;
  useForCertificates: boolean; useForDns: boolean;
  accessKeyIdMasked?: string; accessKeySecretMasked?: string;
  accessKeyIdMask?: string; secretConfigured?: boolean; hasAccessKeySecret?: boolean;
  contactName?: string; contactEmail?: string; contactPhone?: string;
  aliyunContactId?: string;
  acmeDirectoryUrl?: string;
  acmeAccountMode?: AcmeAccountMode; acmeAccountStatus?: string; accountUrl?: string; publicKeyThumbprint?: string; registeredAtUtc?: string | null;
  /** 最近一次连接与权限检测结果；密钥字段永远不在列表响应中。 */
  lastTestAtUtc?: string; lastTestSuccess?: boolean | null; lastTestCode?: string; lastTestMessage?: string;
  /** 自动同步调度配置；autoSyncNextRunAtUtc 由服务端根据配置计算。 */
  autoSyncEnabled?: boolean;
  autoSyncIntervalUnit?: 'minute' | 'hour' | 'day' | 'month';
  autoSyncIntervalValue?: number;
  autoSyncAtLocalTime?: string; lastAutoSyncAtUtc?: string;
  autoSyncNextRunAtUtc?: string; nextSyncAtUtc?: string; nextAutoSyncAtUtc?: string;
  /** 兼容旧接口字段，新的检测结果使用 lastTestAtUtc。 */
  lastTestAt?: string;
}
export interface DnsZone { id: string; name?: string; domain?: string; provider: Provider; accountId: string; accountName?: string; remoteId?: string; zoneId?: string; status?: string; syncedAtUtc?: string; lastSyncedAt?: string; }
export interface DnsRecord { id: string; recordId?: string; name: string; type: string; value: string; ttl: number; mx?: number; line?: string; enabled?: boolean; status?: string; }
export type ValidationMode = 'NativeAutoDns' | 'ManagedDns' | 'ManualDns' | 'File';
export interface Certificate {
  id: string; accountId: string; accountName?: string; provider: Provider;
  remoteId?: string; certificateId?: string; instanceId?: string;
  domain: string; alias?: string; status: string; providerStatus?: string;
  notBefore?: string; notAfter?: string; issuedAt?: string; expiresAt?: string; notBeforeUtc?: string; notAfterUtc?: string; syncedAtUtc?: string; rawStatus?: string; orderId?: string; apiVersion?: string; productCode?: string; isFree?: boolean | null;
  validationMode?: ValidationMode; autoCleanup?: boolean; cleanupStatus?: string;
  hasPrivateKey?: boolean; isStaging?: boolean;
  canDownload?: boolean; canDeploy?: boolean; canRevoke?: boolean; canCancel?: boolean; canDelete?: boolean; downloadFormats?: string[];
  lastSyncedAt?: string; errorMessage?: string;
  validations?: ValidationRecord[]; tasks?: CertificateTask[];
}
export interface CertificateDetail { certificate: Certificate; validations: ValidationRecord[]; tasks: CertificateTask[]; }
export interface ValidationRecord { domain?: string; message?: string; createdBySystem?: boolean; id?: string; name?: string; type?: string; value?: string; recordName?: string; recordType?: string; recordValue?: string; status?: string; cleanupStatus?: string; createdByPlatform?: boolean; recordId?: string; filePath?: string; fileContent?: string; }
export interface CertificateTask { kind?: string; createdAtUtc?: string; nextRunAtUtc?: string; requestId?: string; id?: string; type?: string; status?: string; attempts?: number; message?: string; lastError?: string; createdAt?: string; updatedAt?: string; nextRunAt?: string; }
export interface AuditLog { code?: string; createdAtUtc?: string; id: string; createdAt?: string; username?: string; actor?: string; action: string; resourceType?: string; resourceId?: string; success?: boolean; resultCode?: string; message?: string; ipAddress?: string; }
export interface ApplyCertificate { accountId: string; domain: string; alias?: string; validationMode: ValidationMode; autoCleanup: boolean; dnsZoneId?: string; instanceId?: string; apiVersion?: string; }
