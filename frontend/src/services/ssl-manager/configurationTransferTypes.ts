import type { CertificateScheduleInput } from './certificateSchedule';
import type { DeploymentTargetInput } from './deploymentTypes';
import type { ExpiryReminderSettingsInput, MailSettingsInput } from './mailTypes';
import type { McpAllowRule, McpClientInput, McpSettingsInput } from './mcpTypes';

export type ConfigurationImportMode = 'CreateOnly' | 'UpdateByName';
export interface ConfigurationEntry<T> { sourceId: string; settings: T; }
/** MCP 客户端仅迁移公开配置；不携带用户绑定、OAuth ID、秘密或有效授权。 */
export interface McpClientConfiguration {
  sourceId: string;
  settings: Omit<McpClientInput, 'boundUserId' | 'configRevision'>;
  /** 账号和目标 ID 引用包内 sourceId，由服务器导入时映射；所有规则强制停用。 */
  allowRules: McpAllowRule[];
}

/** 文件包含明文凭据；仅短暂保存在当前页面内存，不用于页面渲染或本地存储。 */
export interface ConfigurationPackage {
  format: 'free-ssl-manager.configuration';
  version: 1;
  exportedAtUtc: string;
  cloudAccounts: ConfigurationEntry<Record<string, unknown>>[];
  deploymentTargets: ConfigurationEntry<DeploymentTargetInput>[];
  certificateSchedules: ConfigurationEntry<CertificateScheduleInput>[];
  mailSettings: MailSettingsInput | null;
  /** 旧版本文件可省略；导入时提醒规则同样强制停用。 */
  expiryReminderSettings?: ExpiryReminderSettingsInput | null;
  /** 可选字段兼容旧包；导入强制关闭服务并清空公开地址，待本实例核对。 */
  mcpSettings?: (Omit<McpSettingsInput, 'systemName'> & { systemName?: string }) | null;
  /** 客户端重建为停用状态，必须重新绑定本地用户；机密客户端需要轮换新秘密。 */
  mcpClients?: McpClientConfiguration[];
}
export interface ConfigurationImportRequest {
  package: unknown;
  mode: ConfigurationImportMode;
  previewToken?: string;
}
export interface ConfigurationPreviewItem {
  kind: 'CloudAccount' | 'DeploymentTarget' | 'CertificateSchedule' | 'MailSettings' | 'ExpiryReminderSettings' | 'McpSettings' | 'McpClient';
  sourceId: string;
  name: string;
  action: 'Create' | 'Update' | 'Conflict' | 'Invalid';
}
/** 预览只返回名称、数量和校验结果，不返回配置或凭据。 */
export interface ConfigurationPreview {
  mode: ConfigurationImportMode;
  previewToken: string;
  canImport: boolean;
  created: number;
  updated: number;
  conflicts: number;
  items: ConfigurationPreviewItem[];
  errors: { path: string; message: string }[];
}
export interface ConfigurationImportResult {
  created: number;
  updated: number;
  importedAtUtc: string;
}
