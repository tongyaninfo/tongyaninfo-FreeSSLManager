/** 单套 SMTP 配置；服务端只返回密码是否已配置。 */
export interface MailSettingsDto {
  configured: boolean;
  host: string;
  port: number;
  security: 'SslOnConnect' | 'StartTls';
  username: string;
  fromAddress: string;
  fromName: string;
  hasPassword: boolean;
  enabled: boolean;
  updatedAtUtc?: string | null;
}

export interface MailSettingsInput {
  host: string;
  port: number;
  security: MailSettingsDto['security'];
  username: string;
  fromAddress: string;
  fromName: string;
  /** 留空时复用服务端已保存的密码，不提供清空凭据操作。 */
  password?: string;
  enabled: boolean;
}

export interface MailSendInput {
  /** 同一份草稿使用同一请求 ID，网络结果不明时不新建发送任务。 */
  requestId: string;
  to: string[];
  subject: string;
  body: string;
}

/** 发件列表不返回正文，正文只在主动读取详情后展示。 */
export interface MailMessageDto {
  id: string;
  to: string[];
  subject: string;
  fromAddress: string;
  body?: string;
  status: string;
  code: string;
  message: string;
  createdByName: string;
  createdAtUtc: string;
  completedAtUtc?: string | null;
  messageId?: string;
}

/** 到期提醒复用系统 SMTP；保存规则不直接提交邮件。 */
export interface ExpiryReminderSettingsInput {
  enabled: boolean;
  daysBeforeExpiry: number;
  repeatIntervalDays: number;
  recipients: string[];
}

export interface ExpiryReminderSettingsSummary extends ExpiryReminderSettingsInput {
  configured: boolean;
  smtpConfigured: boolean;
  smtpEnabled: boolean;
  updatedAtUtc?: string | null;
}

export type ExpiryReminderAlertStatus = 'Active' | 'Resolved' | 'Ignored';

/** 预警状态与最近邮件结果独立展示，SMTP 受理不代表最终送达。 */
export interface ExpiryReminderAlert {
  id: string;
  certificateId: string;
  accountName: string;
  domain: string;
  alias: string;
  notAfterUtc: string;
  status: ExpiryReminderAlertStatus;
  firstDetectedAtUtc: string;
  lastAttemptAtUtc?: string | null;
  nextReminderAtUtc?: string | null;
  lastMailStatus: string;
  message: string;
}
