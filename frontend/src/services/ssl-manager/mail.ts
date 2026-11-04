import { api, query } from './api';
import type {
  ExpiryReminderAlert,
  ExpiryReminderSettingsInput,
  ExpiryReminderSettingsSummary,
  MailMessageDto,
  MailSendInput,
  MailSettingsDto,
  MailSettingsInput,
} from './mailTypes';
import type { PageResult } from './types';

/** 邮件复用当前会话、CSRF 与统一结果；发送请求不自动重试。 */
export const mailApi = {
  settings: () => api<MailSettingsDto>('/mail/settings'),
  saveSettings: (body: MailSettingsInput) =>
    api<MailSettingsDto>('/mail/settings', 'PUT', body),
  probe: () => api<unknown>('/mail/probe', 'POST'),
  send: (body: MailSendInput) =>
    api<MailMessageDto>('/mail/send', 'POST', body),
  messages: (params: Record<string, unknown> = {}) =>
    api<PageResult<MailMessageDto>>(`/mail/messages?${query(params)}`),
  message: (id: string) =>
    api<MailMessageDto>(`/mail/messages/${encodeURIComponent(id)}`),
  expiryReminderSettings: () =>
    api<ExpiryReminderSettingsSummary>('/mail/expiry-reminders/settings'),
  saveExpiryReminderSettings: (body: ExpiryReminderSettingsInput) =>
    api<ExpiryReminderSettingsSummary>('/mail/expiry-reminders/settings', 'PUT', body),
  expiryReminderAlerts: (params: Record<string, unknown> = {}) =>
    api<PageResult<ExpiryReminderAlert>>(`/mail/expiry-reminders/alerts?${query(params)}`),
  ignoreExpiryReminderAlert: (id: string) =>
    api<unknown>(`/mail/expiry-reminders/alerts/${encodeURIComponent(id)}/ignore`, 'POST'),
};
