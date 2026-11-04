import { api, query } from './api';
import type { ApiResult, PageResult } from './types';

export type ScheduleIntervalUnit = 'hour' | 'day' | 'month';

/** 计划仅保存已有账号和目标的 ID，不复制其连接凭据。 */
export interface CertificateScheduleInput {
  name: string;
  accountId: string;
  domain: string;
  alias: string;
  validationMode: 'ManagedDns' | 'NativeAutoDns';
  dnsZoneId?: string | null;
  autoCleanup: boolean;
  revokeOldCertificates: boolean;
  targetIds: string[];
  intervalValue: number;
  intervalUnit: ScheduleIntervalUnit;
  firstRunAtUtc: string;
  enabled: boolean;
  configRevision?: number | null;
}

export interface ScheduleTargetProgress {
  targetId: string;
  targetName: string;
  batchId: string;
  status: string;
  code: string;
  message: string;
}

export interface ScheduleCertificateCleanup {
  certificateId: string;
  domain: string;
  status: string;
  code: string;
  message: string;
}

export interface CertificateScheduleRun {
  id: string;
  scheduleId: string;
  certificateId: string;
  status: string;
  code: string;
  message: string;
  cleanupStatus: string;
  applicationCleanupStatus?: string;
  scheduledForUtc: string;
  createdAtUtc: string;
  startedAtUtc?: string | null;
  finishedAtUtc?: string | null;
  nextCheckAtUtc: string;
  active: boolean;
  targets: ScheduleTargetProgress[];
  oldCertificates: ScheduleCertificateCleanup[];
}

export interface CertificateSchedule extends CertificateScheduleInput {
  id: string;
  accountName: string;
  nextRunAtUtc: string;
  createdAtUtc: string;
  updatedAtUtc: string;
  latestRun?: CertificateScheduleRun | null;
}

/** 统一使用 Cookie、CSRF 与 ApiResult，立即执行只提交一轮，由后台持久推进。 */
export const certificateScheduleApi = {
  list: (params: Record<string, unknown> = {}): Promise<ApiResult<PageResult<CertificateSchedule>>> =>
    api(`/certificate-schedules?${query(params)}`),
  get: (id: string) => api<CertificateSchedule>(`/certificate-schedules/${encodeURIComponent(id)}`),
  save: (id: string | undefined, body: CertificateScheduleInput) =>
    api<CertificateSchedule>(`/certificate-schedules${id ? `/${encodeURIComponent(id)}` : ''}`, id ? 'PUT' : 'POST', body),
  status: (id: string, enabled: boolean) =>
    api<CertificateSchedule>(`/certificate-schedules/${encodeURIComponent(id)}/status`, 'POST', { enabled }),
  run: (id: string) => api<CertificateScheduleRun>(`/certificate-schedules/${encodeURIComponent(id)}/run`, 'POST'),
  runs: (id: string, params: Record<string, unknown> = {}) =>
    api<PageResult<CertificateScheduleRun>>(`/certificate-schedules/${encodeURIComponent(id)}/runs?${query(params)}`),
  resume: (runId: string) => api<CertificateScheduleRun>(`/certificate-schedules/runs/${encodeURIComponent(runId)}/resume`, 'POST'),
  resolve: (runId: string, note: string) => api<CertificateScheduleRun>(`/certificate-schedules/runs/${encodeURIComponent(runId)}/resolve`, 'POST', { note }),
};
