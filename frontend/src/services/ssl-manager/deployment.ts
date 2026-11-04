import { api, query } from './api';
import type {
  CertificateSourceListing,
  DeploymentBatch,
  DeploymentConnectionTest,
  DeploymentDiscovery,
  DeploymentExecutorDescriptor,
  DeploymentInspection,
  DeploymentPlan,
  DeploymentSelection,
  DeploymentTarget,
  DeploymentTargetInput,
  DeploymentTask,
  RemoteDirectoryBrowseInput,
  RemoteDirectoryListing,
} from './deploymentTypes';
import type { PageResult } from './types';

/** 所有部署请求沿用现有 Cookie、CSRF 和统一业务返回，不自行保存认证材料。 */
export const deploymentApi = {
  sourceFiles: (certificateId: string, format: string) =>
    api<CertificateSourceListing>(
      `/certificates/${encodeURIComponent(certificateId)}/deployment-files?${query({ format })}`,
    ),
  executors: () => api<DeploymentExecutorDescriptor[]>('/deployment-executors'),
  targets: (params: Record<string, unknown> = {}) =>
    api<PageResult<DeploymentTarget>>(`/deployment-targets?${query(params)}`),
  target: (id: string) =>
    api<DeploymentTarget>(`/deployment-targets/${encodeURIComponent(id)}`),
  saveTarget: (id: string | undefined, body: DeploymentTargetInput) =>
    api<DeploymentTarget>(
      `/deployment-targets${id ? `/${encodeURIComponent(id)}` : ''}`,
      id ? 'PUT' : 'POST',
      body,
    ),
  targetStatus: (id: string, enabled: boolean) =>
    api<DeploymentTarget>(
      `/deployment-targets/${encodeURIComponent(id)}/status`,
      'POST',
      { enabled },
    ),
  testTarget: (id: string) =>
    api<DeploymentConnectionTest>(
      `/deployment-targets/${encodeURIComponent(id)}/test`,
      'POST',
    ),
  discover: (id: string) =>
    api<DeploymentDiscovery>(
      `/deployment-targets/${encodeURIComponent(id)}/discover`,
      'POST',
    ),
  browseDirectory: (body: RemoteDirectoryBrowseInput) =>
    api<RemoteDirectoryListing>('/deployment-targets/browse', 'POST', body),
  plan: (certificateId: string, targets: DeploymentSelection[]) =>
    api<DeploymentPlan>(
      `/certificates/${encodeURIComponent(certificateId)}/deployments/plan`,
      'POST',
      { targets },
    ),
  submit: (batchId: string, planRevision: number, idempotencyKey: string) =>
    api<DeploymentBatch>(
      `/deployments/${encodeURIComponent(batchId)}/submit`,
      'POST',
      { planRevision, idempotencyKey },
    ),
  batches: (params: Record<string, unknown> = {}) =>
    api<PageResult<DeploymentBatch>>(`/deployments?${query(params)}`),
  batch: (id: string) =>
    api<DeploymentBatch>(`/deployments/${encodeURIComponent(id)}`),
  task: (id: string) =>
    api<DeploymentTask>(`/deployment-tasks/${encodeURIComponent(id)}`),
  cancel: (id: string) =>
    api<DeploymentTask>(
      `/deployment-tasks/${encodeURIComponent(id)}/cancel`,
      'POST',
    ),
  inspect: (id: string) =>
    api<DeploymentInspection>(
      `/deployment-tasks/${encodeURIComponent(id)}/inspect`,
      'POST',
    ),
  resolve: (id: string, note: string) =>
    api<DeploymentTask>(
      `/deployment-tasks/${encodeURIComponent(id)}/resolve`,
      'POST',
      { note },
    ),
  retryPlan: (id: string) =>
    api<DeploymentPlan>(
      `/deployment-tasks/${encodeURIComponent(id)}/retry-plan`,
      'POST',
    ),
  rollbackPlan: (id: string) =>
    api<DeploymentPlan>(
      `/deployment-tasks/${encodeURIComponent(id)}/rollback-plan`,
      'POST',
    ),
};
