/** 部署功能独立契约；秘密只出现在输入类型，查询类型不提供明文字段。 */
export interface DeploymentExecutorDescriptor {
  key: string;
  name: string;
  targetType: string;
  operatingSystem: string;
  protocol: string;
  revision: string;
  supportedProductVersions: string;
  available: boolean;
  unavailableReason: string;
  authenticationModes?: string[];
  materialFormats?: string[];
  supportsRollback: boolean;
}

export interface DeploymentFileMapping {
  role: string;
  fileName: string;
  directory?: string;
  sourceFileName?: string;
}

/** 实际下载包内的源文件清单，只含元数据。 */
export interface CertificateSourceFile {
  name: string;
  role: string;
  size: number;
  sha256: string;
  containsSecrets: boolean;
}

export interface CertificateSourceListing {
  certificateId: string;
  domain: string;
  format: string;
  files: CertificateSourceFile[];
}

/** 目录浏览只返回元数据，不提供远端文件内容或明文凭据。 */
export interface RemoteDirectoryEntry {
  name: string;
  path: string;
  isDirectory: boolean;
  isSymbolicLink: boolean;
  isRegularFile: boolean;
  size: number;
  modifiedAtUtc?: string | null;
  canSelect: boolean;
}

export interface RemoteDirectoryListing {
  path: string;
  parentPath: string;
  entries: RemoteDirectoryEntry[];
  truncated: boolean;
  observedFingerprint: string;
}

/** 未保存表单可临时连接；空凭据只在连接身份未改变时复用已保存目标。 */
export interface RemoteDirectoryBrowseInput {
  targetId?: string;
  configRevision?: number;
  executorKey: string;
  endpoint: string;
  port: number;
  username: string;
  authenticationMode: string;
  password?: string;
  privateKey?: string;
  privateKeyPassphrase?: string;
  hostKeyFingerprint: string;
  path: string;
  connectionTimeoutSeconds?: number;
  operationTimeoutSeconds?: number;
}

export interface DeploymentCommand {
  command: string;
  workingDirectory: string;
  timeoutSeconds: number;
  executionMode: 'WaitForExit' | 'ExpectDisconnect';
  /** 退出码为 0 时证明原命令已完成，恢复时先检查。 */
  recoveryCheckCommand?: string;
  /** 仅对可安全重复执行的命令开启。 */
  retryOnInterruption?: boolean;
}

export interface DeploymentTargetConfiguration {
  /** Harbor 已有安装目录与 Compose 代理服务；只更新证书，不运行安装脚本。 */
  harborInstallDirectory?: string;
  harborComposeCommand?: 'docker compose' | 'docker-compose';
  harborProxyService?: string;
  /** 目标绑定业务主域名，同域名续签证书可复用映射。 */
  sourceDomain?: string;
  /** 仅兼容历史配置，新配置不再按证书 ID 绑定。 */
  sourceCertificateId?: string;
  sourceFormat?: string;
  siteIds: string[];
  remoteCertificateId: string;
  certificateDescription: string;
  bindSites: boolean;
  operatingSystem: string;
  shell: string;
  outputDirectory: string;
  files: DeploymentFileMapping[];
  validationCommands: DeploymentCommand[];
  postCommands: DeploymentCommand[];
  hostKeyFingerprint: string;
  createDirectory: boolean;
  verificationHost: string;
  verificationPort: number;
  verificationServerName: string;
  connectionTimeoutSeconds: number;
  operationTimeoutSeconds: number;
}

export interface DeploymentTargetInput {
  name: string;
  description: string;
  executorKey: string;
  endpoint: string;
  port: number;
  username: string;
  authenticationMode: string;
  password?: string;
  apiToken?: string;
  privateKey?: string;
  privateKeyPassphrase?: string;
  pfxPassword?: string;
  enabled: boolean;
  tlsFingerprint: string;
  configRevision?: number;
  configuration: DeploymentTargetConfiguration;
}

export interface DeploymentTarget {
  id: string;
  name: string;
  description: string;
  executorKey: string;
  executorRevision: string;
  endpoint: string;
  port: number;
  username: string;
  authenticationMode: string;
  enabled: boolean;
  tlsFingerprint: string;
  configRevision: number;
  configuration: DeploymentTargetConfiguration;
  passwordConfigured: boolean;
  apiTokenConfigured: boolean;
  privateKeyConfigured: boolean;
  pfxPasswordConfigured: boolean;
  lastTestAtUtc?: string;
  lastTestSuccess?: boolean;
  lastTestMessage: string;
  productVersion: string;
  lastDeploymentAtUtc?: string;
  lastDeploymentStatus: string;
}

export interface DeploymentConnectionTest {
  productVersion: string;
  message: string;
  capabilities?: string[];
}

export interface DeploymentDiscovery {
  certificates: Array<{
    id: string;
    name: string;
    domains: string[];
    fingerprint: string;
    relatedSiteIds?: string[];
  }>;
  sites: Array<{
    id: string;
    name: string;
    domains: string[];
    certificateId: string;
  }>;
  productVersion: string;
}

export interface CertificateMaterialMetadata {
  certificateId: string;
  domain: string;
  domains: string[];
  fingerprint: string;
  materialDigest: string;
  notBeforeUtc: string;
  notAfterUtc: string;
}

export interface DeploymentSelection {
  targetId: string;
  remoteCertificateId?: string;
  siteIds?: string[];
}

export interface DeploymentTargetPlan {
  resourceKey: string;
  action: string;
  summary: string;
  remoteResourceId: string;
  siteIds?: string[];
  filePaths?: string[];
  warnings?: string[];
}

export interface DeploymentPlan {
  batchId: string;
  planRevision: number;
  expiresAtUtc: string;
  certificate: CertificateMaterialMetadata;
  targets: Array<{
    taskId: string;
    targetId: string;
    targetName: string;
    executorKey: string;
    configRevision: number;
    plan: DeploymentTargetPlan;
  }>;
}

export interface DeploymentStep {
  id: string;
  phase: string;
  status: string;
  message: string;
  createdAtUtc: string;
}

export interface DeploymentTask {
  id: string;
  batchId: string;
  targetId: string;
  targetName: string;
  executorKey: string;
  status: string;
  phase: string;
  message: string;
  code: string;
  verificationLevel: string;
  fingerprint: string;
  remoteResourceId: string;
  cancelRequested: boolean;
  createdAtUtc: string;
  startedAtUtc?: string;
  finishedAtUtc?: string;
  steps?: DeploymentStep[];
  sourceTaskId?: string;
}

export interface DeploymentBatch {
  id: string;
  certificateId: string;
  certificateDomain: string;
  fingerprint: string;
  status: string;
  planRevision: number;
  createdAtUtc: string;
  expiresAtUtc: string;
  tasks: DeploymentTask[];
  operationType: 'Deploy' | 'Rollback';
}

export interface DeploymentInspection {
  matchesExpected: boolean;
  message: string;
  fingerprint: string;
  verificationLevel: string;
}
