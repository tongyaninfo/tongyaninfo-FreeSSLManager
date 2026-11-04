/** MCP 管理使用现有 Cookie 会话；协议调用使用独立 OAuth 或 API Key Bearer。 */
export interface McpSettingsInput {
  systemName: string;
  enabled: boolean;
  publicBaseUrl: string;
  mode: 'ReadOnly' | 'ControlledWrite';
  allowedCidrs: string[];
  allowedOrigins: string[];
  allowedTools: string[];
  rateLimitPerMinute: number;
  maxConcurrentCalls: number;
  logRetentionDays: number;
  configRevision?: number | null;
}
export interface McpSettings extends McpSettingsInput {
  instanceId: string;
  configRevision: number;
  updatedAtUtc?: string | null;
}
export interface McpStatus {
  systemName: string;
  instanceId: string;
  supported: boolean;
  enabled: boolean;
  oAuthReady: boolean;
  apiKeyReady?: boolean;
  state: string;
  message: string;
  mcpUrl: string;
  protocolVersions: string[];
  sdkVersion: string;
}
export interface McpClientInput {
  name: string;
  clientType: 'public' | 'confidential';
  grantType: 'authorization_code' | 'client_credentials';
  boundUserId: string;
  scopes: string[];
  redirectUris: string[];
  expiresAtUtc?: string | null;
  configRevision?: number;
}
export interface McpClient extends McpClientInput {
  id: string;
  clientId: string;
  enabled: boolean;
  configRevision: number;
  createdAtUtc: string;
  updatedAtUtc: string;
  lastUsedAtUtc?: string | null;
}
export interface McpClientCreated {
  client: McpClient;
  /** 仅创建或轮换的当前响应提供，不保存到浏览器持久存储。 */
  clientSecret?: string | null;
}
export interface McpSecret { clientId: string; clientSecret: string }
export interface McpApiKey {
  id: string;
  clientId: string;
  name: string;
  prefix: string;
  enabled: boolean;
  expiresAtUtc?: string | null;
  createdAtUtc: string;
  updatedAtUtc: string;
  lastUsedAtUtc?: string | null;
  revokedAtUtc?: string | null;
  configRevision: number;
}
export interface McpApiKeyInput { name: string; expiresAtUtc?: string | null }
/** 明文只在创建和轮换响应中返回，列表不提供回读。 */
export interface McpApiKeyCreated { key: McpApiKey; apiKey: string }
export interface McpAllowRule {
  toolNames: string[];
  accountIds: string[];
  domains: string[];
  targetIds: string[];
  allowedCidrs: string[];
  scopes: string[];
  allAccounts: boolean;
  allDomains: boolean;
  allTargets: boolean;
  approvalMode: 'Manual' | 'Preauthorized';
  enabled: boolean;
  expiresAtUtc?: string | null;
}
export interface McpAllowRules { rules: McpAllowRule[]; configRevision: number }
export interface McpTool {
  name: string;
  title: string;
  description: string;
  readOnly: boolean;
  scopes: string[];
  resourceKinds: string[];
  inputSchema: Record<string, unknown>;
  outputSchema?: Record<string, unknown> | null;
}
export interface McpConnectionProfile {
  systemName: string;
  instanceId: string;
  mcpUrl: string;
  clientId: string;
  transport: string;
  grantType: McpClientInput['grantType'];
  scopes: string[];
  authorizationUrl: string;
  tokenUrl: string;
}
export interface McpCallLog {
  id: string;
  traceId: string;
  requestId: string;
  protocolVersion: string;
  method: string;
  toolName: string;
  clientId: string;
  authenticationType?: 'OAuth' | 'ApiKey' | string;
  apiKeyId?: string;
  apiKeyName?: string;
  apiKeyPrefix?: string;
  contextJson?: string;
  userId: string;
  authorizationId: string;
  remoteIp: string;
  sourceIp: string;
  status: string;
  code: string;
  message: string;
  argumentsDigest: string;
  operationId: string;
  certificateId: string;
  batchId: string;
  taskId: string;
  idempotencyReused: boolean;
  policyRevision: number;
  httpStatus: number;
  startedAtUtc: string;
  finishedAtUtc?: string | null;
  durationMilliseconds: number;
  occurrenceCount?: number;
}
export interface McpCallContext {
  userAgent?: string;
  systemName?: string;
  instanceId?: string;
  clientName?: string;
  clientVersion?: string;
  input?: unknown;
  output?: unknown;
  inputCaptured?: boolean;
  outputCaptured?: boolean;
  inputTruncated?: boolean;
  outputTruncated?: boolean;
  truncated?: boolean;
}
export interface McpCallStatistics {
  fromUtc: string;
  toUtc: string;
  totalRequests: number;
  toolCalls: number;
  succeeded: number;
  failed: number;
  denied: number;
  unknown: number;
  averageDurationMilliseconds: number | null;
  trend: { bucketUtc: string; requests: number; toolCalls: number; failed: number; denied: number }[];
}
export interface McpOperation {
  id: string;
  kind: string;
  toolName: string;
  status: string;
  idempotencyKey: string;
  effectiveUserId: string;
  preparedBy: string;
  approvedBy: string;
  approvalExpiresAtUtc?: string | null;
  approvedAtUtc?: string | null;
  consumedAtUtc?: string | null;
  certificateId: string;
  certificateJobId: string;
  batchId: string;
  taskId: string;
  planRevision: number;
  version: number;
  createdAtUtc: string;
  updatedAtUtc: string;
  message: string;
  code: string;
  /** 后端只包含已批准公开的参数、指纹及资源摘要，不是原始输入快照。 */
  summaryJson: string;
  clientId?: string;
  argumentsDigest?: string;
  canApprove?: boolean;
}
