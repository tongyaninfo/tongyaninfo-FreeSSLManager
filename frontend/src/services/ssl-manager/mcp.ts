import { api, query } from './api';
import type {
  McpAllowRules, McpCallLog, McpClient, McpClientCreated, McpClientInput,
  McpConnectionProfile, McpOperation, McpSecret, McpSettings, McpSettingsInput,
  McpStatus, McpTool,
  McpApiKey, McpApiKeyInput, McpApiKeyCreated,
  McpCallStatistics,
} from './mcpTypes';
import type { PageResult } from './types';

const clientPath = (id: string) => `/mcp/clients/${encodeURIComponent(id)}`;
/** 所有管理写请求复用 CSRF；网络结果不明时不自动重复创建、轮换或审批。 */
export const mcpApi = {
  settings: () => api<McpSettings>('/mcp/settings'),
  saveSettings: (input: McpSettingsInput) => api<McpSettings>('/mcp/settings', 'PUT', input),
  status: () => api<McpStatus>('/mcp/status'),
  tools: () => api<McpTool[]>('/mcp/tools'),
  clients: (params: Record<string, unknown> = {}) => api<PageResult<McpClient>>(`/mcp/clients?${query(params)}`),
  createClient: (input: McpClientInput) => api<McpClientCreated>('/mcp/clients', 'POST', input),
  updateClient: (id: string, input: McpClientInput) => api<McpClient>(clientPath(id), 'PUT', input),
  clientStatus: (id: string, enabled: boolean, configRevision: number) => api<McpClient>(`${clientPath(id)}/status`, 'POST', { enabled, configRevision }),
  rotateSecret: (id: string) => api<McpSecret>(`${clientPath(id)}/rotate-secret`, 'POST'),
  apiKeys: (id: string) => api<McpApiKey[]>(`${clientPath(id)}/api-keys`),
  createApiKey: (id: string, input: McpApiKeyInput) => api<McpApiKeyCreated>(`${clientPath(id)}/api-keys`, 'POST', input),
  apiKeyStatus: (id: string, enabled: boolean, configRevision: number) => api<McpApiKey>(`/mcp/api-keys/${encodeURIComponent(id)}/status`, 'POST', { enabled, configRevision }),
  rotateApiKey: (id: string, configRevision: number) => api<McpApiKeyCreated>(`/mcp/api-keys/${encodeURIComponent(id)}/rotate`, 'POST', { configRevision }),
  revokeApiKey: (id: string, configRevision: number) => api<McpApiKey>(`/mcp/api-keys/${encodeURIComponent(id)}/revoke`, 'POST', { configRevision }),
  revokeClient: (id: string) => api<unknown>(`${clientPath(id)}/revoke`, 'POST'),
  rules: (id: string) => api<McpAllowRules>(`${clientPath(id)}/allow-rules`),
  saveRules: (id: string, input: McpAllowRules) => api<McpAllowRules>(`${clientPath(id)}/allow-rules`, 'PUT', input),
  connectionProfile: (id: string) => api<McpConnectionProfile>(`${clientPath(id)}/connection-profile`),
  callLogs: (params: Record<string, unknown> = {}) => api<PageResult<McpCallLog>>(`/mcp/call-logs?${query(params)}`),
  callStatistics: (params: Record<string, unknown> = {}) => api<McpCallStatistics>(`/mcp/call-logs/statistics?${query(params)}`),
  callLog: (id: string) => api<McpCallLog>(`/mcp/call-logs/${encodeURIComponent(id)}`),
  operations: (params: Record<string, unknown> = {}) => api<PageResult<McpOperation>>(`/mcp/operations?${query(params)}`),
  operation: (id: string) => api<McpOperation>(`/mcp/operations/${encodeURIComponent(id)}`),
  approve: (id: string, version: number, note: string) => api<McpOperation>(`/mcp/operations/${encodeURIComponent(id)}/approve`, 'POST', { version, note }),
  reject: (id: string, version: number, note: string) => api<McpOperation>(`/mcp/operations/${encodeURIComponent(id)}/reject`, 'POST', { version, note }),
};
