/** 多行配置去重，空输入保持空白名单，不隐式转换为全部资源。 */
export function mcpLines(value?: string): string[] {
  return [
    ...new Set(
      (value || '')
        .split(/[\r\n,]+/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ];
}
export function mcpDate(value?: string | null): string {
  if (!value) return '—';
  const date = new Date(
    /[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : `${value.replace(' ', 'T')}Z`,
  );
  return Number.isNaN(date.getTime())
    ? '—'
    : date.toLocaleString('zh-CN', {
        timeZone: 'Asia/Shanghai',
        hour12: false,
      });
}
export const mcpStatusNames: Record<string, string> = {
  Unsupported: '当前环境不支持',
  OAuthNotReady: 'OAuth 尚未就绪',
  NoAuthorizedClients: '无有效客户端授权',
  Disabled: '已关闭',
  Unavailable: '环境不支持',
  Ready: '可调用',
  NoAuthorization: '无有效授权',
  Started: '处理中',
  Succeeded: '成功',
  Failed: '失败',
  Rejected: '已拒绝',
  Denied: '未授权',
  Prepared: '待审批',
  PendingApproval: '待审批',
  Approved: '已批准',
  Submitted: '已提交',
  Dispatching: '正在派发',
  Completed: '已完成',
  Expired: '已过期',
  Cancelled: '已取消',
  Unknown: '结果未知',
  TimedOut: '超时',
  Interrupted: '中断待核对',
};
export function mcpStatusText(status: string): string {
  return mcpStatusNames[status] || status;
}

/** 客户端连接名使用兼容的 ASCII 字符和实例 ID，中文系统名仍在协议及页面完整展示。 */
export function mcpConnectionName(
  systemName: string,
  instanceId: string,
): string {
  const name =
    systemName.replace(/[^A-Za-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '') ||
    'free-ssl-manager';
  const identity =
    instanceId.replace(/[^A-Za-z0-9_-]+/g, '_') || 'unconfigured';
  return `${name.slice(0, 48)}-${identity}`;
}

/** 审批只作用于尚未提交且未过期的草稿，服务端再次校验所有修订和有效身份。 */
export function canApproveOperation(
  operation: { status: string; approvalExpiresAtUtc?: string | null },
  now = Date.now(),
): boolean {
  return (
    ['Prepared', 'PendingApproval'].includes(operation.status) &&
    (!operation.approvalExpiresAtUtc ||
      new Date(operation.approvalExpiresAtUtc).getTime() > now)
  );
}
