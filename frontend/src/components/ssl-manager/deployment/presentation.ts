/** 部署状态与验证证据分别展示，避免把文件写入误报为服务已生效。 */
export const deploymentStatusNames: Record<string, string> = {
  Draft: '待确认',
  Planned: '待确认',
  Queued: '等待执行',
  Running: '执行中',
  Recovering: '恢复核对中',
  Succeeded: '已完成',
  PartiallySucceeded: '部分成功',
  CompletedWithWarnings: '已完成，有待处理项',
  Failed: '失败',
  NeedsAttention: '结果待核对',
  Resolved: '已人工解除',
  Cancelled: '已取消',
  Skipped: '无需重复部署',
  RolledBack: '文件已恢复',
  RollbackFailed: '恢复失败',
};

export const deploymentPhaseNames: Record<string, string> = {
  Material: '读取证书材料',
  Preflight: '前置检查',
  Backup: '备份',
  Stage: '暂存上传',
  Activate: '激活证书',
  Validation: '配置检查',
  PostCommand: '执行后置命令',
  Verify: '生效验证',
  Recover: '恢复检查',
  Completed: '已结束',
};

export const verificationLevelNames: Record<string, string> = {
  None: '服务生效未验证',
  FilesChecked: '文件与哈希已核对',
  FileHash: '文件与哈希已核对',
  PlatformReadback: '平台证书已核对',
  TlsObserved: '服务证书已生效',
  FilesRestored: '文件已恢复，服务生效未验证',
};

export const deploymentActionNames: Record<string, string> = {
  Create: '新增证书',
  Replace: '替换证书',
  Update: '更新证书',
  Upload: '上传证书',
  Files: '写入证书文件',
  ReplaceFiles: '替换证书文件',
  Rollback: '恢复原备份文件',
  Skip: '无需重复部署',
};

/** EF 读取的 Utc 时间可能缺少 Z，部署模块统一补齐 UTC 语义并按上海时区显示。 */
export function deploymentDateText(value?: string) {
  if (!value?.trim()) return '—';
  const text = value.trim().replace(' ', 'T');
  const date = new Date(
    /(?:Z|[+-]\d{2}:?\d{2})$/i.test(text) ? text : `${text}Z`,
  );
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour12: false,
  });
}

/** 只为正在运行的任务轮询，草稿和待人工核对状态不持续发请求。 */
export function isDeploymentActive(state?: string) {
  return state === 'Queued' || state === 'Running' || state === 'Recovering';
}

export function deploymentStatusColor(state?: string) {
  if (state === 'Succeeded' || state === 'Skipped' || state === 'RolledBack')
    return 'success';
  if (state === 'Failed' || state === 'RollbackFailed') return 'error';
  if (state === 'NeedsAttention' || state === 'PartiallySucceeded')
    return 'warning';
  return isDeploymentActive(state) ? 'processing' : 'default';
}
