import dayjs from 'dayjs';
import timezone from 'dayjs/plugin/timezone';
import utc from 'dayjs/plugin/utc';

dayjs.extend(utc);
dayjs.extend(timezone);

export const scheduleUnitNames = { hour: '小时', day: '天', month: '月' };
export const scheduleStateNames: Record<string, string> = {
  Pending: '等待执行',
  Applying: '申请证书',
  WaitingCertificate: '等待签发',
  WaitingForIssuance: '等待签发',
  Deploying: '部署中',
  Recovering: '恢复核对中',
  CleaningOldCertificates: '清理证书和验证记录',
  Succeeded: '已完成',
  Failed: '失败',
  PartiallySucceeded: '部分成功',
  PartialFailed: '部分失败',
  NeedsAttention: '需要处理',
  Paused: '已暂停',
  Cancelled: '已取消',
  Skipped: '已跳过',
  Resolved: '已人工结束',
  Submitting: '正在提交部署',
};
export const cleanupStateNames: Record<string, string> = {
  Pending: '等待部署结果',
  NotRequested: '未开启',
  Disabled: '未开启',
  NotStarted: '未执行',
  NotRequired: '无需清理',
  Skipped: '未执行',
  Running: '清理中',
  Cleaning: '清理中',
  Succeeded: '清理完成',
  Completed: '清理完成',
  CompletedWithSkips: '已清理，部分跳过',
  Cancelled: '已取消',
  Deleted: '已删除',
  Revoking: '等待吊销确认',
  Revoked: '已吊销',
  Deleting: '删除中',
  DnsCleaning: '清理证书验证记录',
  NeedsAttention: '清理需处理',
  Failed: '清理失败',
  Blocked: '暂不能清理',
};

export const oldCertificateStateNames: Record<string, string> = {
  ...cleanupStateNames,
  Pending: '等待清理',
  Skipped: '已跳过',
  RevokeSubmitting: '吊销提交中',
  DeleteSubmitting: '删除提交中',
};

/** 所有输入、默认值与展示固定为上海时区，避免浏览器所在时区改变周期锚点。 */
export function scheduleDate(value: string) {
  const text = value.trim().replace(' ', 'T');
  return dayjs
    .utc(/(?:Z|[+-]\d{2}:?\d{2})$/i.test(text) ? text : `${text}Z`)
    .tz('Asia/Shanghai');
}

export function defaultScheduleFirstRun(now = new Date()) {
  return dayjs(now)
    .tz('Asia/Shanghai')
    .add(1, 'month')
    .hour(2)
    .minute(0)
    .second(0)
    .millisecond(0);
}

export function scheduleStateColor(state?: string) {
  if (['Succeeded', 'Completed', 'Deleted', 'Skipped'].includes(state || ''))
    return 'success';
  if (state === 'Failed') return 'error';
  if (
    [
      'NeedsAttention',
      'PartiallySucceeded',
      'PartialFailed',
      'CompletedWithSkips',
      'Blocked',
    ].includes(state || '')
  )
    return 'warning';
  return [
    'Pending',
    'Applying',
    'WaitingCertificate',
    'WaitingForIssuance',
    'Deploying',
    'Recovering',
    'CleaningOldCertificates',
    'Running',
    'Cleaning',
    'Revoking',
    'Deleting',
    'DnsCleaning',
    'Submitting',
    'RevokeSubmitting',
    'DeleteSubmitting',
  ].includes(state || '')
    ? 'processing'
    : 'default';
}
