import { describe, expect, it } from 'vitest';
import {
  deploymentDateText,
  deploymentStatusColor,
  isDeploymentActive,
  verificationLevelNames,
} from './presentation';

describe('部署任务展示', () => {
  it('缺少时区标记的 Utc 时间按 UTC 解释，再转换到上海时间', () => {
    const expected = '2026/10/28 14:23:00';
    expect(deploymentDateText('2026-10-28T06:23:00')).toBe(expected);
    expect(deploymentDateText('2026-10-28T06:23:00Z')).toBe(expected);
    expect(deploymentDateText('2026-10-28T14:23:00+08:00')).toBe(expected);
  });

  it('仅等待和执行中的任务继续轮询，待核对和终态停止轮询', () => {
    expect(isDeploymentActive('Queued')).toBe(true);
    expect(isDeploymentActive('Running')).toBe(true);
    expect(isDeploymentActive('Recovering')).toBe(true);
    for (const state of [
      'Draft',
      'Succeeded',
      'PartiallySucceeded',
      'NeedsAttention',
      'Cancelled',
      'Failed',
      'Skipped',
      undefined,
    ])
      expect(isDeploymentActive(state)).toBe(false);
  });

  it('待核对显示为警告，并保留文件与服务生效的证据差异', () => {
    expect(deploymentStatusColor('NeedsAttention')).toBe('warning');
    expect(verificationLevelNames.FilesChecked).toBe('文件与哈希已核对');
    expect(verificationLevelNames.TlsObserved).toBe('服务证书已生效');
    expect(verificationLevelNames.None).toBe('服务生效未验证');
  });
});
