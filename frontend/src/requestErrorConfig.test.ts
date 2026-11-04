import { beforeEach, describe, expect, it, vi } from 'vitest';
import { errorConfig } from './requestErrorConfig';

describe('请求异常处理边界', () => {
  const notify = vi.fn();
  beforeEach(() => {
    notify.mockReset();
    window.addEventListener('ssl-system-error', notify, { once: true });
  });
  it('没有将业务失败转换为异常的 errorThrower', () => {
    expect(errorConfig.errorConfig?.errorThrower).toBeUndefined();
  });
  it('HTTP 系统错误交由 App 上下文展示', () => {
    errorConfig.errorConfig?.errorHandler?.(
      { response: { status: 500 } } as any,
      {},
    );
    expect(notify).toHaveBeenCalledWith(
      expect.objectContaining({ detail: '请求失败（HTTP 500）' }),
    );
  });
  it('主动跳过默认提示时不重复弹窗', () => {
    errorConfig.errorConfig?.errorHandler?.(
      { response: { status: 500 } } as any,
      { skipErrorHandler: true },
    );
    expect(notify).not.toHaveBeenCalled();
  });
});
