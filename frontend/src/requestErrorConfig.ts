import type { RequestConfig } from '@umijs/max';

// 业务失败由 service 返回 success/code/message，禁止用异常表示业务规则。
export const errorConfig: RequestConfig = {
  errorConfig: {
    errorHandler: (error: any, options: any) => {
      if (options?.skipErrorHandler) return;
      const status = error.response?.status;
      const text = status
        ? `请求失败（HTTP ${status}）`
        : '服务连接失败，请稍后重试。';
      window.dispatchEvent(
        new CustomEvent('ssl-system-error', { detail: text }),
      );
    },
  },
};
