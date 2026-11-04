import { api } from './api';
import type {
  ConfigurationImportRequest,
  ConfigurationImportResult,
  ConfigurationPackage,
  ConfigurationPreview,
} from './configurationTransferTypes';

/** 导出、只读预览及正式导入均复用 Cookie、CSRF 和统一业务返回，不自动重试。 */
export const configurationTransferApi = {
  export: () => api<ConfigurationPackage>('/configuration-transfer/export', 'POST'),
  preview: (body: ConfigurationImportRequest) =>
    api<ConfigurationPreview>('/configuration-transfer/preview', 'POST', body),
  import: (body: ConfigurationImportRequest) =>
    api<ConfigurationImportResult>('/configuration-transfer/import', 'POST', body),
};
