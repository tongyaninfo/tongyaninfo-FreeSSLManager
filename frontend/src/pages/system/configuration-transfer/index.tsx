import { PageContainer } from '@ant-design/pro-components';
import { useAccess } from '@umijs/max';
import {
  Alert,
  Button,
  Card,
  Modal,
  Radio,
  Result,
  Table,
  Typography,
  Upload,
} from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import { configurationTransferApi } from '@/services/ssl-manager/configurationTransfer';
import type {
  ConfigurationImportMode,
  ConfigurationPackage,
  ConfigurationPreview,
  ConfigurationPreviewItem,
} from '@/services/ssl-manager/configurationTransferTypes';

const maximumFileSize = 5 * 1024 * 1024;
// 后端 JSON 深度上限为 64；预留请求包装层，避免序列化极深输入时栈溢出。
const maximumJsonDepth = 60;
const uncertainCodes = new Set([
  'NETWORK_ERROR',
  'INVALID_RESPONSE',
  'SYSTEM_ERROR',
]);
const kindNames: Record<ConfigurationPreviewItem['kind'], string> = {
  CloudAccount: '云账号',
  DeploymentTarget: '部署目标',
  CertificateSchedule: '计划任务',
  MailSettings: '邮件设置',
  ExpiryReminderSettings: '到期提醒设置',
  McpSettings: 'MCP 服务设置',
  McpClient: 'MCP 客户端及调用规则',
};
const actionNames: Record<ConfigurationPreviewItem['action'], string> = {
  Create: '新增',
  Update: '更新',
  Conflict: '冲突',
  Invalid: '无效',
};

function hasSupportedJsonDepth(text: string): boolean {
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (const character of text) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') quoted = false;
    } else if (character === '"') quoted = true;
    else if (character === '{' || character === '[') {
      if (++depth > maximumJsonDepth) return false;
    } else if (character === '}' || character === ']') depth--;
  }
  return true;
}

function isConfigurationPackage(value: unknown): value is ConfigurationPackage {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  return (
    candidate.format === 'free-ssl-manager.configuration' &&
    candidate.version === 1 &&
    typeof candidate.exportedAtUtc === 'string' &&
    Array.isArray(candidate.cloudAccounts) &&
    Array.isArray(candidate.deploymentTargets) &&
    Array.isArray(candidate.certificateSchedules) &&
    (candidate.mcpSettings === undefined ||
      candidate.mcpSettings === null ||
      (typeof candidate.mcpSettings === 'object' &&
        !Array.isArray(candidate.mcpSettings))) &&
    (candidate.mcpClients === undefined ||
      Array.isArray(candidate.mcpClients)) &&
    (candidate.mailSettings === null ||
      (typeof candidate.mailSettings === 'object' &&
        !Array.isArray(candidate.mailSettings)))
  );
}

/** 管理员入口独立挂载，权限撤销后卸载组件并释放含凭据的数据包。 */
export default function ConfigurationTransfer() {
  const access = useAccess();
  return access.canAdmin ? (
    <ConfigurationTransferContent />
  ) : (
    <Result status="403" title="无配置导入导出权限" />
  );
}

function ConfigurationTransferContent() {
  const packageRef = useRef<ConfigurationPackage | undefined>(undefined);
  const revision = useRef(0);
  const pending = useRef(false);
  const active = useRef(true);
  const [fileName, setFileName] = useState('');
  const [mode, setMode] = useState<ConfigurationImportMode>('CreateOnly');
  const [preview, setPreview] = useState<ConfigurationPreview>();
  const [busy, setBusy] = useState<'file' | 'preview' | 'import' | 'export'>();
  const [confirmation, setConfirmation] = useState<'import' | 'export'>();
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [uncertain, setUncertain] = useState(false);
  const [expired, setExpired] = useState<'session' | 'permission'>();

  const clearSensitiveState = (reason: 'session' | 'permission') => {
    active.current = false;
    revision.current++;
    packageRef.current = undefined;
    setFileName('');
    setPreview(undefined);
    setConfirmation(undefined);
    setError('');
    setNotice('');
    setExpired(reason);
  };
  const handleAuthorizationFailure = (code: string) => {
    if (code !== 'FORBIDDEN' && code !== 'UNAUTHORIZED') return false;
    clearSensitiveState(code === 'FORBIDDEN' ? 'permission' : 'session');
    return true;
  };

  useEffect(() => {
    active.current = true;
    const expire = () => clearSensitiveState('session');
    window.addEventListener('ssl-auth-expired', expire);
    return () => {
      active.current = false;
      revision.current++;
      packageRef.current = undefined;
      window.removeEventListener('ssl-auth-expired', expire);
    };
  }, []);

  const selectFile = async (file: File) => {
    if (pending.current || uncertain || !active.current) return;
    const selectedRevision = ++revision.current;
    packageRef.current = undefined;
    setPreview(undefined);
    setConfirmation(undefined);
    setNotice('');
    setError('');
    setFileName('');
    if (!file.name.toLowerCase().endsWith('.json')) {
      setError('请选择 JSON 配置文件。');
      return;
    }
    if (file.size === 0 || file.size > maximumFileSize) {
      setError('配置文件不能为空，且不能超过 5 MiB。');
      return;
    }
    pending.current = true;
    setBusy('file');
    try {
      const text = await file.text();
      if (!active.current || revision.current !== selectedRevision) return;
      if (!hasSupportedJsonDepth(text)) {
        setError('JSON 嵌套层级过深，请使用本系统导出的配置文件。');
        return;
      }
      const parsed: unknown = JSON.parse(text);
      if (!isConfigurationPackage(parsed)) {
        setError('配置文件格式或版本不受支持，请选择本系统导出的版本 1 文件。');
        return;
      }
      packageRef.current = parsed;
      setFileName(file.name);
    } catch {
      if (active.current && revision.current === selectedRevision)
        setError('无法读取有效的 JSON 配置文件。');
    } finally {
      pending.current = false;
      if (active.current) setBusy(undefined);
    }
  };

  const changeMode = (nextMode: ConfigurationImportMode) => {
    revision.current++;
    setMode(nextMode);
    setPreview(undefined);
    setConfirmation(undefined);
    setError('');
    setNotice('');
  };

  const previewImport = async () => {
    if (pending.current || !packageRef.current || uncertain || !active.current)
      return;
    const selectedRevision = revision.current;
    const selectedPackage = packageRef.current;
    pending.current = true;
    setBusy('preview');
    setError('');
    setNotice('');
    setPreview(undefined);
    try {
      const result = await configurationTransferApi.preview({
        package: selectedPackage,
        mode,
      });
      if (
        !active.current ||
        handleAuthorizationFailure(result.code) ||
        revision.current !== selectedRevision
      )
        return;
      if (!result.success || !result.data)
        setError(result.message || '导入预览失败，请重新预览。');
      else setPreview(result.data);
    } catch {
      if (active.current && revision.current === selectedRevision)
        setError('导入预览失败，请重新预览。');
    } finally {
      pending.current = false;
      if (active.current) setBusy(undefined);
    }
  };

  const exportPackage = async () => {
    if (pending.current || !active.current) return;
    pending.current = true;
    setBusy('export');
    setError('');
    setNotice('');
    try {
      const result = await configurationTransferApi.export();
      if (!active.current || handleAuthorizationFailure(result.code)) return;
      if (!result.success || !result.data) {
        setError(result.message || '配置导出失败。');
        return;
      }
      // 与导入采用同一字节上限；不使用缩进，以免合法导出被空白撑大后无法回导。
      const blob = new Blob([JSON.stringify(result.data)], {
        type: 'application/json;charset=utf-8',
      });
      if (blob.size > maximumFileSize) {
        setError('配置文件超过 5 MiB，无法导出为可重新导入的文件。');
        return;
      }
      const url = URL.createObjectURL(blob);
      try {
        const link = document.createElement('a');
        link.href = url;
        const date = new Date().toLocaleDateString('en-CA', {
          timeZone: 'Asia/Shanghai',
        });
        link.download = `freesslmanager-configuration-${date}.json`;
        link.click();
      } finally {
        URL.revokeObjectURL(url);
      }
      setNotice('配置文件已下载，文件包含明文凭据，请妥善保存。');
    } catch {
      if (active.current) setError('配置导出失败，请稍后重试。');
    } finally {
      pending.current = false;
      if (active.current) {
        setBusy(undefined);
        setConfirmation(undefined);
      }
    }
  };

  const importPackage = async () => {
    if (
      pending.current ||
      !active.current ||
      !packageRef.current ||
      !preview?.canImport ||
      !preview.previewToken ||
      preview.mode !== mode ||
      uncertain
    )
      return;
    // 同一对象与预览令牌一起提交，避免预览后更换内容；请求结果不明时不自动重试。
    const selectedPackage = packageRef.current;
    const previewToken = preview.previewToken;
    pending.current = true;
    setBusy('import');
    setError('');
    setNotice('');
    try {
      const result = await configurationTransferApi.import({
        package: selectedPackage,
        mode,
        previewToken,
      });
      if (!active.current || handleAuthorizationFailure(result.code)) return;
      setPreview(undefined);
      if (result.success && result.data) {
        packageRef.current = undefined;
        setFileName('');
        setNotice(
          `配置导入完成：新增 ${result.data.created} 项，更新 ${result.data.updated} 项。导入项均已停用，请核对后手动启用。`,
        );
      } else {
        setError(
          result.success
            ? '服务器未返回有效的导入结果，请先核验配置。'
            : result.message || '导入失败，请重新预览后再操作。',
        );
        if (result.success || uncertainCodes.has(result.code))
          setUncertain(true);
      }
    } catch {
      if (active.current) {
        setPreview(undefined);
        setUncertain(true);
        setError('导入请求的结果暂时无法确认。');
      }
    } finally {
      pending.current = false;
      if (active.current) {
        setBusy(undefined);
        setConfirmation(undefined);
      }
    }
  };

  if (expired)
    return (
      <Result
        status="warning"
        title={
          expired === 'session'
            ? '登录已失效，已清除待导入配置，请重新登录。'
            : '当前账号已无配置导入导出权限，已清除待导入配置。'
        }
      />
    );
  const canImport =
    preview?.canImport &&
    Boolean(preview.previewToken) &&
    preview.mode === mode &&
    !uncertain;
  return (
    <PageContainer
      title="配置导入导出"
      subTitle="迁移云账号、部署目标、计划任务、邮件、到期提醒及 MCP 非秘密配置"
    >
      <Alert
        type="warning"
        showIcon
        title="JSON 文件包含明文凭据，请仅在可信环境中保存和传递。"
        description="导入的云账号、部署目标、计划任务、邮件和到期提醒设置均会停用；MCP 服务关闭、公开地址清空，客户端与调用规则停用。请在目标实例核对后逐项启用。"
        style={{ marginBottom: 16 }}
      />
      <Alert
        type="info"
        showIcon
        title="MCP 只迁移服务公开设置、停用客户端和调用规则。"
        description="不迁移 OAuth 客户端秘密、令牌、有效授权或调用历史；账号和部署目标引用由服务器重新映射。导入后必须重新绑定本地用户、核对资源范围，机密客户端还需轮换新秘密。"
        style={{ marginBottom: 16 }}
      />
      {error && (
        <Alert
          type="error"
          showIcon
          title={error}
          style={{ marginBottom: 16 }}
        />
      )}
      {notice && (
        <Alert
          type="success"
          showIcon
          title={notice}
          style={{ marginBottom: 16 }}
        />
      )}
      {uncertain && (
        <Alert
          type="warning"
          showIcon
          title="导入结果待核验"
          description="请先检查现有配置及审计记录，确认结果后重新进入本页操作；当前页面不会再次提交导入。"
          style={{ marginBottom: 16 }}
        />
      )}
      <Card title="导出配置" style={{ marginBottom: 16 }}>
        <Typography.Paragraph>
          导出配置及其明文凭据，用于在其他实例中导入。
        </Typography.Paragraph>
        <Button
          disabled={Boolean(busy)}
          onClick={() => setConfirmation('export')}
        >
          导出 JSON 配置
        </Button>
      </Card>
      <Card title="导入配置">
        <Typography.Paragraph>
          选择本系统导出的 JSON 文件（最多 5 MiB），预览确认后再导入。
        </Typography.Paragraph>
        <Upload
          accept=".json,application/json"
          showUploadList={false}
          maxCount={1}
          disabled={Boolean(busy) || uncertain}
          beforeUpload={(file) => {
            void selectFile(file);
            return Upload.LIST_IGNORE;
          }}
        >
          <Button disabled={Boolean(busy) || uncertain}>选择 JSON 文件</Button>
        </Upload>
        <Typography.Paragraph style={{ marginTop: 12 }}>
          {fileName ? `已选择：${fileName}` : '尚未选择配置文件'}
        </Typography.Paragraph>
        <fieldset style={{ border: 0, padding: 0, marginBottom: 16 }}>
          <legend>导入方式</legend>
          <Radio.Group
            value={mode}
            disabled={Boolean(busy) || uncertain}
            onChange={(event) => changeMode(event.target.value)}
            options={[
              { label: '仅新增（同名冲突时阻止导入）', value: 'CreateOnly' },
              { label: '按名称更新已有配置', value: 'UpdateByName' },
            ]}
          />
        </fieldset>
        <Button
          onClick={() => void previewImport()}
          loading={busy === 'preview'}
          disabled={!fileName || Boolean(busy) || uncertain}
        >
          预览导入
        </Button>
        {preview && (
          <div style={{ marginTop: 16 }}>
            <Typography.Paragraph>
              预览：新增 {preview.created} 项，更新 {preview.updated} 项，冲突{' '}
              {preview.conflicts} 项。
            </Typography.Paragraph>
            {preview.errors.map((item) => (
              <Alert
                key={`${item.path}-${item.message}`}
                type="error"
                title={`${item.path}：${item.message}`}
                style={{ marginBottom: 8 }}
              />
            ))}
            <Table<ConfigurationPreviewItem & { key: number }>
              size="small"
              pagination={{ pageSize: 10, hideOnSinglePage: true }}
              dataSource={preview.items.map((item, key) => ({ ...item, key }))}
              columns={[
                {
                  title: '类型',
                  dataIndex: 'kind',
                  render: (kind: ConfigurationPreviewItem['kind']) =>
                    kindNames[kind],
                },
                { title: '名称', dataIndex: 'name' },
                {
                  title: '导入操作',
                  dataIndex: 'action',
                  render: (action: ConfigurationPreviewItem['action']) =>
                    actionNames[action],
                },
              ]}
            />
            {!preview.canImport && (
              <Typography.Paragraph type="danger">
                存在冲突或校验错误，请调整文件或导入方式后重新预览。
              </Typography.Paragraph>
            )}
            <Button
              type="primary"
              disabled={!canImport || Boolean(busy)}
              onClick={() => setConfirmation('import')}
            >
              确认导入配置
            </Button>
          </div>
        )}
      </Card>
      <Modal
        open={Boolean(confirmation)}
        title={confirmation === 'export' ? '确认导出明文配置' : '确认导入配置'}
        okText={confirmation === 'export' ? '确认导出并下载' : '执行导入'}
        cancelText="取消"
        confirmLoading={busy === 'export' || busy === 'import'}
        closable={!busy}
        keyboard={!busy}
        mask={{ closable: !busy }}
        onCancel={() => {
          if (!pending.current) setConfirmation(undefined);
        }}
        onOk={() => {
          if (confirmation === 'export') void exportPackage();
          else if (confirmation === 'import') void importPackage();
        }}
      >
        <Typography.Paragraph>
          {confirmation === 'export'
            ? '下载文件包含云账号、部署连接和邮件设置中的明文凭据。请妥善保存，不要公开分享。'
            : `即将新增 ${preview?.created ?? 0} 项，更新 ${preview?.updated ?? 0} 项配置。${mode === 'UpdateByName' ? '同名配置将被更新。' : ''}导入项均保持停用。MCP 客户端需在目标实例重新绑定用户，机密客户端需轮换新秘密。`}
        </Typography.Paragraph>
      </Modal>
    </PageContainer>
  );
}
