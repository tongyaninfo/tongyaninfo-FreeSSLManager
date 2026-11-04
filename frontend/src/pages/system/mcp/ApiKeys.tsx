import {
  Alert,
  Button,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd';
import dayjs, { type Dayjs } from 'dayjs';
import React, { useEffect, useRef, useState } from 'react';
import { useResultMessage } from '@/components/ssl-manager';
import { mcpApi } from '@/services/ssl-manager/mcp';
import type {
  McpApiKey,
  McpApiKeyCreated,
  McpClient,
} from '@/services/ssl-manager/mcpTypes';
import { mcpConnectionName, mcpDate } from './presentation';
import AgentConnection from './AgentConnection';
import { apiKeyEnvironmentName, copyMcpText } from './connectionInstructions';
export { apiKeyEnvironmentName } from './connectionInstructions';

/** 模板只含环境变量占位符，绝不混入当前一次展示的明文密钥。 */
export function apiKeyConnectionTemplate(
  mcpUrl: string,
  systemName = 'Free SSL Manager',
  instanceId = '',
) {
  const placeholder = `\${${apiKeyEnvironmentName(instanceId)}}`;
  return {
    mcpServers: {
      [mcpConnectionName(systemName, instanceId)]: {
        type: 'http',
        url: mcpUrl,
        headers: { Authorization: `Bearer ${placeholder}` },
      },
    },
  };
}

type Values = { name: string; expiresAt?: Dayjs };

/** 每个 Key 继承客户端的用户、scope 和白名单；密钥停用、轮换、撤销均由服务器立即复核。 */
export default function ApiKeys({
  client,
  onConfigureRules,
}: {
  client: McpClient;
  onConfigureRules: () => void;
}) {
  const [form] = Form.useForm<Values>();
  const showResult = useResultMessage();
  const [keys, setKeys] = useState<McpApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<McpApiKeyCreated>();
  const [copyError, setCopyError] = useState('');
  const [mcpUrl, setMcpUrl] = useState('');
  const [identity, setIdentity] = useState({
    systemName: 'Free SSL Manager',
    instanceId: '',
  });
  const active = useRef(true);
  const pending = useRef(false);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  useEffect(() => {
    let current = true;
    setLoading(true);
    void Promise.all([mcpApi.apiKeys(client.id), mcpApi.status()])
      .then(([result, status]) => {
        if (!current) return;
        setError(result.success ? '' : result.message);
        if (result.success && result.data) setKeys(result.data);
        if (status.success && status.data) {
          setMcpUrl(status.data.mcpUrl);
          setIdentity({
            systemName: status.data.systemName,
            instanceId: status.data.instanceId,
          });
        }
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [client.id, revision]);

  const perform = async (action: () => Promise<void>) => {
    if (pending.current || !active.current) return;
    pending.current = true;
    setBusy(true);
    setError('');
    try {
      await action();
    } finally {
      pending.current = false;
      if (active.current) setBusy(false);
    }
  };
  const create = ({ name, expiresAt }: Values) =>
    perform(async () => {
      const result = await mcpApi.createApiKey(client.id, {
        name: name.trim(),
        expiresAtUtc: expiresAt?.toISOString() || null,
      });
      if (!active.current) return;
      if (result.success && result.data) {
        setSecret(result.data);
        setCopyError('');
        setCreating(false);
        form.resetFields();
        setRevision((value) => value + 1);
      } else setError(result.message);
    });
  const confirmChange = (key: McpApiKey, kind: 'rotate' | 'revoke') => {
    Modal.confirm({
      title: kind === 'rotate' ? '轮换此 API Key？' : '永久撤销此 API Key？',
      content:
        kind === 'rotate'
          ? '旧密钥立即失效，使用旧密钥准备或排队的操作将停止，需要重新准备。新密钥使用新标识且只展示一次，调用方需要更新配置。'
          : '该密钥及其待执行 MCP 操作将失去授权，撤销后不能再次启用。',
      okText: kind === 'rotate' ? '轮换 API Key' : '撤销 API Key',
      cancelText: '取消',
      onOk: () =>
        perform(async () => {
          if (kind === 'rotate') {
            const result = await mcpApi.rotateApiKey(
              key.id,
              key.configRevision,
            );
            if (!active.current) return;
            if (result.success && result.data) {
              setSecret(result.data);
              setCopyError('');
            } else {
              setError(result.message);
              return;
            }
          } else {
            const result = await mcpApi.revokeApiKey(
              key.id,
              key.configRevision,
            );
            if (!active.current) return;
            if (!showResult(result, 'API Key 已撤销')) {
              setError(result.message);
              return;
            }
          }
          setRevision((value) => value + 1);
        }),
    });
  };
  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        title="API Key 直接调用，无需 OAuth 证书或交换令牌。"
        description="请求携带 Authorization: Bearer <API_KEY>。密钥继承此客户端的绑定用户、scope 和调用白名单；客户端与服务均启用后才可调用。API Key 不授予后台登录权限。"
      />
      {!client.enabled && (
        <Alert
          type="warning"
          showIcon
          title="此客户端已停用，创建密钥后还需核对白名单并启用客户端。"
        />
      )}
      {error && <Alert type="error" showIcon title={error} />}
      <Space wrap>
        <Button
          type="primary"
          disabled={busy}
          onClick={() => {
            form.resetFields();
            setCreating(true);
          }}
        >
          创建 API Key
        </Button>
        <Button
          disabled={busy}
          onClick={() => setRevision((value) => value + 1)}
        >
          刷新密钥
        </Button>
        <Button onClick={onConfigureRules}>配置客户端白名单</Button>
      </Space>
      <Table<McpApiKey>
        rowKey="id"
        dataSource={keys}
        loading={loading}
        pagination={{ pageSize: 10 }}
        scroll={{ x: 1000 }}
        columns={[
          {
            title: '名称 / 标识',
            width: 220,
            render: (_, key) => (
              <>
                <strong>{key.name}</strong>
                <div>
                  <Typography.Text copyable>{key.id}</Typography.Text>
                </div>
                <code>{key.prefix}…</code>
              </>
            ),
          },
          {
            title: '状态',
            width: 100,
            render: (_, key) => (
              <Tag
                color={
                  key.revokedAtUtc
                    ? 'error'
                    : key.expiresAtUtc &&
                        dayjs(key.expiresAtUtc).isBefore(dayjs())
                      ? 'warning'
                      : key.enabled
                        ? 'success'
                        : 'default'
                }
              >
                {key.revokedAtUtc
                  ? '已撤销'
                  : key.expiresAtUtc &&
                      dayjs(key.expiresAtUtc).isBefore(dayjs())
                    ? '已过期'
                    : key.enabled
                      ? '启用'
                      : '停用'}
              </Tag>
            ),
          },
          {
            title: '到期 / 最近调用',
            width: 190,
            render: (_, key) => (
              <>
                {mcpDate(key.expiresAtUtc)}
                <div>{mcpDate(key.lastUsedAtUtc)}</div>
              </>
            ),
          },
          {
            title: '创建时间',
            width: 185,
            render: (_, key) => mcpDate(key.createdAtUtc),
          },
          {
            title: '操作',
            width: 260,
            render: (_, key) => (
              <Space wrap>
                <Button
                  type="link"
                  disabled={busy || !!key.revokedAtUtc}
                  onClick={() =>
                    void perform(async () => {
                      const result = await mcpApi.apiKeyStatus(
                        key.id,
                        !key.enabled,
                        key.configRevision,
                      );
                      if (!active.current) return;
                      if (showResult(result)) setRevision((value) => value + 1);
                      else setError(result.message);
                    })
                  }
                >
                  {key.enabled ? '停用密钥' : '启用密钥'}
                </Button>
                <Button
                  type="link"
                  disabled={busy || !!key.revokedAtUtc}
                  onClick={() => confirmChange(key, 'rotate')}
                >
                  轮换密钥
                </Button>
                <Button
                  type="link"
                  danger
                  disabled={busy || !!key.revokedAtUtc}
                  onClick={() => confirmChange(key, 'revoke')}
                >
                  撤销密钥
                </Button>
              </Space>
            ),
          },
        ]}
      />
      <Descriptions
        column={1}
        items={[
          { key: 'system', label: '系统名称', children: identity.systemName },
          {
            key: 'instance',
            label: '系统实例 ID',
            children: identity.instanceId || '请先保存服务设置',
          },
          {
            key: 'client',
            label: '客户端',
            children: `${client.name} / ${client.clientId}`,
          },
          {
            key: 'url',
            label: 'MCP 地址',
            children: mcpUrl || '请先在服务设置中保存 HTTP / HTTPS 服务基址',
          },
        ]}
      />
      <AgentConnection
        profile={{
          ...identity,
          mcpUrl,
          authenticationType: 'ApiKey',
          clientId: client.clientId,
        }}
      />
      <Alert
        type="warning"
        showIcon
        title="Agent 先调用 ssl_system_status_get 核对系统身份，再执行写操作。"
        description="受控写工具必须显式传 systemInstanceId，与此系统实例 ID 精确匹配；它不是云平台证书的 instanceId。请为每个系统分别配置密钥与连接名称。"
      />
      <Alert
        type="info"
        showIcon
        title="Claude Code HTTP 连接模板（.mcp.json）"
        description={`在调用方环境中设置 ${apiKeyEnvironmentName(identity.instanceId)}，再复制下方配置。每个实例使用独立环境变量；其他 Agent 需按其 HTTP 请求头配置方式适配。`}
      />
      <Typography.Paragraph
        copyable={{
          text: JSON.stringify(
            apiKeyConnectionTemplate(
              mcpUrl || 'https://ssl.example.com/mcp',
              identity.systemName,
              identity.instanceId,
            ),
            null,
            2,
          ),
        }}
      >
        <pre style={{ whiteSpace: 'pre-wrap' }}>
          {JSON.stringify(
            apiKeyConnectionTemplate(
              mcpUrl || 'https://ssl.example.com/mcp',
              identity.systemName,
              identity.instanceId,
            ),
            null,
            2,
          )}
        </pre>
      </Typography.Paragraph>
      <Typography.Paragraph
        copyable={{
          text: `curl '${mcpUrl || 'https://ssl.example.com/mcp'}' -H "Authorization: Bearer $${apiKeyEnvironmentName(identity.instanceId)}" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2026-07-28' -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ssl_system_status_get","arguments":{}}}'`,
        }}
      >
        <code>{`Authorization: Bearer $${apiKeyEnvironmentName(identity.instanceId)}`}</code>
      </Typography.Paragraph>
      <Typography.Link
        href="https://code.claude.com/docs/en/mcp#environment-variable-expansion-in-mcpjson"
        target="_blank"
        rel="noreferrer"
      >
        Claude Code 官方配置说明
      </Typography.Link>
      <Modal
        title="创建 API Key"
        open={creating}
        onCancel={() => {
          setCreating(false);
          form.resetFields();
        }}
        onOk={() => form.submit()}
        confirmLoading={busy}
        okText="创建密钥"
        cancelText="取消"
        destroyOnHidden
      >
        <Form<Values>
          form={form}
          layout="vertical"
          onFinish={create}
          disabled={busy}
          autoComplete="off"
        >
          <Form.Item
            name="name"
            label="密钥名称"
            rules={[
              {
                required: true,
                whitespace: true,
                message: '请填写便于审计识别的名称',
              },
            ]}
          >
            <Input maxLength={100} placeholder="例如：内部运维 Agent" />
          </Form.Item>
          <Form.Item
            name="expiresAt"
            label="到期时间（当前浏览器时区）"
            extra="建议设置期限；留空仍受客户端、用户状态和白名单限制。"
          >
            <DatePicker showTime style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
      <Drawer
        title="API Key：仅显示一次"
        open={!!secret}
        onClose={() => setSecret(undefined)}
        destroyOnHidden
        size={600}
        extra={
          <Button type="primary" onClick={() => setSecret(undefined)}>
            已安全保存，关闭
          </Button>
        }
      >
        <Alert
          type="warning"
          showIcon
          title="关闭窗口、切换标签或会话过期将清除明文，之后无法回读。"
          style={{ marginBottom: 16 }}
        />
        <Descriptions
          column={1}
          items={[
            { key: 'name', label: '密钥名称', children: secret?.key.name },
            { key: 'prefix', label: '密钥前缀', children: secret?.key.prefix },
          ]}
        />
        <Input.Password
          aria-label="一次展示的 API Key"
          value={secret?.apiKey || ''}
          readOnly
          autoComplete="off"
        />
        {copyError && (
          <Alert type="warning" title={copyError} style={{ marginTop: 12 }} />
        )}
        <Button
          style={{ marginTop: 12 }}
          onClick={async () => {
            if (!secret) return;
            try {
              await copyMcpText(secret.apiKey);
              setCopyError('');
            } catch {
              setCopyError('浏览器未允许复制，请在密钥框内手动复制。');
            }
          }}
        >
          复制 API Key
        </Button>
        {secret && (
          <div style={{ marginTop: 16 }}>
            <AgentConnection
              profile={{
                ...identity,
                mcpUrl,
                authenticationType: 'ApiKey',
                clientId: client.clientId,
              }}
              apiKey={secret.apiKey}
            />
          </div>
        )}
      </Drawer>
    </Space>
  );
}
