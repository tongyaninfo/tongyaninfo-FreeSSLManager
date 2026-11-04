import {
  Alert,
  Button,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd';
import dayjs, { type Dayjs } from 'dayjs';
import React, { useEffect, useRef, useState } from 'react';
import { useResultMessage } from '@/components/ssl-manager';
import { userApi } from '@/services/ssl-manager/api';
import { mcpApi } from '@/services/ssl-manager/mcp';
import type {
  McpClient,
  McpClientInput,
  McpConnectionProfile,
  McpSecret,
} from '@/services/ssl-manager/mcpTypes';
import type { ManagedUser } from '@/services/ssl-manager/types';
import { mcpConnectionName, mcpDate, mcpLines } from './presentation';
import ApiKeys from './ApiKeys';

type Values = Omit<McpClientInput, 'redirectUris' | 'expiresAtUtc'> & {
  redirectText: string;
  expiresAt?: Dayjs;
};

/** 连接模板逐字段构造，防止将一次展示的客户端秘密混入导出内容。 */
export function connectionTemplate(
  profile: McpConnectionProfile,
  clientType?: McpClientInput['clientType'],
) {
  return {
    name: mcpConnectionName(profile.systemName, profile.instanceId),
    systemName: profile.systemName,
    instanceId: profile.instanceId,
    url: profile.mcpUrl,
    transport: profile.transport,
    oauth: {
      clientId: profile.clientId,
      grantType: profile.grantType,
      scopes: profile.scopes,
      authorizationUrl: profile.authorizationUrl,
      tokenUrl: profile.tokenUrl,
      ...(clientType === 'confidential' ||
      profile.grantType === 'client_credentials'
        ? { clientSecretEnv: 'MCP_CLIENT_SECRET' }
        : {}),
    },
  };
}

export default function Clients({
  onConfigureRules,
}: {
  onConfigureRules: (id: string) => void;
}) {
  const [form] = Form.useForm<Values>();
  const showResult = useResultMessage();
  const [clients, setClients] = useState<McpClient[]>([]);
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [usersError, setUsersError] = useState('');
  const [editing, setEditing] = useState<McpClient>();
  const [open, setOpen] = useState(false);
  const [secret, setSecret] = useState<McpSecret>();
  const [profile, setProfile] = useState<McpConnectionProfile>();
  const [keyClient, setKeyClient] = useState<McpClient>();
  const [creatingForApiKey, setCreatingForApiKey] = useState(false);
  const [profileClientType, setProfileClientType] =
    useState<McpClientInput['clientType']>();
  const active = useRef(true);
  const pending = useRef(false);
  const clientType = Form.useWatch('clientType', form);
  const grantType = Form.useWatch('grantType', form);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      form.resetFields();
    };
  }, [form]);
  useEffect(() => {
    let current = true;
    setLoading(true);
    void mcpApi
      .clients({ page, pageSize, search })
      .then((result) => {
        if (!current) return;
        setError(result.success ? '' : result.message);
        if (result.success && result.data) {
          setClients(result.data.items);
          setTotal(result.data.total);
        }
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [page, pageSize, search, revision]);
  useEffect(() => {
    let current = true;
    setUsersError('');
    const load = async () => {
      const all: ManagedUser[] = [];
      for (let currentPage = 1; ; currentPage++) {
        const result = await userApi.list({ page: currentPage, pageSize: 100 });
        if (!current) return;
        if (!result.success || !result.data) {
          setUsersError(result.message || '读取绑定用户失败');
          return;
        }
        all.push(...result.data.items);
        if (all.length >= result.data.total || !result.data.items.length) break;
      }
      setUsers(all);
    };
    void load();
    return () => {
      current = false;
    };
  }, [revision]);

  const edit = (client?: McpClient, forApiKey = false) => {
    setEditing(client);
    setCreatingForApiKey(forApiKey);
    form.resetFields();
    form.setFieldsValue(
      client
        ? {
            ...client,
            redirectText: client.redirectUris.join('\n'),
            expiresAt: client.expiresAtUtc
              ? dayjs(client.expiresAtUtc)
              : undefined,
          }
        : {
            name: '',
            clientType: forApiKey ? 'confidential' : 'public',
            grantType: forApiKey ? 'client_credentials' : 'authorization_code',
            boundUserId: '',
            scopes: ['mcp.read'],
            redirectText: '',
          },
    );
    setOpen(true);
  };
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
  const save = async ({ redirectText, expiresAt, ...values }: Values) =>
    perform(async () => {
      const input = {
        ...values,
        name: values.name.trim(),
        redirectUris: mcpLines(redirectText),
        expiresAtUtc: expiresAt?.toISOString() || null,
        configRevision: editing?.configRevision,
      };
      if (editing) {
        const result = await mcpApi.updateClient(editing.id, input);
        if (!active.current) return;
        if (!showResult(result, '客户端已保存')) {
          setError(result.message);
          return;
        }
      } else {
        const result = await mcpApi.createClient(input);
        if (!active.current) return;
        if (!showResult(result, '客户端已创建，默认为停用')) {
          setError(result.message);
          return;
        }
        if (creatingForApiKey && result.data) setKeyClient(result.data.client);
        else if (result.data?.clientSecret)
          setSecret({
            clientId: result.data.client.clientId,
            clientSecret: result.data.clientSecret,
          });
      }
      setOpen(false);
      form.resetFields();
      setRevision((value) => value + 1);
    });

  return (
    <>
      <Alert
        type="info"
        showIcon
        title="客户端绑定现有用户，不改变该用户角色。"
        description="支持给现有客户端创建 API Key，第三方 Agent 直接携带密钥调用，无需配置 OAuth 证书。OAuth 公开客户端使用授权码 / PKCE，机器客户端使用 client_credentials。客户端创建后保持停用，核对绑定用户与白名单后启用。"
        style={{ marginBottom: 16 }}
      />
      {(error || usersError) && (
        <Alert
          type="error"
          title={error || usersError}
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}
      <Space wrap style={{ marginBottom: 16 }}>
        <Input.Search
          aria-label="搜索 MCP 客户端"
          placeholder="名称 / Client ID"
          onSearch={(value) => {
            setSearch(value);
            setPage(1);
          }}
          style={{ width: 300 }}
          allowClear
        />
        <Button type="primary" disabled={busy} onClick={() => edit()}>
          新增客户端
        </Button>
        <Button disabled={busy} onClick={() => edit(undefined, true)}>
          新增 API Key 客户端
        </Button>
        <Button
          disabled={busy}
          onClick={() => setRevision((value) => value + 1)}
        >
          刷新客户端
        </Button>
      </Space>
      <Table<McpClient>
        rowKey="id"
        loading={loading}
        dataSource={clients}
        scroll={{ x: 1150 }}
        pagination={{
          current: page,
          pageSize,
          total,
          showSizeChanger: true,
          onChange: (next, size) => {
            setPage(next);
            setPageSize(size);
          },
        }}
        columns={[
          {
            title: '名称 / Client ID',
            width: 240,
            render: (_, client) => (
              <>
                <strong>{client.name}</strong>
                <div>
                  <Typography.Text copyable>{client.clientId}</Typography.Text>
                </div>
              </>
            ),
          },
          {
            title: '类型 / 流程',
            width: 175,
            render: (_, client) => (
              <>
                {client.clientType === 'public' ? '公开客户端' : '机密客户端'}
                <div>
                  {client.grantType === 'authorization_code'
                    ? '授权码 / PKCE'
                    : '机器身份'}
                </div>
              </>
            ),
          },
          {
            title: '绑定身份',
            width: 180,
            render: (_, client) => {
              const user = users.find((item) => item.id === client.boundUserId);
              return user
                ? `${user.displayName || user.username}（${user.role === 'admin' ? '管理员' : '只读用户'}）`
                : client.boundUserId || '待重新绑定本地用户';
            },
          },
          {
            title: '状态',
            width: 90,
            render: (_, client) => (
              <Tag color={client.enabled ? 'success' : 'default'}>
                {client.enabled ? '启用' : '停用'}
              </Tag>
            ),
          },
          {
            title: '到期 / 最近调用',
            width: 190,
            render: (_, client) => (
              <>
                {mcpDate(client.expiresAtUtc)}
                <div>{mcpDate(client.lastUsedAtUtc)}</div>
              </>
            ),
          },
          {
            title: '操作',
            width: 350,
            render: (_, client) => (
              <Space wrap>
                <Button
                  type="link"
                  disabled={busy}
                  onClick={() => setKeyClient(client)}
                >
                  API Key
                </Button>
                <Button
                  type="link"
                  disabled={busy}
                  onClick={() => edit(client)}
                >
                  编辑
                </Button>
                <Button
                  type="link"
                  disabled={busy}
                  onClick={() => onConfigureRules(client.id)}
                >
                  白名单
                </Button>
                <Button
                  type="link"
                  disabled={
                    busy ||
                    (!client.enabled &&
                      !users.some(
                        (user) =>
                          user.id === client.boundUserId && user.enabled,
                      ))
                  }
                  title={
                    !client.boundUserId
                      ? '请先编辑客户端并重新绑定本地用户'
                      : undefined
                  }
                  onClick={() =>
                    void perform(async () => {
                      const result = await mcpApi.clientStatus(
                        client.id,
                        !client.enabled,
                        client.configRevision,
                      );
                      if (!active.current) return;
                      if (showResult(result)) setRevision((value) => value + 1);
                      else setError(result.message);
                    })
                  }
                >
                  {client.enabled ? '停用' : '启用'}
                </Button>
                <Button
                  type="link"
                  disabled={busy}
                  onClick={() =>
                    void perform(async () => {
                      const result = await mcpApi.connectionProfile(client.id);
                      if (!active.current) return;
                      if (result.success && result.data) {
                        setProfileClientType(client.clientType);
                        setProfile(result.data);
                      } else setError(result.message);
                    })
                  }
                >
                  连接模板
                </Button>
                {client.clientType === 'confidential' && (
                  <Button
                    type="link"
                    disabled={busy}
                    onClick={() =>
                      Modal.confirm({
                        title: '轮换此客户端秘密？',
                        content:
                          '旧秘密将失效。新秘密只在本次响应展示，请准备好安全保存。',
                        okText: '轮换秘密',
                        cancelText: '取消',
                        onOk: () =>
                          perform(async () => {
                            const result = await mcpApi.rotateSecret(client.id);
                            if (!active.current) return;
                            if (result.success && result.data) {
                              setSecret(result.data);
                              setRevision((value) => value + 1);
                            } else setError(result.message);
                          }),
                      })
                    }
                  >
                    轮换秘密
                  </Button>
                )}
                <Button
                  type="link"
                  danger
                  disabled={busy}
                  onClick={() =>
                    Modal.confirm({
                      title: '撤销此客户端的 OAuth 授权和全部 API Key？',
                      content:
                        'OAuth 会话与 API Key 均立即失效，待执行操作将失去授权；此操作不变更绑定用户角色。',
                      okText: '撤销授权',
                      cancelText: '取消',
                      onOk: () =>
                        perform(async () => {
                          const result = await mcpApi.revokeClient(client.id);
                          if (!active.current) return;
                          if (showResult(result, '授权已撤销'))
                            setRevision((value) => value + 1);
                          else setError(result.message);
                        }),
                    })
                  }
                >
                  撤销授权
                </Button>
              </Space>
            ),
          },
        ]}
      />
      <Drawer
        title={`${keyClient?.name || ''} · API Key 管理`}
        open={!!keyClient}
        onClose={() => setKeyClient(undefined)}
        size={1100}
        destroyOnHidden
      >
        {keyClient && (
          <ApiKeys
            key={keyClient.id}
            client={keyClient}
            onConfigureRules={() => {
              setKeyClient(undefined);
              onConfigureRules(keyClient.id);
            }}
          />
        )}
      </Drawer>
      <Modal
        title={editing ? '编辑 MCP 客户端' : '新增 MCP 客户端'}
        open={open}
        onCancel={() => {
          setOpen(false);
          form.resetFields();
        }}
        onOk={() => form.submit()}
        confirmLoading={busy}
        okText="保存客户端"
        cancelText="取消"
        destroyOnHidden
        width={650}
      >
        {editing && (
          <Alert
            type="warning"
            showIcon
            title="保存客户端资料会撤销现有 OAuth 授权和全部 API Key。"
            description="调整名称、绑定用户、scope 等资料后，需要重新创建 Key 或重新授权；仅调整白名单会实时收敛权限，不撤销密钥。"
            style={{ marginBottom: 16 }}
          />
        )}
        {creatingForApiKey && (
          <Alert
            type="info"
            showIcon
            title="先创建受限机器客户端，保存后继续创建 API Key。"
            description="无需填写回调地址或配置 OAuth 证书；Key 继承下方绑定用户和 scope，再通过客户端白名单限制可调用的工具和资源。"
            style={{ marginBottom: 16 }}
          />
        )}
        {editing && !editing.boundUserId && (
          <Alert
            type="warning"
            showIcon
            title="迁移后的客户端尚未绑定本地用户，不能启用或取得业务权限。"
            description="请在下方选择本实例的有效用户后保存；机密客户端需要另外轮换新秘密。"
            style={{ marginBottom: 16 }}
          />
        )}
        <Form<Values>
          form={form}
          layout="vertical"
          onFinish={save}
          disabled={busy}
          autoComplete="off"
        >
          <Form.Item
            name="name"
            label="客户端名称"
            rules={[{ required: true, whitespace: true }]}
          >
            <Input maxLength={100} />
          </Form.Item>
          <Form.Item
            name="clientType"
            label="客户端类型"
            rules={[{ required: true }]}
          >
            <Select
              disabled={!!editing}
              options={[
                { value: 'public', label: '公开客户端（桌面 / 浏览器，PKCE）' },
                {
                  value: 'confidential',
                  label: '机密客户端（服务端安全保存秘密）',
                },
              ]}
              onChange={(value) => {
                if (value === 'public')
                  form.setFieldValue('grantType', 'authorization_code');
              }}
            />
          </Form.Item>
          <Form.Item
            name="grantType"
            label="授权流程"
            rules={[{ required: true }]}
          >
            <Select
              disabled={!!editing}
              onChange={(value) => {
                if (value === 'client_credentials')
                  form.setFieldValue('redirectText', '');
              }}
              options={[
                {
                  value: 'authorization_code',
                  label: '交互授权码 / PKCE S256',
                },
                ...(clientType === 'confidential'
                  ? [
                      {
                        value: 'client_credentials',
                        label: '机器 client_credentials',
                      },
                    ]
                  : []),
              ]}
            />
          </Form.Item>
          <Form.Item
            name="boundUserId"
            label="绑定现有用户"
            rules={[{ required: true, message: '请选择有效用户' }]}
            extra="调用权限不会超过此用户的当前角色；管理员审批不会将调用身份提升为管理员。"
          >
            <Select
              showSearch={{ optionFilterProp: 'label' }}
              options={users.map((user) => ({
                value: user.id,
                disabled: !user.enabled,
                label: `${user.displayName || user.username} · ${user.role === 'admin' ? '管理员' : '只读用户'}${user.enabled ? '' : ' · 已停用'}`,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="scopes"
            label="允许 scope"
            rules={[{ required: true, message: '至少选择一个 scope' }]}
          >
            <Select
              mode="multiple"
              options={[
                { value: 'mcp.read', label: 'mcp.read · 查询' },
                { value: 'mcp.write', label: 'mcp.write · 受控操作' },
              ]}
            />
          </Form.Item>
          <Form.Item
            name="redirectText"
            label="回调地址"
            rules={[
              {
                required: grantType === 'authorization_code',
                message: '交互客户端请填写精确回调地址',
              },
            ]}
            extra="每行一个预注册地址，必须与客户端实际回调完全一致；机器流程不使用回调。"
          >
            <Input.TextArea
              rows={3}
              disabled={grantType === 'client_credentials'}
            />
          </Form.Item>
          <Form.Item
            name="expiresAt"
            label="客户端到期时间（当前浏览器时区）"
            extra="留空代表未配置固定期限，仍受用户、客户端状态与令牌期限限制。"
          >
            <DatePicker showTime style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        title="客户端秘密：仅显示一次"
        open={!!secret}
        onCancel={() => setSecret(undefined)}
        footer={
          <Button type="primary" onClick={() => setSecret(undefined)}>
            已安全保存，关闭
          </Button>
        }
        destroyOnHidden
      >
        <Alert
          type="warning"
          showIcon
          title="关闭、切换标签或会话过期后将清除，列表不提供回读。"
          style={{ marginBottom: 16 }}
        />
        <Descriptions
          column={1}
          items={[
            { key: 'client', label: 'Client ID', children: secret?.clientId },
          ]}
        />
        <Input.Password
          aria-label="一次展示的客户端秘密"
          value={secret?.clientSecret || ''}
          readOnly
          autoComplete="off"
        />
      </Modal>
      <Modal
        title={`${profile?.systemName || 'Free SSL Manager'} · OAuth 接入参数`}
        open={!!profile}
        onCancel={() => setProfile(undefined)}
        footer={
          <Space>
            <Button
              onClick={() => {
                if (!profile) return;
                const blob = new Blob(
                  [
                    JSON.stringify(
                      connectionTemplate(profile, profileClientType),
                      null,
                      2,
                    ),
                  ],
                  { type: 'application/json' },
                );
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = 'mcp-connection-profile.json';
                link.click();
                URL.revokeObjectURL(url);
              }}
            >
              下载连接模板
            </Button>
            <Button onClick={() => setProfile(undefined)}>关闭</Button>
          </Space>
        }
        width={750}
        destroyOnHidden
      >
        <Descriptions
          column={1}
          items={[
            { key: 'system', label: '系统名称', children: profile?.systemName },
            {
              key: 'instance',
              label: '系统实例 ID',
              children: profile?.instanceId,
            },
            { key: 'url', label: 'MCP 地址', children: profile?.mcpUrl },
          ]}
        />
        <Alert
          type="info"
          showIcon
          title="Agent 应先调用 ssl_system_status_get 核对系统名称与实例 ID。"
          description="所有受控写工具都需要额外传 systemInstanceId，必须与此系统实例 ID 完全一致；它不是云平台证书的 instanceId。"
          style={{ marginBottom: 16 }}
        />
        <Alert
          type="info"
          title="这是通用 OAuth 接入参数摘要，需要按所用 Agent 的 OAuth 支持适配。"
          description="不作为可直接导入全部客户端的配置文件。客户端秘密通过环境变量单独配置，access token 由 OAuth 获取；使用 API Key 时请打开该客户端的 API Key 管理。"
          style={{ marginBottom: 16 }}
        />
        <Typography.Paragraph copyable>
          <pre style={{ whiteSpace: 'pre-wrap' }}>
            {profile
              ? JSON.stringify(
                  connectionTemplate(profile, profileClientType),
                  null,
                  2,
                )
              : ''}
          </pre>
        </Typography.Paragraph>
      </Modal>
    </>
  );
}
