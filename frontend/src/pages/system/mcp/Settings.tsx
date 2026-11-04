import {
  Alert,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
} from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import { useResultMessage } from '@/components/ssl-manager';
import { mcpApi } from '@/services/ssl-manager/mcp';
import type {
  McpSettings,
  McpSettingsInput,
  McpStatus,
  McpTool,
} from '@/services/ssl-manager/mcpTypes';
import { mcpDate, mcpLines, mcpStatusText } from './presentation';

type Values = Omit<McpSettingsInput, 'allowedCidrs' | 'allowedOrigins'> & {
  cidrsText: string;
  originsText: string;
};

/** 配置状态与实际可调用状态分别读取；关闭服务仍保留管理和日志入口。 */
export default function Settings() {
  const [form] = Form.useForm<Values>();
  const showResult = useResultMessage();
  const [settings, setSettings] = useState<McpSettings>();
  const [status, setStatus] = useState<McpStatus>();
  const [tools, setTools] = useState<McpTool[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const active = useRef(true);
  const pending = useRef(false);
  const enabled = Form.useWatch('enabled', form);
  useEffect(() => {
    active.current = true;
    let current = true;
    setLoading(true);
    setError('');
    void Promise.all([mcpApi.settings(), mcpApi.status(), mcpApi.tools()])
      .then(([configuration, runtime, catalog]) => {
        if (!current) return;
        if (runtime.success && runtime.data) setStatus(runtime.data);
        if (catalog.success && catalog.data) setTools(catalog.data);
        if (!configuration.success || !configuration.data) {
          setError(configuration.message || '读取 MCP 设置失败');
          return;
        }
        setSettings(configuration.data);
        form.setFieldsValue({
          ...configuration.data,
          cidrsText: configuration.data.allowedCidrs.join('\n'),
          originsText: configuration.data.allowedOrigins.join('\n'),
        });
        const failure = [runtime, catalog].find((result) => !result.success);
        if (failure) setError(failure.message);
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
      active.current = false;
    };
  }, [form, revision]);

  const save = async ({ cidrsText, originsText, ...values }: Values) => {
    if (pending.current || !active.current || !settings || !status) return;
    pending.current = true;
    setBusy(true);
    setError('');
    try {
      const result = await mcpApi.saveSettings({
        ...values,
        systemName: values.systemName.trim(),
        enabled: status?.supported ? values.enabled : false,
        publicBaseUrl: values.publicBaseUrl.trim(),
        allowedCidrs: mcpLines(cidrsText),
        allowedOrigins: mcpLines(originsText),
        configRevision: settings.configRevision,
      });
      if (!active.current) return;
      if (showResult(result, 'MCP 设置已保存') && result.data) {
        setSettings(result.data);
        setRevision((value) => value + 1);
      } else setError(result.message);
    } finally {
      pending.current = false;
      if (active.current) setBusy(false);
    }
  };

  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      {error && <Alert type="error" showIcon title={error} />}
      <Card
        title="实际接入状态"
        extra={
          <Button
            loading={loading}
            disabled={busy}
            onClick={() => setRevision((value) => value + 1)}
          >
            重新读取设置与状态
          </Button>
        }
      >
        {status ? (
          <>
            <Alert
              type={
                status.supported && (status.apiKeyReady || status.oAuthReady)
                  ? 'info'
                  : 'warning'
              }
              title={mcpStatusText(status.state)}
              description={status.message}
              showIcon
              style={{ marginBottom: 16 }}
            />
            <Descriptions
              size="small"
              column={2}
              items={[
                {
                  key: 'systemName',
                  label: '系统名称',
                  children:
                    status.systemName ||
                    settings?.systemName ||
                    'Free SSL Manager',
                },
                {
                  key: 'instanceId',
                  label: '系统实例 ID',
                  children:
                    status.instanceId ||
                    settings?.instanceId ||
                    '保存设置后生成',
                },
                {
                  key: 'apiKey',
                  label: 'API Key 接入',
                  children: status.apiKeyReady
                    ? '可使用（无需 OAuth 证书）'
                    : '当前环境不可用',
                },
                {
                  key: 'url',
                  label: 'MCP 地址',
                  children: status.mcpUrl || '尚未配置公开 HTTPS 地址',
                },
                {
                  key: 'auth',
                  label: 'OAuth 状态',
                  children: status.oAuthReady
                    ? '已配置'
                    : '未就绪（不影响 API Key 接入）',
                },
                {
                  key: 'protocol',
                  label: '协议版本',
                  children: status.protocolVersions.join('、') || '—',
                },
                {
                  key: 'sdk',
                  label: 'SDK 版本',
                  children: status.sdkVersion || '—',
                },
                {
                  key: 'updated',
                  label: '配置更新时间',
                  children: mcpDate(settings?.updatedAtUtc),
                },
              ]}
            />
          </>
        ) : (
          <span>正在读取实际状态；尚未确认服务可调用。</span>
        )}
      </Card>
      <Card title="服务与全局限制">
        <Alert
          type="info"
          showIcon
          title="服务默认关闭，工具和来源白名单为空时拒绝调用。"
          description="API Key 可直接调用，无需 OAuth 证书。实际权限还需同时满足绑定用户角色、scope、客户端规则及资源范围；仅打开服务开关不会获得业务权限。"
          style={{ marginBottom: 16 }}
        />
        <Spin spinning={loading}>
          <Form<Values>
            form={form}
            layout="vertical"
            disabled={loading || busy || !settings || !status}
            onFinish={save}
          >
            <Form.Item
              name="systemName"
              label="系统名称"
              extra="为不同系统或环境设置可辨识的名称，例如“生产证书中心”。Agent 会看到该名称和独立实例 ID。"
              rules={[
                { required: true, whitespace: true, message: '请填写系统名称' },
                { max: 100 },
                {
                  pattern: /^[^\p{Cc}]+$/u,
                  message: '系统名称不能含控制字符',
                },
              ]}
            >
              <Input maxLength={100} placeholder="Free SSL Manager" />
            </Form.Item>
            <Form.Item
              name="enabled"
              label="启用 MCP 服务"
              valuePropName="checked"
              extra={
                !status?.supported
                  ? status?.message || '当前运行环境尚未确认支持 MCP。'
                  : '保存后立即影响新调用；已提交业务任务按执行阶段复核。'
              }
            >
              <Switch disabled={!status?.supported} />
            </Form.Item>
            <Form.Item
              name="publicBaseUrl"
              label="公开 HTTPS 基址"
              rules={[
                { required: !!enabled, message: '启用前请填写公开 HTTPS 基址' },
                {
                  validator: async (_, value) => {
                    if (!value) return;
                    try {
                      const url = new URL(value);
                      if (
                        url.protocol === 'https:' &&
                        url.pathname === '/' &&
                        !url.username &&
                        !url.password &&
                        !url.search &&
                        !url.hash
                      )
                        return;
                    } catch {
                      /* 统一展示校验失败。 */
                    }
                    throw new Error(
                      '请输入不含账号、查询参数和片段的 HTTPS 地址',
                    );
                  },
                },
              ]}
            >
              <Input placeholder="https://ssl.example.com" maxLength={2048} />
            </Form.Item>
            <Form.Item
              name="mode"
              label="调用模式"
              rules={[{ required: true }]}
            >
              <Select
                options={[
                  { value: 'ReadOnly', label: '只读' },
                  {
                    value: 'ControlledWrite',
                    label: '受控写入（需显式授权及审批）',
                  },
                ]}
              />
            </Form.Item>
            <Form.Item
              name="allowedTools"
              label="全局允许工具"
              extra="只允许从服务端实际工具目录选择；留空拒绝所有工具。"
            >
              <Select
                mode="multiple"
                showSearch={{ optionFilterProp: 'label' }}
                options={tools.map((tool) => ({
                  value: tool.name,
                  label: `${tool.title} · ${tool.readOnly ? '查询' : '受控操作'} · ${tool.name}`,
                }))}
              />
            </Form.Item>
            <Form.Item
              name="cidrsText"
              label="全局来源 IP / CIDR"
              extra="每行一项，支持 IPv4 / IPv6；留空拒绝所有来源。仅信任服务器配置的代理链。"
            >
              <Input.TextArea rows={3} placeholder="192.0.2.10/32" />
            </Form.Item>
            <Form.Item
              name="originsText"
              label="允许的浏览器 Origin"
              extra="每行一个完整源地址。合法非浏览器客户端可不携带 Origin；Origin 不代替 OAuth / API Key 认证。"
            >
              <Input.TextArea
                rows={2}
                placeholder="https://client.example.com"
              />
            </Form.Item>
            <Space align="start" wrap>
              <Form.Item
                name="rateLimitPerMinute"
                label="每客户端每分钟调用上限"
                rules={[{ required: true }]}
              >
                <InputNumber min={1} max={600} />
              </Form.Item>
              <Form.Item
                name="maxConcurrentCalls"
                label="每客户端并发上限"
                rules={[{ required: true }]}
              >
                <InputNumber min={1} max={32} />
              </Form.Item>
              <Form.Item
                name="logRetentionDays"
                label="调用日志保留天数"
                rules={[{ required: true }]}
              >
                <InputNumber min={1} max={365} />
              </Form.Item>
            </Space>
            <div>
              <Button type="primary" htmlType="submit" loading={busy}>
                保存 MCP 设置
              </Button>
            </div>
          </Form>
        </Spin>
      </Card>
      <Card title="实际工具目录">
        {tools.map((tool) => (
          <div
            key={tool.name}
            style={{ padding: '8px 0', borderBottom: '1px solid #f0f0f0' }}
          >
            <Tag color={tool.readOnly ? 'blue' : 'orange'}>
              {tool.readOnly ? '查询' : '受控操作'}
            </Tag>
            <strong>{tool.title}</strong> <code>{tool.name}</code>
            <div style={{ marginTop: 4 }}>{tool.description}</div>
          </div>
        ))}
      </Card>
    </Space>
  );
}
