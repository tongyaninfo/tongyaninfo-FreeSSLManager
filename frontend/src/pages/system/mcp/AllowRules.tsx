import {
  Alert,
  Button,
  Card,
  Checkbox,
  DatePicker,
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
import { accountApi } from '@/services/ssl-manager/api';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import type { DeploymentTarget } from '@/services/ssl-manager/deploymentTypes';
import { mcpApi } from '@/services/ssl-manager/mcp';
import type {
  McpAllowRule,
  McpClient,
  McpTool,
} from '@/services/ssl-manager/mcpTypes';
import type { CloudAccount } from '@/services/ssl-manager/types';
import { mcpLines } from './presentation';

type Values = Omit<
  McpAllowRule,
  'domains' | 'allowedCidrs' | 'expiresAtUtc'
> & { domainsText: string; cidrsText: string; expiresAt?: Dayjs };
const emptyRule = (): McpAllowRule => ({
  toolNames: [],
  accountIds: [],
  domains: [],
  targetIds: [],
  allowedCidrs: [],
  scopes: [],
  allAccounts: false,
  allDomains: false,
  allTargets: false,
  approvalMode: 'Manual',
  enabled: true,
});

/** 修改列表只产生本地草稿；保存整组时携带服务端修订，空列表仍表示拒绝。 */
export default function AllowRules({
  initialClientId = '',
}: {
  initialClientId?: string;
}) {
  const [form] = Form.useForm<Values>();
  const showResult = useResultMessage();
  const [clients, setClients] = useState<McpClient[]>([]);
  const [tools, setTools] = useState<McpTool[]>([]);
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [targets, setTargets] = useState<DeploymentTarget[]>([]);
  const [clientId, setClientId] = useState(initialClientId);
  const [rules, setRules] = useState<McpAllowRule[]>([]);
  const [configRevision, setConfigRevision] = useState<number>();
  const [loading, setLoading] = useState(false);
  const [optionsLoading, setOptionsLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState<number>();
  const [open, setOpen] = useState(false);
  const [revision, setRevision] = useState(0);
  const active = useRef(true);
  const pending = useRef(false);
  const allAccounts = Form.useWatch('allAccounts', form);
  const allDomains = Form.useWatch('allDomains', form);
  const allTargets = Form.useWatch('allTargets', form);
  const approvalMode = Form.useWatch('approvalMode', form);
  const client = clients.find((item) => item.id === clientId);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      form.resetFields();
    };
  }, [form]);
  useEffect(() => {
    let current = true;
    const load = async () => {
      const allClients: McpClient[] = [];
      const allTargetsList: DeploymentTarget[] = [];
      const collectClients = async () => {
        for (let page = 1; ; page++) {
          const result = await mcpApi.clients({ page, pageSize: 100 });
          if (!result.success || !result.data)
            throw new Error(result.message || '客户端读取失败');
          allClients.push(...result.data.items);
          if (
            allClients.length >= result.data.total ||
            !result.data.items.length
          )
            return;
        }
      };
      const collectTargets = async () => {
        for (let page = 1; ; page++) {
          const result = await deploymentApi.targets({ page, pageSize: 200 });
          if (!result.success || !result.data)
            throw new Error(result.message || '部署目标读取失败');
          allTargetsList.push(...result.data.items);
          if (
            allTargetsList.length >= result.data.total ||
            !result.data.items.length
          )
            return;
        }
      };
      try {
        const [, , catalog, accountOptions] = await Promise.all([
          collectClients(),
          collectTargets(),
          mcpApi.tools(),
          accountApi.options(),
        ]);
        if (!current) return;
        if (!catalog.success || !accountOptions.success) {
          setError(!catalog.success ? catalog.message : accountOptions.message);
          return;
        }
        setClients(allClients);
        setTargets(allTargetsList);
        setTools(catalog.data || []);
        setAccounts(accountOptions.data || []);
      } catch (exception) {
        if (current)
          setError(
            exception instanceof Error ? exception.message : '选项读取失败',
          );
      } finally {
        if (current) setOptionsLoading(false);
      }
    };
    void load();
    return () => {
      current = false;
    };
  }, []);
  useEffect(() => {
    let current = true;
    setRules([]);
    setConfigRevision(undefined);
    setDirty(false);
    setOpen(false);
    if (!clientId) return;
    setLoading(true);
    void mcpApi
      .rules(clientId)
      .then((result) => {
        if (!current) return;
        if (result.success && result.data) {
          setRules(result.data.rules);
          setConfigRevision(result.data.configRevision);
          setError('');
        } else setError(result.message);
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [clientId, revision]);

  const edit = (index?: number) => {
    setEditing(index);
    const rule = index === undefined ? emptyRule() : rules[index];
    form.resetFields();
    form.setFieldsValue({
      ...rule,
      domainsText: rule.domains.join('\n'),
      cidrsText: rule.allowedCidrs.join('\n'),
      expiresAt: rule.expiresAtUtc ? dayjs(rule.expiresAtUtc) : undefined,
    });
    setOpen(true);
  };
  const applyDraft = ({
    domainsText,
    cidrsText,
    expiresAt,
    ...values
  }: Values) => {
    const rule: McpAllowRule = {
      ...values,
      domains: mcpLines(domainsText).map((domain) =>
        domain.toLowerCase().replace(/\.$/, ''),
      ),
      allowedCidrs: mcpLines(cidrsText),
      expiresAtUtc: expiresAt?.toISOString() || null,
    };
    setRules((items) =>
      editing === undefined
        ? [...items, rule]
        : items.map((item, index) => (index === editing ? rule : item)),
    );
    setDirty(true);
    setOpen(false);
    form.resetFields();
  };
  const save = async () => {
    if (
      pending.current ||
      !active.current ||
      configRevision === undefined ||
      !clientId
    )
      return;
    pending.current = true;
    setBusy(true);
    setError('');
    try {
      const result = await mcpApi.saveRules(clientId, {
        rules,
        configRevision,
      });
      if (!active.current) return;
      if (showResult(result, '调用白名单已保存') && result.data) {
        setRules(result.data.rules);
        setConfigRevision(result.data.configRevision);
        setDirty(false);
      } else setError(result.message);
    } finally {
      pending.current = false;
      if (active.current) setBusy(false);
    }
  };

  return (
    <>
      <Alert
        type="info"
        showIcon
        title="单条规则内取交集，多条允许规则取并集；不能突破全局限制和用户角色。"
        description="空工具、空来源、空适用资源范围均不隐含全部。跨账号、域名和部署目标会在每次调用时复核；白名单变更立即影响后续调用。"
        style={{ marginBottom: 16 }}
      />
      {error && (
        <Alert
          type="error"
          title={error}
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}
      <Space wrap style={{ marginBottom: 16 }}>
        <Select
          aria-label="白名单客户端"
          placeholder="选择要配置的客户端"
          value={clientId || undefined}
          style={{ minWidth: 340 }}
          loading={optionsLoading}
          disabled={busy}
          showSearch={{ optionFilterProp: 'label' }}
          options={clients.map((item) => ({
            value: item.id,
            label: `${item.name} · ${item.clientId}${item.enabled ? '' : ' · 停用'}`,
          }))}
          onChange={(id) => {
            if (!dirty) {
              setClientId(id);
              return;
            }
            Modal.confirm({
              title: '切换客户端并放弃尚未保存的规则？',
              okText: '切换',
              cancelText: '继续编辑',
              onOk: () => {
                if (active.current) setClientId(id);
              },
            });
          }}
        />
        <Button
          disabled={
            !clientId || busy || loading || configRevision === undefined
          }
          onClick={() => edit()}
        >
          添加允许规则
        </Button>
        <Button
          loading={busy}
          type="primary"
          disabled={!dirty || loading || configRevision === undefined}
          onClick={() => {
            if (
              rules.some(
                (rule) =>
                  rule.allAccounts ||
                  rule.allDomains ||
                  rule.allTargets ||
                  rule.approvalMode === 'Preauthorized',
              )
            )
              Modal.confirm({
                title: '保存含显式全部范围或预授权的规则？',
                content:
                  '请核对已选择的工具、全部资源范围和预授权策略。预授权允许受控操作跳过逐次人工批准，但仍受当前用户和资源权限限制。',
                okText: '确认范围并保存',
                cancelText: '返回核对',
                onOk: save,
              });
            else void save();
          }}
        >
          保存调用白名单
        </Button>
        <Button
          disabled={!clientId || busy}
          onClick={() => setRevision((value) => value + 1)}
        >
          重新读取
        </Button>
      </Space>
      {client && (
        <Typography.Paragraph type="secondary">
          当前客户端：{client.name}；绑定用户 ID：
          {client.boundUserId || '交互登录用户'}；允许 scope：
          {client.scopes.join('、') || '无'}；配置修订：{configRevision ?? '—'}
          。此页面不修改用户角色。
        </Typography.Paragraph>
      )}
      {!rules.length && clientId && !loading && (
        <Alert
          type="warning"
          showIcon
          title="当前没有允许规则，此客户端的工具调用将被拒绝。"
          style={{ marginBottom: 16 }}
        />
      )}
      <Table<McpAllowRule & { rowIndex: number }>
        rowKey="rowIndex"
        loading={loading}
        pagination={false}
        dataSource={rules.map((rule, rowIndex) => ({ ...rule, rowIndex }))}
        columns={[
          {
            title: '工具 / scope',
            render: (_, rule) => (
              <>
                {rule.toolNames.map((name) => (
                  <Tag key={name}>
                    {tools.find((tool) => tool.name === name)?.title || name}
                  </Tag>
                ))}
                <div>{rule.scopes.join('、') || '无 scope'}</div>
              </>
            ),
          },
          {
            title: '业务资源范围',
            render: (_, rule) => (
              <>
                <div>
                  账号：
                  {rule.allAccounts
                    ? '全部（显式）'
                    : `${rule.accountIds.length} 个`}
                </div>
                <div>
                  域名：
                  {rule.allDomains
                    ? '全部（显式）'
                    : rule.domains.join('、') || '未授权'}
                </div>
                <div>
                  目标：
                  {rule.allTargets
                    ? '全部（显式）'
                    : `${rule.targetIds.length} 个`}
                </div>
              </>
            ),
          },
          {
            title: '来源 / 审批',
            render: (_, rule) => (
              <>
                {rule.allowedCidrs.join('、') || '来源全部拒绝'}
                <div>
                  {rule.approvalMode === 'Preauthorized'
                    ? '显式预授权'
                    : '管理员逐次确认'}
                </div>
                <Tag>{rule.enabled ? '启用' : '停用'}</Tag>
              </>
            ),
          },
          {
            title: '草稿操作',
            width: 155,
            render: (_, rule) => (
              <Space>
                <Button
                  type="link"
                  disabled={busy}
                  onClick={() => edit(rule.rowIndex)}
                >
                  编辑
                </Button>
                <Button
                  type="link"
                  danger
                  disabled={busy}
                  onClick={() => {
                    setRules((items) =>
                      items.filter((_, index) => index !== rule.rowIndex),
                    );
                    setDirty(true);
                  }}
                >
                  移除规则
                </Button>
              </Space>
            ),
          },
        ]}
      />
      <Modal
        title={
          editing === undefined
            ? '添加允许规则（保存整组后生效）'
            : '编辑允许规则（保存整组后生效）'
        }
        open={open}
        onCancel={() => {
          setOpen(false);
          form.resetFields();
        }}
        onOk={() => form.submit()}
        okText="更新规则草稿"
        cancelText="取消"
        destroyOnHidden
        width={780}
      >
        <Form<Values> form={form} layout="vertical" onFinish={applyDraft}>
          <Form.Item name="enabled" valuePropName="checked">
            <Checkbox>启用此规则</Checkbox>
          </Form.Item>
          <Form.Item
            name="toolNames"
            label="允许工具"
            rules={[{ required: true, message: '至少选择一个工具' }]}
          >
            <Select
              mode="multiple"
              showSearch={{ optionFilterProp: 'label' }}
              options={tools.map((tool) => ({
                value: tool.name,
                label: `${tool.title} · ${tool.readOnly ? '查询' : '受控操作'}`,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="scopes"
            label="规则 scope"
            rules={[{ required: true }]}
          >
            <Select
              mode="multiple"
              options={(client?.scopes || []).map((scope) => ({
                value: scope,
                label: scope,
              }))}
            />
          </Form.Item>
          <Card
            size="small"
            title="业务范围（只有显式勾选才代表全部）"
            style={{ marginBottom: 16 }}
          >
            <Form.Item name="allAccounts" valuePropName="checked">
              <Checkbox>显式允许全部云账号</Checkbox>
            </Form.Item>
            <Form.Item name="accountIds" label="允许云账号">
              <Select
                mode="multiple"
                disabled={!!allAccounts}
                showSearch={{ optionFilterProp: 'label' }}
                options={accounts.map((account) => ({
                  value: account.id,
                  label: `${account.name} · ${account.provider}`,
                }))}
              />
            </Form.Item>
            <Form.Item name="allDomains" valuePropName="checked">
              <Checkbox>显式允许全部域名</Checkbox>
            </Form.Item>
            <Form.Item
              name="domainsText"
              label="允许域名"
              extra="每行一个精确域名，子域规则需显式填写，例如 *.example.com；空值不代表全部。"
            >
              <Input.TextArea disabled={!!allDomains} rows={3} />
            </Form.Item>
            <Form.Item name="allTargets" valuePropName="checked">
              <Checkbox>显式允许全部部署目标</Checkbox>
            </Form.Item>
            <Form.Item name="targetIds" label="允许部署目标">
              <Select
                mode="multiple"
                disabled={!!allTargets}
                showSearch={{ optionFilterProp: 'label' }}
                options={targets.map((target) => ({
                  value: target.id,
                  label: `${target.name} · ${target.endpoint}${target.enabled ? '' : ' · 已停用'}`,
                }))}
              />
            </Form.Item>
          </Card>
          <Form.Item
            name="cidrsText"
            label="本规则允许来源 IP / CIDR"
            rules={[
              {
                required: true,
                whitespace: true,
                message: '请明确填写允许来源；留空将拒绝调用',
              },
            ]}
            extra="与全局来源限制取交集，每行一个 IPv4 / IPv6 地址或 CIDR。"
          >
            <Input.TextArea rows={3} />
          </Form.Item>
          <Form.Item
            name="approvalMode"
            label="写入审批策略"
            rules={[{ required: true }]}
          >
            <Select
              options={[
                { value: 'Manual', label: '管理员逐次核对并批准' },
                {
                  value: 'Preauthorized',
                  label: '显式预授权（仅受控自动化客户端）',
                },
              ]}
            />
          </Form.Item>
          {approvalMode === 'Preauthorized' && (
            <Alert
              type="warning"
              title="预授权会允许规则范围内的受控操作跳过逐次人工审批；保存整组前再次核对影响。"
              showIcon
              style={{ marginBottom: 16 }}
            />
          )}
          <Form.Item name="expiresAt" label="规则到期时间（当前浏览器时区）">
            <DatePicker showTime style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
