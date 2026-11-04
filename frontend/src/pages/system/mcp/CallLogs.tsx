import {
  Alert,
  Button,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd';
import dayjs, { type Dayjs } from 'dayjs';
import React, { useEffect, useRef, useState } from 'react';
import { useResultMessage } from '@/components/ssl-manager';
import { mcpApi } from '@/services/ssl-manager/mcp';
import type {
  McpCallLog,
  McpCallStatistics,
  McpOperation,
} from '@/services/ssl-manager/mcpTypes';
import { canApproveOperation, mcpDate, mcpStatusText } from './presentation';
import AuditContext from './AuditContext';

type Filters = {
  clientId?: string;
  toolName?: string;
  status?: string;
  code?: string;
  sourceIp?: string;
  authenticationType?: string;
  apiKeyId?: string;
  method?: string;
  traceId?: string;
  httpStatus?: number;
  times?: [Dayjs, Dayjs];
};
const defaultTimes: [Dayjs, Dayjs] = [dayjs().subtract(7, 'day'), dayjs()];
const statusOptions = [
  'Started',
  'Succeeded',
  'Failed',
  'Denied',
  'Rejected',
  'TimedOut',
  'Cancelled',
  'Unknown',
].map((value) => ({ value, label: mcpStatusText(value) }));

/** 关联跳转只拼接已知本平台路径，不采用调用方提供的任意 URL。 */
function BusinessLinks({
  certificateId,
  batchId,
  taskId,
}: {
  certificateId?: string;
  batchId?: string;
  taskId?: string;
}) {
  return (
    <Space wrap>
      {certificateId && (
        <a href={`/certificates/${encodeURIComponent(certificateId)}`}>
          查看证书
        </a>
      )}
      {batchId && (
        <a href={`/deployments?batchId=${encodeURIComponent(batchId)}`}>
          查看部署批次
        </a>
      )}
      {taskId && <Typography.Text>任务 ID：{taskId}</Typography.Text>}
    </Space>
  );
}

function OperationDetail({ operation }: { operation: McpOperation }) {
  let summary: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(operation.summaryJson || '{}');
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed))
      summary = parsed;
  } catch {
    /* 不能用原输入快照替代缺失的公开摘要。 */
  }
  const plain = (key: string) =>
    typeof summary[key] === 'string' ||
    typeof summary[key] === 'number' ||
    typeof summary[key] === 'boolean'
      ? String(summary[key])
      : '—';
  return (
    <>
      <Alert
        type="info"
        showIcon
        title="审批不改变实际调用用户，执行前还会复核权限与计划修订。"
        description="批准只允许此草稿在有效期内提交；后续 MCP 提交仍由原客户端完成。批准不等于证书已申请或部署已执行。"
        style={{ marginBottom: 16 }}
      />
      <Descriptions
        column={1}
        bordered
        size="small"
        items={[
          { key: 'id', label: '操作 ID', children: operation.id },
          {
            key: 'client',
            label: '原调用客户端',
            children: operation.clientId || '—',
          },
          {
            key: 'tool',
            label: '工具 / 类型',
            children: `${operation.toolName} · ${operation.kind}`,
          },
          {
            key: 'status',
            label: '状态',
            children: mcpStatusText(operation.status),
          },
          {
            key: 'identity',
            label: '实际调用用户 ID',
            children: operation.effectiveUserId,
          },
          {
            key: 'prepared',
            label: '准备人 / 批准人',
            children: `${operation.preparedBy || '—'} / ${operation.approvedBy || '—'}`,
          },
          {
            key: 'expiry',
            label: '草稿 / 批准到期',
            children: mcpDate(operation.approvalExpiresAtUtc),
          },
          {
            key: 'version',
            label: '操作 / 计划修订',
            children: `${operation.version} / ${operation.planRevision || '—'}`,
          },
          {
            key: 'created',
            label: '创建时间',
            children: mcpDate(operation.createdAtUtc),
          },
          { key: 'account', label: '云账号 ID', children: plain('accountId') },
          { key: 'domain', label: '业务域名', children: plain('domain') },
          { key: 'dns', label: 'DNS 影响', children: plain('dnsImpact') },
          {
            key: 'free',
            label: '免费规格',
            children: summary.free === true ? '是' : '—',
          },
          {
            key: 'fingerprint',
            label: '证书指纹',
            children: plain('fingerprint'),
          },
          {
            key: 'digest',
            label: '固定参数摘要',
            children: operation.argumentsDigest || '—',
          },
          {
            key: 'preauth',
            label: '预授权',
            children:
              summary.preauthorized === true
                ? '本操作使用显式预授权策略'
                : '无',
          },
          {
            key: 'message',
            label: '业务结果',
            children: `${operation.code || '—'} ${operation.message || ''}`,
          },
        ]}
      />
      {Array.isArray(summary.targets) && (
        <div style={{ marginTop: 16 }}>
          <strong>本次允许变更的部署目标</strong>
          <Table<Record<string, unknown>>
            size="small"
            pagination={false}
            rowKey={(item) => String(item.targetId)}
            dataSource={summary.targets.filter(
              (item): item is Record<string, unknown> =>
                !!item && typeof item === 'object',
            )}
            columns={[
              {
                title: '目标',
                render: (_, item) =>
                  String(item.targetName || item.targetId || '—'),
              },
              {
                title: '目标配置修订',
                render: (_, item) => String(item.configRevision ?? '—'),
              },
              {
                title: '动作',
                render: (_, item) => String(item.action || '—'),
              },
              {
                title: '影响摘要',
                render: (_, item) => String(item.summary || '—'),
              },
            ]}
          />
        </div>
      )}
      <div style={{ marginTop: 16 }}>
        <BusinessLinks {...operation} />
      </div>
    </>
  );
}

export default function CallLogs() {
  const showResult = useResultMessage();
  const [form] = Form.useForm<Filters>();
  const [tab, setTab] = useState('logs');
  const [params, setParams] = useState<Record<string, unknown>>({
    fromUtc: defaultTimes[0].toISOString(),
    toUtc: defaultTimes[1].toISOString(),
  });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);
  const [logs, setLogs] = useState<McpCallLog[]>([]);
  const [statistics, setStatistics] = useState<McpCallStatistics>();
  const [statisticsError, setStatisticsError] = useState('');
  const [operations, setOperations] = useState<McpOperation[]>([]);
  const [operationStatus, setOperationStatus] = useState<string>();
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [log, setLog] = useState<McpCallLog>();
  const [operation, setOperation] = useState<McpOperation>();
  const [drawer, setDrawer] = useState<'log' | 'operation'>();
  const [error, setError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [confirm, setConfirm] = useState<'approve' | 'reject'>();
  const [busy, setBusy] = useState(false);
  const active = useRef(true);
  const detailSequence = useRef(0);
  const pending = useRef(false);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      detailSequence.current++;
    };
  }, []);
  useEffect(() => {
    let current = true;
    setLoading(true);
    setError('');
    const load = async () => {
      if (tab === 'logs') {
        const [result, summary] = await Promise.all([
          mcpApi.callLogs({ ...params, page, pageSize }),
          mcpApi.callStatistics({
            fromUtc: params.fromUtc,
            toUtc: params.toUtc,
          }),
        ]);
        if (!current) return;
        setStatistics(summary.success ? summary.data || undefined : undefined);
        setStatisticsError(summary.success ? '' : summary.message);
        if (result.success && result.data) {
          setLogs(result.data.items);
          setTotal(result.data.total);
        } else {
          setLogs([]);
          setError(result.message);
        }
      } else {
        const result = await mcpApi.operations({
          status: operationStatus,
          page,
          pageSize,
        });
        if (!current) return;
        if (result.success && result.data) {
          setOperations(result.data.items);
          setTotal(result.data.total);
        } else {
          setOperations([]);
          setError(result.message);
        }
      }
    };
    void load().finally(() => {
      if (current) setLoading(false);
    });
    return () => {
      current = false;
    };
  }, [tab, params, page, pageSize, operationStatus, revision]);

  const inspect = async (id: string, kind: 'log' | 'operation') => {
    const sequence = ++detailSequence.current;
    setDrawer(kind);
    setLog(undefined);
    setOperation(undefined);
    setDetailLoading(true);
    setDetailError('');
    setConfirm(undefined);
    try {
      if (kind === 'log') {
        const result = await mcpApi.callLog(id);
        if (sequence !== detailSequence.current || !active.current) return;
        if (result.success && result.data) setLog(result.data);
        else setDetailError(result.message);
      } else {
        const result = await mcpApi.operation(id);
        if (sequence !== detailSequence.current || !active.current) return;
        if (result.success && result.data) setOperation(result.data);
        else setDetailError(result.message);
      }
    } finally {
      if (sequence === detailSequence.current && active.current)
        setDetailLoading(false);
    }
  };
  const approveOrReject = async () => {
    if (!operation || !confirm || pending.current || !active.current) return;
    pending.current = true;
    setBusy(true);
    const id = operation.id;
    const sequence = detailSequence.current;
    try {
      const result =
        confirm === 'approve'
          ? await mcpApi.approve(id, operation.version, '')
          : await mcpApi.reject(id, operation.version, '');
      if (!active.current || sequence !== detailSequence.current) return;
      if (
        showResult(
          result,
          confirm === 'approve' ? '操作已批准，等待原客户端提交' : '操作已拒绝',
        ) &&
        result.data
      ) {
        setOperation(result.data);
        setConfirm(undefined);
        setRevision((value) => value + 1);
      } else setDetailError(result.message);
    } finally {
      pending.current = false;
      if (active.current) setBusy(false);
    }
  };
  const pagination = {
    current: page,
    pageSize,
    total,
    pageSizeOptions: [20, 50, 100],
    showSizeChanger: true,
    onChange: (next: number, size: number) => {
      setPage(next);
      setPageSize(size);
    },
  };

  return (
    <>
      <Alert
        type="info"
        showIcon
        title="调用结果以业务状态为准，HTTP 200 不代表工具成功。"
        description="记录认证身份、调用元数据和白名单脱敏的有界入参出参；服务关闭后仍可查看日志和待确认操作。时间按上海时区显示。"
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
      <Tabs
        activeKey={tab}
        onChange={(value) => {
          setTab(value);
          setPage(1);
        }}
        items={[
          {
            key: 'logs',
            label: '调用记录',
            children: (
              <>
                {statisticsError && (
                  <Alert
                    type="warning"
                    showIcon
                    title={`调用统计暂不可用：${statisticsError}`}
                    style={{ marginBottom: 16 }}
                  />
                )}
                {statistics && (
                  <section
                    aria-label="MCP 调用统计"
                    style={{ marginBottom: 20 }}
                  >
                    <Descriptions
                      title="时间范围内的全部调用"
                      size="small"
                      column={{ xs: 1, sm: 2, md: 4 }}
                      items={[
                        {
                          key: 'total',
                          label: '请求总数',
                          children: statistics.totalRequests,
                        },
                        {
                          key: 'tools',
                          label: '工具调用',
                          children: statistics.toolCalls,
                        },
                        {
                          key: 'success',
                          label: '成功',
                          children: statistics.succeeded,
                        },
                        {
                          key: 'failed',
                          label: '失败',
                          children: statistics.failed,
                        },
                        {
                          key: 'denied',
                          label: '拒绝',
                          children: statistics.denied,
                        },
                        {
                          key: 'unknown',
                          label: '结果未知',
                          children: statistics.unknown,
                        },
                        {
                          key: 'duration',
                          label: '平均耗时',
                          children:
                            statistics.averageDurationMilliseconds === null
                              ? '—'
                              : `${statistics.averageDurationMilliseconds.toFixed(1)} ms`,
                        },
                        {
                          key: 'range',
                          label: '统计范围',
                          children: `${mcpDate(statistics.fromUtc)} — ${mcpDate(statistics.toUtc)}`,
                        },
                      ]}
                    />
                    <Typography.Text type="secondary">
                      接入拒绝可能按分钟与错误码合并，统计按实际请求次数汇总，列表分页按记录行计。统计不随客户端、工具等列表筛选变化；最多查询
                      90 天。
                    </Typography.Text>
                    <details style={{ marginTop: 8 }}>
                      <summary>查看调用趋势</summary>
                      <Table
                        rowKey="bucketUtc"
                        size="small"
                        pagination={{ pageSize: 8 }}
                        dataSource={statistics.trend}
                        columns={[
                          {
                            title: '时间段（上海）',
                            render: (_, item) => mcpDate(item.bucketUtc),
                          },
                          { title: '请求', dataIndex: 'requests' },
                          { title: '工具调用', dataIndex: 'toolCalls' },
                          { title: '失败', dataIndex: 'failed' },
                          { title: '拒绝', dataIndex: 'denied' },
                        ]}
                      />
                    </details>
                  </section>
                )}
                <Form<Filters>
                  form={form}
                  layout="inline"
                  initialValues={{ times: defaultTimes }}
                  onFinish={({ times, ...values }) => {
                    setParams({
                      ...values,
                      fromUtc: times?.[0]?.toISOString(),
                      toUtc: times?.[1]?.toISOString(),
                    });
                    setPage(1);
                  }}
                  style={{ rowGap: 12, marginBottom: 16 }}
                >
                  <Form.Item name="clientId" label="Client ID">
                    <Input style={{ width: 190 }} />
                  </Form.Item>
                  <Form.Item name="authenticationType" label="认证方式">
                    <Select
                      allowClear
                      style={{ width: 135 }}
                      options={[
                        { value: 'ApiKey', label: 'API Key' },
                        { value: 'OAuth', label: 'OAuth' },
                      ]}
                    />
                  </Form.Item>
                  <Form.Item name="apiKeyId" label="Key ID">
                    <Input style={{ width: 190 }} />
                  </Form.Item>
                  <Form.Item name="method" label="协议方法">
                    <Input style={{ width: 180 }} placeholder="tools/call" />
                  </Form.Item>
                  <Form.Item name="traceId" label="Trace ID">
                    <Input style={{ width: 210 }} />
                  </Form.Item>
                  <Form.Item name="httpStatus" label="HTTP 状态">
                    <InputNumber min={100} max={599} precision={0} />
                  </Form.Item>
                  <Form.Item name="toolName" label="工具名">
                    <Input style={{ width: 210 }} />
                  </Form.Item>
                  <Form.Item name="status" label="调用状态">
                    <Select
                      allowClear
                      style={{ width: 150 }}
                      options={statusOptions}
                    />
                  </Form.Item>
                  <Form.Item name="code" label="业务码">
                    <Input style={{ width: 160 }} />
                  </Form.Item>
                  <Form.Item name="sourceIp" label="来源 IP">
                    <Input style={{ width: 170 }} />
                  </Form.Item>
                  <Form.Item name="times" label="时间范围">
                    <DatePicker.RangePicker showTime />
                  </Form.Item>
                  <Button type="primary" htmlType="submit">
                    查询调用日志
                  </Button>
                </Form>
                <Button
                  onClick={() => setRevision((value) => value + 1)}
                  style={{ marginBottom: 12 }}
                >
                  刷新日志
                </Button>
                <Table<McpCallLog>
                  rowKey="id"
                  loading={loading}
                  dataSource={logs}
                  pagination={pagination}
                  scroll={{ x: 1200 }}
                  columns={[
                    {
                      title: '开始时间',
                      width: 185,
                      render: (_, item) => mcpDate(item.startedAtUtc),
                    },
                    {
                      title: '客户端 / 工具',
                      width: 260,
                      render: (_, item) => (
                        <>
                          {item.clientId || '未认证'}
                          <div>
                            {item.authenticationType === 'ApiKey'
                              ? `API Key · ${item.apiKeyName || item.apiKeyPrefix || item.apiKeyId || '—'}`
                              : item.authenticationType || '未认证'}
                          </div>
                          <div>{item.toolName || item.method}</div>
                        </>
                      ),
                    },
                    { title: '来源 IP', dataIndex: 'sourceIp', width: 150 },
                    {
                      title: '业务状态',
                      width: 130,
                      render: (_, item) => (
                        <Tag
                          color={
                            item.status === 'Succeeded'
                              ? 'success'
                              : item.status === 'Started'
                                ? 'processing'
                                : 'warning'
                          }
                        >
                          {mcpStatusText(item.status)}
                        </Tag>
                      ),
                    },
                    {
                      title: '业务码 / HTTP',
                      width: 180,
                      render: (_, item) => (
                        <>
                          {item.code || '—'} / {item.httpStatus || '—'}
                        </>
                      ),
                    },
                    {
                      title: '请求次数',
                      width: 100,
                      render: (_, item) => item.occurrenceCount ?? 1,
                    },
                    {
                      title: '耗时',
                      width: 100,
                      render: (_, item) => `${item.durationMilliseconds} ms`,
                    },
                    {
                      title: '操作',
                      width: 170,
                      render: (_, item) => (
                        <Space>
                          <Button
                            type="link"
                            onClick={() => void inspect(item.id, 'log')}
                          >
                            详情
                          </Button>
                          {item.operationId && (
                            <Button
                              type="link"
                              onClick={() =>
                                void inspect(item.operationId, 'operation')
                              }
                            >
                              关联操作
                            </Button>
                          )}
                        </Space>
                      ),
                    },
                  ]}
                />
              </>
            ),
          },
          {
            key: 'operations',
            label: '待确认与历史操作',
            children: (
              <>
                <Space style={{ marginBottom: 16 }} wrap>
                  <Select
                    aria-label="受控操作状态"
                    value={operationStatus}
                    allowClear
                    placeholder="全部操作状态"
                    style={{ width: 200 }}
                    onChange={(value) => {
                      setOperationStatus(value);
                      setPage(1);
                    }}
                    options={[
                      'Prepared',
                      'Approved',
                      'Submitted',
                      'Dispatching',
                      'Completed',
                      'Rejected',
                      'Expired',
                      'Unknown',
                      'Failed',
                    ].map((value) => ({ value, label: mcpStatusText(value) }))}
                  />
                  <Button onClick={() => setRevision((value) => value + 1)}>
                    刷新受控操作
                  </Button>
                </Space>
                <Table<McpOperation>
                  rowKey="id"
                  loading={loading}
                  dataSource={operations}
                  pagination={pagination}
                  columns={[
                    {
                      title: '工具 / 操作 ID',
                      render: (_, item) => (
                        <>
                          {item.toolName}
                          <div>{item.id}</div>
                        </>
                      ),
                    },
                    { title: '实际调用用户', dataIndex: 'effectiveUserId' },
                    {
                      title: '状态',
                      render: (_, item) => mcpStatusText(item.status),
                    },
                    {
                      title: '审批期限',
                      render: (_, item) => mcpDate(item.approvalExpiresAtUtc),
                    },
                    {
                      title: '操作',
                      render: (_, item) => (
                        <Button
                          type="link"
                          onClick={() => void inspect(item.id, 'operation')}
                        >
                          核对操作详情
                        </Button>
                      ),
                    },
                  ]}
                />
              </>
            ),
          },
        ]}
      />
      <Drawer
        title={drawer === 'operation' ? '受控操作核对与审批' : '调用详情'}
        open={!!drawer}
        loading={detailLoading}
        size={850}
        onClose={() => {
          detailSequence.current++;
          setDrawer(undefined);
          setConfirm(undefined);
          setLog(undefined);
          setOperation(undefined);
          setDetailError('');
        }}
        extra={
          operation &&
          operation.canApprove !== false &&
          canApproveOperation(operation) && (
            <Space>
              <Button
                danger
                disabled={busy}
                onClick={() => {
                  setConfirm('reject');
                }}
              >
                拒绝此操作
              </Button>
              <Button
                type="primary"
                disabled={busy}
                onClick={() => {
                  setConfirm('approve');
                }}
              >
                批准此操作
              </Button>
            </Space>
          )
        }
      >
        {detailError && (
          <Alert
            type="error"
            title={detailError}
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}
        {operation && <OperationDetail operation={operation} />}
        {log && (
          <>
            <Descriptions
              column={1}
              bordered
              size="small"
              items={[
                {
                  key: 'id',
                  label: '调用 ID / Trace ID',
                  children: `${log.id} / ${log.traceId}`,
                },
                {
                  key: 'client',
                  label: '客户端 / 实际用户',
                  children: `${log.clientId || '未认证'} / ${log.userId || '—'}`,
                },
                {
                  key: 'auth',
                  label: '认证方式 / API Key',
                  children: `${log.authenticationType === 'ApiKey' ? 'API Key' : log.authenticationType || '未认证'} / ${[log.apiKeyName, log.apiKeyPrefix && `${log.apiKeyPrefix}…`, log.apiKeyId].filter(Boolean).join(' · ') || '—'}`,
                },
                {
                  key: 'tool',
                  label: '工具 / 协议版本',
                  children: `${log.toolName || log.method} / ${log.protocolVersion}`,
                },
                {
                  key: 'time',
                  label: '开始 / 结束时间',
                  children: `${mcpDate(log.startedAtUtc)} / ${mcpDate(log.finishedAtUtc)}`,
                },
                {
                  key: 'source',
                  label: '实际对端 / 可信来源',
                  children: `${log.remoteIp} / ${log.sourceIp}`,
                },
                {
                  key: 'status',
                  label: '调用状态 / 业务码',
                  children: `${mcpStatusText(log.status)} / ${log.code}`,
                },
                {
                  key: 'message',
                  label: '脱敏说明',
                  children: log.message || '—',
                },
                {
                  key: 'count',
                  label: '此记录包含请求次数',
                  children: log.occurrenceCount ?? 1,
                },
                {
                  key: 'http',
                  label: 'HTTP 状态 / 耗时',
                  children: `${log.httpStatus} / ${log.durationMilliseconds} ms`,
                },
                {
                  key: 'digest',
                  label: '参数摘要 / 策略修订',
                  children: `${log.argumentsDigest || '—'} / ${log.policyRevision}`,
                },
                {
                  key: 'reused',
                  label: '幂等复用',
                  children: log.idempotencyReused
                    ? '返回原操作，无新建业务提交'
                    : '否',
                },
              ]}
            />
            <AuditContext contextJson={log.contextJson} />
            <div style={{ marginTop: 16 }}>
              <BusinessLinks {...log} />
              {log.operationId && (
                <Button
                  type="link"
                  onClick={() => void inspect(log.operationId, 'operation')}
                >
                  核对关联受控操作
                </Button>
              )}
            </div>
          </>
        )}
      </Drawer>
      <Modal
        title={confirm === 'approve' ? '确认批准此草稿？' : '确认拒绝此草稿？'}
        open={!!confirm && !!operation}
        onCancel={() => setConfirm(undefined)}
        onOk={() => void approveOrReject()}
        confirmLoading={busy}
        okText={confirm === 'approve' ? '核对无误，批准' : '拒绝操作'}
        cancelText="返回核对"
        destroyOnHidden
      >
        <p>操作：{operation?.id}</p>
        <p>原实际调用用户：{operation?.effectiveUserId}</p>
        <p>
          操作修订：{operation?.version}
          。批准不会改变用户权限，也不会立即执行外部写入。
        </p>
      </Modal>
    </>
  );
}
