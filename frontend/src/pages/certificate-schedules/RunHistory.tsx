import {
  type ActionType,
  type ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { history } from '@umijs/max';
import {
  Alert,
  Button,
  Descriptions,
  Form,
  Input,
  Modal,
  Space,
  Table,
  Tag,
} from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import { tableResult, useResultMessage } from '@/components/ssl-manager';
import { DeploymentStateTag } from '@/components/ssl-manager/deployment/BatchPanel';
import { deploymentDateText } from '@/components/ssl-manager/deployment/presentation';
import {
  type CertificateSchedule,
  type CertificateScheduleRun,
  certificateScheduleApi,
} from '@/services/ssl-manager/certificateSchedule';
import {
  cleanupStateNames,
  oldCertificateStateNames,
  scheduleStateColor,
  scheduleStateNames,
} from './presentation';

export function ScheduleStateTag({
  state,
  cleanup = false,
  oldCertificate = false,
}: {
  state?: string;
  cleanup?: boolean;
  oldCertificate?: boolean;
}) {
  return (
    <Tag color={scheduleStateColor(state)}>
      {(oldCertificate
        ? oldCertificateStateNames
        : cleanup
          ? cleanupStateNames
          : scheduleStateNames)[state || ''] ||
        state ||
        '尚未执行'}
    </Tag>
  );
}

/** 一轮内的部署结果与旧证书清理单独呈现，清理失败不伪装成设备部署失败。 */
export function RunDetail({ run }: { run: CertificateScheduleRun }) {
  return (
    <Space direction="vertical" style={{ width: '100%' }} size="middle">
      <Descriptions
        column={2}
        items={[
          {
            key: 'status',
            label: '本轮阶段',
            children: <ScheduleStateTag state={run.status} />,
          },
          {
            key: 'cleanup',
            label: '旧证书清理',
            children: <ScheduleStateTag state={run.cleanupStatus} cleanup />,
          },
          {
            key: 'applicationCleanup',
            label: '申请验证 DNS 清理',
            children: (
              <ScheduleStateTag
                state={run.applicationCleanupStatus || 'NotRequested'}
                cleanup
              />
            ),
          },
          {
            key: 'certificate',
            label: '本轮证书',
            children: run.certificateId ? (
              <Button
                type="link"
                onClick={() =>
                  history.push(
                    `/certificates/${encodeURIComponent(run.certificateId)}`,
                  )
                }
              >
                查看证书
              </Button>
            ) : (
              '尚未关联证书'
            ),
          },
          {
            key: 'scheduled',
            label: '原定执行时间',
            children: deploymentDateText(run.scheduledForUtc),
          },
          {
            key: 'started',
            label: '开始时间',
            children: deploymentDateText(run.startedAtUtc || undefined),
          },
          {
            key: 'finished',
            label: '结束时间',
            children: deploymentDateText(run.finishedAtUtc || undefined),
          },
          {
            key: 'message',
            label: '处理结果',
            span: 2,
            children: run.message || '正在等待后台推进',
          },
          ...(run.code
            ? [{ key: 'code', label: '结果代码', children: run.code }]
            : []),
        ]}
      />
      <div style={{ fontWeight: 600 }}>各目标部署结果</div>
      <Table
        rowKey="targetId"
        size="small"
        pagination={false}
        dataSource={run.targets}
        columns={[
          {
            title: '部署目标',
            dataIndex: 'targetName',
            render: (name, item) => name || item.targetId,
          },
          {
            title: '状态',
            dataIndex: 'status',
            render: (state) =>
              state === 'Pending' || state === 'Submitting' ? (
                <ScheduleStateTag state={state} />
              ) : (
                <DeploymentStateTag state={state} />
              ),
          },
          { title: '结果', dataIndex: 'message' },
          {
            title: '部署记录',
            render: (_, item) =>
              item.batchId ? (
                <Button
                  type="link"
                  onClick={() =>
                    history.push(
                      `/deployments?batchId=${encodeURIComponent(item.batchId)}`,
                    )
                  }
                >
                  查看部署记录
                </Button>
              ) : (
                '尚未生成批次'
              ),
          },
        ]}
      />
      <div style={{ fontWeight: 600 }}>旧证书清理明细</div>
      <Table
        rowKey="certificateId"
        size="small"
        pagination={false}
        dataSource={run.oldCertificates}
        locale={{ emptyText: '本轮暂无旧证书清理明细' }}
        columns={[
          { title: '域名', dataIndex: 'domain' },
          { title: '证书 ID', dataIndex: 'certificateId', ellipsis: true },
          {
            title: '清理状态',
            dataIndex: 'status',
            render: (state) => (
              <ScheduleStateTag state={state} oldCertificate />
            ),
          },
          { title: '处理结果', dataIndex: 'message' },
        ]}
      />
    </Space>
  );
}

export default function RunHistory({
  schedule,
  onClose,
  onChanged,
}: {
  schedule?: CertificateSchedule;
  onClose: () => void;
  onChanged: () => void;
}) {
  const actionRef = useRef<ActionType>(null);
  const showResult = useResultMessage();
  const [error, setError] = useState('');
  const [active, setActive] = useState(false);
  const [busy, setBusy] = useState('');
  const [resolving, setResolving] = useState<CertificateScheduleRun>();
  const [noteForm] = Form.useForm<{ note: string }>();
  useEffect(() => {
    setError('');
    setActive(false);
    setResolving(undefined);
  }, [schedule?.id]);
  useEffect(() => {
    if (!schedule || !active) return;
    const timer = window.setInterval(() => {
      if (!document.hidden) actionRef.current?.reload();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [schedule?.id, active]);
  const refresh = () => {
    actionRef.current?.reload();
    onChanged();
  };
  const resume = async (run: CertificateScheduleRun) => {
    setBusy(run.id);
    try {
      const result = await certificateScheduleApi.resume(run.id);
      if (showResult(result, '已提交重新核对')) {
        setError('');
        refresh();
      } else setError(result.message);
    } finally {
      setBusy('');
    }
  };
  const resolve = async () => {
    if (!resolving) return;
    try {
      const values = await noteForm.validateFields();
      setBusy(resolving.id);
      const result = await certificateScheduleApi.resolve(
        resolving.id,
        values.note.trim(),
      );
      if (showResult(result, '本轮已人工结束，原记录和资源已保留')) {
        setResolving(undefined);
        refresh();
      } else setError(result.message);
    } catch (exception) {
      if (exception instanceof Error) setError(exception.message);
    } finally {
      setBusy('');
    }
  };
  const columns: ProColumns<CertificateScheduleRun>[] = [
    {
      title: '原定执行时间',
      dataIndex: 'scheduledForUtc',
      render: (_, run) => deploymentDateText(run.scheduledForUtc),
      width: 190,
    },
    {
      title: '本轮阶段',
      dataIndex: 'status',
      render: (_, run) => <ScheduleStateTag state={run.status} />,
      width: 145,
    },
    {
      title: '旧证书清理',
      dataIndex: 'cleanupStatus',
      render: (_, run) => (
        <ScheduleStateTag state={run.cleanupStatus} cleanup />
      ),
      width: 140,
    },
    { title: '最近结果', dataIndex: 'message', ellipsis: true },
    {
      title: '操作',
      valueType: 'option',
      width: 235,
      render: (_, run) =>
        run.status === 'NeedsAttention' ? (
          <Space size={0}>
            <Button
              type="link"
              loading={busy === run.id}
              onClick={() => resume(run)}
            >
              重新核对
            </Button>
            <Button
              type="link"
              danger
              disabled={!!busy}
              onClick={() => {
                noteForm.resetFields();
                setResolving(run);
              }}
            >
              结束本轮
            </Button>
          </Space>
        ) : null,
    },
  ];
  return (
    <>
      <Modal
        title={`运行历史${schedule ? ` · ${schedule.name}` : ''}`}
        open={!!schedule}
        width={1250}
        onCancel={onClose}
        footer={<Button onClick={onClose}>关闭</Button>}
        destroyOnHidden
      >
        <Alert
          type="info"
          showIcon
          title="服务重启后自动恢复原轮次；部署中断先核对再继续，申请验证 DNS 和旧证书清理也会持续推进。无法确认的操作请查看具体原因。"
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
        {schedule && (
          <ProTable<CertificateScheduleRun>
            key={schedule.id}
            rowKey="id"
            actionRef={actionRef}
            columns={columns}
            search={false}
            options={{ reload: true, density: false, setting: false }}
            pagination={{ defaultPageSize: 10 }}
            scroll={{ x: 1000 }}
            expandable={{ expandedRowRender: (run) => <RunDetail run={run} /> }}
            request={async ({ current, pageSize }) => {
              const result = await certificateScheduleApi.runs(schedule.id, {
                page: current,
                pageSize,
              });
              setError(result.success ? '' : result.message);
              setActive(
                (result.data?.items || []).some(
                  (run) =>
                    run.active &&
                    run.status !== 'NeedsAttention' &&
                    run.status !== 'Paused',
                ),
              );
              return tableResult(result);
            }}
          />
        )}
      </Modal>
      <Modal
        title="人工结束待核对轮次"
        open={!!resolving}
        onCancel={() => setResolving(undefined)}
        onOk={resolve}
        okText="确认结束本轮"
        cancelText="取消"
        confirmLoading={!!busy}
      >
        <Alert
          type="warning"
          showIcon
          title="请先核对云端申请和所有设备的部署结果。"
          description="此操作保留现有资源与历史，不宣告本轮成功。结束后启用的计划可以启动下一轮；请勿在结果仍未知时结束，以免重复申请或覆盖。"
          style={{ marginBottom: 16 }}
        />
        <Form form={noteForm} layout="vertical">
          <Form.Item
            name="note"
            label="处理说明"
            rules={[
              {
                required: true,
                whitespace: true,
                message: '请填写人工核对结果和结束原因',
              },
              { max: 1000 },
            ]}
          >
            <Input.TextArea rows={4} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
