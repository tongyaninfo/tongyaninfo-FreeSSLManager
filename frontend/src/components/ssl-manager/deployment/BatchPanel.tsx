import {
  Alert,
  Button,
  Descriptions,
  Input,
  Modal,
  Space,
  Table,
  Tag,
} from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import { useResultMessage } from '@/components/ssl-manager';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import type {
  DeploymentBatch,
  DeploymentPlan,
  DeploymentStep,
  DeploymentTask,
} from '@/services/ssl-manager/deploymentTypes';
import {
  deploymentDateText,
  deploymentPhaseNames,
  deploymentStatusColor,
  deploymentStatusNames,
  isDeploymentActive,
  verificationLevelNames,
} from './presentation';

export function DeploymentStateTag({ state }: { state: string }) {
  return (
    <Tag color={deploymentStatusColor(state)}>
      {deploymentStatusNames[state] || state}
    </Tag>
  );
}

/** 列表和证书部署弹窗共享任务详情，保留每个目标独立的结果及操作状态。 */
export default function BatchPanel({
  batch,
  onRefresh,
  onRetryPlan,
}: {
  batch: DeploymentBatch;
  onRefresh: () => void;
  onRetryPlan: (plan: DeploymentPlan) => void;
}) {
  const showResult = useResultMessage();
  const [actingIds, setActingIds] = useState<Set<string>>(() => new Set());
  const markBusy = (id: string, busy: boolean) =>
    setActingIds((ids) => {
      const next = new Set(ids);
      if (busy) next.add(id);
      else next.delete(id);
      return next;
    });
  const [task, setTask] = useState<DeploymentTask>();
  const [taskId, setTaskId] = useState('');
  const [taskError, setTaskError] = useState('');
  const [resolveTask, setResolveTask] = useState<DeploymentTask>();
  const [resolutionNote, setResolutionNote] = useState('');
  const [resolutionError, setResolutionError] = useState('');
  const [resolving, setResolving] = useState(false);
  const [rollbackExecutors, setRollbackExecutors] = useState<Set<string>>(
    () => new Set(),
  );
  const sequence = useRef(0);

  useEffect(() => {
    let active = true;
    deploymentApi.executors().then((result) => {
      if (active && result.success)
        setRollbackExecutors(
          new Set(
            (result.data || [])
              .filter((item) => item.available && item.supportsRollback)
              .map((item) => item.key),
          ),
        );
    });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    const current = ++sequence.current;
    if (!taskId) return undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const load = async () => {
      const result = await deploymentApi.task(taskId);
      if (current !== sequence.current) return;
      setTaskError(result.success ? '' : result.message);
      if (result.success && result.data) {
        setTask(result.data);
        if (isDeploymentActive(result.data.status))
          timer = setTimeout(load, 2500);
      }
    };
    setTask(undefined);
    load();
    return () => {
      sequence.current += 1;
      clearTimeout(timer);
    };
  }, [taskId]);

  const act = async (item: DeploymentTask, kind: 'cancel' | 'inspect') => {
    markBusy(item.id, true);
    try {
      const result =
        kind === 'cancel'
          ? await deploymentApi.cancel(item.id)
          : await deploymentApi.inspect(item.id);
      showResult<unknown>(result, result.message);
      onRefresh();
    } finally {
      markBusy(item.id, false);
    }
  };

  const resolve = async () => {
    if (!resolveTask) return;
    if (!resolutionNote.trim()) {
      setResolutionError('请填写实际核对结果和解除原因');
      return;
    }
    setResolving(true);
    try {
      const result = await deploymentApi.resolve(
        resolveTask.id,
        resolutionNote.trim(),
      );
      if (showResult(result, '已记录人工核对结果并解除资源阻塞')) {
        setResolveTask(undefined);
        setResolutionNote('');
        onRefresh();
      } else setResolutionError(result.message);
    } finally {
      setResolving(false);
    }
  };

  const retry = async (item: DeploymentTask) => {
    markBusy(item.id, true);
    try {
      const result = await deploymentApi.retryPlan(item.id);
      if (showResult(result) && result.data) onRetryPlan(result.data);
    } finally {
      markBusy(item.id, false);
    }
  };

  const rollback = async (item: DeploymentTask) => {
    markBusy(item.id, true);
    try {
      const result = await deploymentApi.rollbackPlan(item.id);
      if (showResult(result) && result.data) onRetryPlan(result.data);
    } finally {
      markBusy(item.id, false);
    }
  };

  return (
    <>
      <Descriptions
        size="small"
        column={2}
        items={[
          { key: 'domain', label: '证书', children: batch.certificateDomain },
          {
            key: 'status',
            label: '批次状态',
            children: <DeploymentStateTag state={batch.status} />,
          },
          {
            key: 'operation',
            label: '操作类型',
            children:
              batch.operationType === 'Rollback' ? '恢复备份文件' : '部署证书',
          },
          {
            key: 'created',
            label: '创建时间',
            children: deploymentDateText(batch.createdAtUtc),
          },
          { key: 'id', label: '批次 ID', children: batch.id },
          {
            key: 'fingerprint',
            label: '证书指纹',
            span: 2,
            children: (
              <span style={{ overflowWrap: 'anywhere' }}>
                {batch.fingerprint || '—'}
              </span>
            ),
          },
        ]}
      />
      <Table<DeploymentTask>
        style={{ marginTop: 16 }}
        size="small"
        rowKey="id"
        pagination={false}
        scroll={{ x: 1050 }}
        dataSource={batch.tasks}
        columns={[
          { title: '部署目标', dataIndex: 'targetName', width: 170 },
          {
            title: '状态',
            width: 150,
            render: (_, item) => <DeploymentStateTag state={item.status} />,
          },
          {
            title: '当前阶段',
            dataIndex: 'phase',
            width: 150,
            render: (value) => deploymentPhaseNames[value] || value || '—',
          },
          {
            title: '验证结果',
            dataIndex: 'verificationLevel',
            width: 180,
            render: (value) =>
              verificationLevelNames[value] || value || '服务生效未验证',
          },
          { title: '说明', dataIndex: 'message', width: 300, ellipsis: true },
          {
            title: '操作',
            width: 220,
            render: (_, item) => (
              <Space size={0} wrap>
                <Button type="link" onClick={() => setTaskId(item.id)}>
                  步骤
                </Button>
                {isDeploymentActive(item.status) && (
                  <Button
                    type="link"
                    disabled={item.cancelRequested}
                    loading={actingIds.has(item.id)}
                    onClick={() => act(item, 'cancel')}
                  >
                    {item.cancelRequested ? '取消已请求' : '取消后续步骤'}
                  </Button>
                )}
                {item.status === 'NeedsAttention' && (
                  <>
                    <Button
                      type="link"
                      loading={actingIds.has(item.id)}
                      onClick={() => act(item, 'inspect')}
                    >
                      核对远端
                    </Button>
                    <Button
                      type="link"
                      onClick={() => {
                        setResolveTask(item);
                        setResolutionNote('');
                        setResolutionError('');
                      }}
                    >
                      人工核对后解除
                    </Button>
                  </>
                )}
                {['Failed', 'Cancelled', 'Resolved', 'RollbackFailed'].includes(
                  item.status,
                ) && (
                  <Button
                    type="link"
                    loading={actingIds.has(item.id)}
                    onClick={() => retry(item)}
                  >
                    重新生成计划
                  </Button>
                )}
                {!item.sourceTaskId &&
                  rollbackExecutors.has(item.executorKey) &&
                  ['Succeeded', 'Failed', 'Resolved'].includes(item.status) && (
                    <Button
                      type="link"
                      loading={actingIds.has(item.id)}
                      onClick={() => rollback(item)}
                    >
                      恢复文件
                    </Button>
                  )}
              </Space>
            ),
          },
        ]}
      />
      <Modal
        open={!!resolveTask}
        title="记录人工核对并解除资源阻塞"
        onCancel={() => setResolveTask(undefined)}
        onOk={resolve}
        confirmLoading={resolving}
        okText="记录并解除"
        cancelText="取消"
      >
        <Alert
          type="warning"
          showIcon
          title="此操作仅记录你已完成的人工核对并解除待核对阻塞，不执行远端操作，也不将部署标记为成功。"
          style={{ marginBottom: 16 }}
        />
        {resolutionError && (
          <Alert
            type="error"
            title={resolutionError}
            style={{ marginBottom: 16 }}
          />
        )}
        <Input.TextArea
          aria-label="人工核对结果和解除原因"
          rows={4}
          maxLength={1000}
          value={resolutionNote}
          onChange={(event) => setResolutionNote(event.target.value)}
          placeholder="填写核对到的实际证书、站点或文件状态，以及允许后续任务执行的原因。请勿填写密码或私钥。"
        />
      </Modal>
      <Modal
        open={!!taskId}
        title={`部署步骤${task?.targetName ? ` · ${task.targetName}` : ''}`}
        width={920}
        onCancel={() => setTaskId('')}
        footer={<Button onClick={() => setTaskId('')}>关闭</Button>}
      >
        {taskError && (
          <Alert type="error" title={taskError} style={{ marginBottom: 16 }} />
        )}
        <Table<DeploymentStep>
          loading={!task && !taskError}
          size="small"
          rowKey="id"
          pagination={false}
          dataSource={task?.steps || []}
          scroll={{ x: 800 }}
          columns={[
            {
              title: '时间',
              dataIndex: 'createdAtUtc',
              width: 180,
              render: deploymentDateText,
            },
            {
              title: '阶段',
              dataIndex: 'phase',
              width: 130,
              render: (value) => deploymentPhaseNames[value] || value,
            },
            {
              title: '状态',
              dataIndex: 'status',
              width: 130,
              render: (value) => <DeploymentStateTag state={value} />,
            },
            {
              title: '说明',
              dataIndex: 'message',
              width: 360,
              render: (value) => (
                <span
                  style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}
                >
                  {value}
                </span>
              ),
            },
          ]}
        />
      </Modal>
    </>
  );
}
