import { PlusOutlined } from '@ant-design/icons';
import {
  type ActionType,
  PageContainer,
  type ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { Alert, Button, Descriptions, Modal, Space, Tag } from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import {
  tableResult,
  useResultMessage,
  useTablePreferences,
} from '@/components/ssl-manager';
import { DeploymentStateTag } from '@/components/ssl-manager/deployment/BatchPanel';
import { deploymentDateText } from '@/components/ssl-manager/deployment/presentation';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import type {
  DeploymentConnectionTest,
  DeploymentExecutorDescriptor,
  DeploymentTarget,
} from '@/services/ssl-manager/deploymentTypes';
import TargetForm from './TargetForm';

export default function DeploymentTargets() {
  const actionRef = useRef<ActionType>(null);
  const tablePreferences = useTablePreferences('deployment-targets');
  const showResult = useResultMessage();
  const [executors, setExecutors] = useState<DeploymentExecutorDescriptor[]>(
    [],
  );
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<DeploymentTarget>();
  const [error, setError] = useState('');
  const [actingIds, setActingIds] = useState<Set<string>>(() => new Set());
  const markBusy = (id: string, busy: boolean) =>
    setActingIds((ids) => {
      const next = new Set(ids);
      if (busy) next.add(id);
      else next.delete(id);
      return next;
    });
  const [diagnostic, setDiagnostic] = useState<DeploymentConnectionTest>();

  useEffect(() => {
    let active = true;
    deploymentApi.executors().then((result) => {
      if (!active) return;
      if (result.success) setExecutors(result.data || []);
      else setError(result.message);
    });
    return () => {
      active = false;
    };
  }, []);

  const edit = async (item: DeploymentTarget) => {
    markBusy(item.id, true);
    try {
      const result = await deploymentApi.target(item.id);
      if (showResult(result) && result.data) {
        setEditing(result.data);
        setOpen(true);
      }
    } finally {
      markBusy(item.id, false);
    }
  };
  const test = async (item: DeploymentTarget) => {
    markBusy(item.id, true);
    try {
      const result = await deploymentApi.testTarget(item.id);
      if (showResult(result, result.message) && result.data)
        setDiagnostic(result.data);
      actionRef.current?.reload();
    } finally {
      markBusy(item.id, false);
    }
  };
  const toggle = async (item: DeploymentTarget) => {
    markBusy(item.id, true);
    try {
      const result = await deploymentApi.targetStatus(item.id, !item.enabled);
      if (showResult(result, item.enabled ? '目标已停用' : '目标已启用'))
        actionRef.current?.reload();
    } finally {
      markBusy(item.id, false);
    }
  };

  const columns: ProColumns<DeploymentTarget>[] = [
    { title: '目标名称', dataIndex: 'name', width: 180 },
    {
      title: '类型',
      dataIndex: 'executorKey',
      width: 210,
      search: false,
      render: (_, item) =>
        executors.find((executor) => executor.key === item.executorKey)?.name ||
        item.executorKey,
    },
    {
      title: '地址',
      dataIndex: 'endpoint',
      width: 270,
      search: false,
      ellipsis: true,
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      width: 90,
      search: false,
      render: (_, item) => (
        <Tag color={item.enabled ? 'success' : 'default'}>
          {item.enabled ? '启用' : '停用'}
        </Tag>
      ),
    },
    {
      title: '实际版本',
      dataIndex: 'productVersion',
      width: 140,
      search: false,
      renderText: (value) => value || '未检测',
    },
    {
      title: '最近测试',
      width: 220,
      search: false,
      render: (_, item) =>
        item.lastTestAtUtc ? (
          <>
            <Tag color={item.lastTestSuccess ? 'success' : 'error'}>
              {item.lastTestSuccess ? '连接通过' : '测试失败'}
            </Tag>
            <div>{deploymentDateText(item.lastTestAtUtc)}</div>
          </>
        ) : (
          '尚未测试'
        ),
    },
    {
      title: '最近部署',
      width: 190,
      search: false,
      render: (_, item) =>
        item.lastDeploymentAtUtc ? (
          <>
            <DeploymentStateTag state={item.lastDeploymentStatus} />
            <div>{deploymentDateText(item.lastDeploymentAtUtc)}</div>
          </>
        ) : (
          '尚未部署'
        ),
    },
    {
      title: '操作',
      valueType: 'option',
      width: 245,
      render: (_, item) => (
        <Space size={0} wrap>
          <Button
            type="link"
            loading={actingIds.has(item.id)}
            onClick={() => edit(item)}
          >
            编辑
          </Button>
          <Button
            type="link"
            disabled={!item.enabled}
            loading={actingIds.has(item.id)}
            onClick={() => test(item)}
          >
            测试连接
          </Button>
          <Button
            type="link"
            loading={actingIds.has(item.id)}
            onClick={() => toggle(item)}
          >
            {item.enabled ? '停用' : '启用'}
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <PageContainer
      title="部署目标"
      subTitle="维护雷池、群晖和服务器部署目标，按执行器适配目标版本"
    >
      <Alert
        type="info"
        showIcon
        title="连接测试只验证认证和可用能力，不会上传证书或执行 reload、重启命令。"
        style={{ marginBottom: 16 }}
      />
      {error && (
        <Alert type="error" title={error} style={{ marginBottom: 16 }} />
      )}
      <ProTable<DeploymentTarget>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        {...tablePreferences}
        scroll={{ x: 1550 }}
        request={async ({ current, pageSize, name }) => {
          const result = await deploymentApi.targets({
            page: current,
            pageSize,
            search: name,
          });
          setError(result.success ? '' : result.message);
          return tableResult(result);
        }}
        toolBarRender={() => [
          <Button
            key="new"
            type="primary"
            icon={<PlusOutlined />}
            disabled={!executors.some((executor) => executor.available)}
            onClick={() => {
              setEditing(undefined);
              setOpen(true);
            }}
          >
            新建部署目标
          </Button>,
        ]}
      />
      <TargetForm
        open={open}
        target={editing}
        executors={executors}
        onClose={() => setOpen(false)}
        onSaved={() => actionRef.current?.reload()}
      />
      <Modal
        open={!!diagnostic}
        title="连接测试结果"
        onCancel={() => setDiagnostic(undefined)}
        footer={<Button onClick={() => setDiagnostic(undefined)}>关闭</Button>}
      >
        <Descriptions
          column={1}
          items={[
            {
              key: 'version',
              label: '实际版本',
              children: diagnostic?.productVersion || '未返回版本',
            },
            { key: 'message', label: '结果', children: diagnostic?.message },
            {
              key: 'capabilities',
              label: '已检测能力',
              children:
                diagnostic?.capabilities?.join('、') || '见执行器返回说明',
            },
          ]}
        />
      </Modal>
    </PageContainer>
  );
}
