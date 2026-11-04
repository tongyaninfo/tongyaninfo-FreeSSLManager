import { PlusOutlined } from '@ant-design/icons';
import {
  type ActionType,
  PageContainer,
  type ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { Alert, Button, Modal, Space, Tag } from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import {
  tableResult,
  useResultMessage,
  useTablePreferences,
} from '@/components/ssl-manager';
import { deploymentDateText } from '@/components/ssl-manager/deployment/presentation';
import {
  type CertificateSchedule,
  certificateScheduleApi,
} from '@/services/ssl-manager/certificateSchedule';
import { scheduleUnitNames } from './presentation';
import RunHistory, { ScheduleStateTag } from './RunHistory';
import ScheduleForm from './ScheduleForm';

/** 页面只管理计划和读取进度；申请、轮询、部署与清理均由后台持久推进。 */
export default function CertificateSchedules() {
  const actionRef = useRef<ActionType>(null);
  const tablePreferences = useTablePreferences('certificate-schedules');
  const showResult = useResultMessage();
  const [editing, setEditing] = useState<CertificateSchedule>();
  const [open, setOpen] = useState(false);
  const [historySchedule, setHistorySchedule] = useState<CertificateSchedule>();
  const [error, setError] = useState('');
  const [busyIds, setBusyIds] = useState<Set<string>>(() => new Set());
  const [active, setActive] = useState(false);
  const busy = (id: string, value: boolean) =>
    setBusyIds((current) => {
      const next = new Set(current);
      if (value) next.add(id);
      else next.delete(id);
      return next;
    });
  const reload = () => actionRef.current?.reload();
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => {
      if (!document.hidden) actionRef.current?.reload();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [active]);

  const edit = async (item: CertificateSchedule) => {
    busy(item.id, true);
    try {
      const result = await certificateScheduleApi.get(item.id);
      if (showResult(result) && result.data) {
        setEditing(result.data);
        setOpen(true);
      } else setError(result.message);
    } finally {
      busy(item.id, false);
    }
  };
  const toggle = async (item: CertificateSchedule) => {
    busy(item.id, true);
    try {
      const result = await certificateScheduleApi.status(
        item.id,
        !item.enabled,
      );
      if (
        showResult(
          result,
          item.enabled
            ? '计划已停用，已提交的部署仍可在部署记录中管理'
            : '计划已启用',
        )
      ) {
        setError('');
        reload();
      } else setError(result.message);
    } finally {
      busy(item.id, false);
    }
  };
  const run = async (item: CertificateSchedule) => {
    busy(item.id, true);
    try {
      const result = await certificateScheduleApi.run(item.id);
      if (showResult(result, '已提交立即执行，本轮不会改变周期锚点')) {
        setError('');
        setHistorySchedule(item);
        reload();
      } else setError(result.message);
    } finally {
      busy(item.id, false);
    }
  };
  const permissionText = (item: CertificateSchedule) => (
    <>
      <p>
        账号：{item.accountName || item.accountId}；域名：{item.domain}；目标：
        {item.targetIds.length} 个。
      </p>
      <p>
        后台将申请新证书，签发后自动部署，并执行所选目标配置的验证、刷新或重启命令。
      </p>
      {item.revokeOldCertificates && (
        <p>
          已开启“吊销删除老证书”：全部目标成功后，旧证书未过期先吊销并确认后删除，已过期直接删除。
        </p>
      )}
    </>
  );
  const columns: ProColumns<CertificateSchedule>[] = [
    {
      title: '任务名称',
      dataIndex: 'name',
      width: 170,
      fieldProps: { placeholder: '搜索任务名称或域名' },
    },
    { title: '证书域名', dataIndex: 'domain', width: 220, search: false },
    { title: '证书账号', dataIndex: 'accountName', search: false, width: 160 },
    {
      title: '状态',
      search: false,
      width: 95,
      render: (_, item) => (
        <Tag color={item.enabled ? 'success' : 'default'}>
          {item.enabled ? '启用' : '停用'}
        </Tag>
      ),
    },
    {
      title: '周期',
      search: false,
      width: 100,
      render: (_, item) =>
        `每 ${item.intervalValue} ${scheduleUnitNames[item.intervalUnit] || item.intervalUnit}`,
    },
    {
      title: '下次执行（上海时间）',
      dataIndex: 'nextRunAtUtc',
      search: false,
      width: 200,
      render: (_, item) => deploymentDateText(item.nextRunAtUtc),
    },
    {
      title: '最近申请与部署',
      search: false,
      width: 230,
      render: (_, item) =>
        item.latestRun ? (
          <>
            <ScheduleStateTag state={item.latestRun.status} />
            <div style={{ color: '#666' }}>
              {item.latestRun.message || '等待后台推进'}
            </div>
          </>
        ) : (
          '尚未执行'
        ),
    },
    {
      title: '旧证书清理',
      search: false,
      width: 160,
      render: (_, item) =>
        item.latestRun ? (
          <ScheduleStateTag state={item.latestRun.cleanupStatus} cleanup />
        ) : item.revokeOldCertificates ? (
          '已开启，等待首次执行'
        ) : (
          '未开启'
        ),
    },
    {
      title: '操作',
      valueType: 'option',
      fixed: 'right',
      width: 300,
      render: (_, item) => (
        <Space size={0} wrap>
          <Button
            type="link"
            loading={busyIds.has(item.id)}
            onClick={() => edit(item)}
          >
            编辑
          </Button>
          <Button
            type="link"
            disabled={busyIds.has(item.id)}
            onClick={() =>
              item.enabled
                ? void toggle(item)
                : Modal.confirm({
                    title: `启用计划 · ${item.name}`,
                    content: permissionText(item),
                    okText: '确认启用',
                    cancelText: '取消',
                    onOk: () => toggle(item),
                  })
            }
          >
            {item.enabled ? '停用' : '启用'}
          </Button>
          <Button
            type="link"
            disabled={
              !item.enabled || !!item.latestRun?.active || busyIds.has(item.id)
            }
            onClick={() =>
              Modal.confirm({
                title: `立即执行一次 · ${item.name}`,
                content: (
                  <>
                    {permissionText(item)}
                    <p>
                      立即执行不改变周期锚点；同一计划有进行中的轮次时不会重复启动。
                    </p>
                  </>
                ),
                okText: '确认立即执行',
                cancelText: '取消',
                onOk: () => run(item),
              })
            }
          >
            立即执行
          </Button>
          <Button type="link" onClick={() => setHistorySchedule(item)}>
            运行历史
          </Button>
        </Space>
      ),
    },
  ];
  return (
    <PageContainer
      title="计划任务"
      subTitle="按业务域名周期申请新证书，签发后自动部署到明确选择的目标"
    >
      <Alert
        type="info"
        showIcon
        title="后台独立调度，关闭浏览器不影响执行。申请、部署和旧证书清理分别记录；结果需核对时可在运行历史处理。"
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
      <ProTable<CertificateSchedule>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        {...tablePreferences}
        scroll={{ x: 1660 }}
        request={async ({ current, pageSize, name, domain }) => {
          const result = await certificateScheduleApi.list({
            page: current,
            pageSize,
            search: name || domain,
          });
          setError(result.success ? '' : result.message);
          setActive(
            (result.data?.items || []).some(
              (item) =>
                item.latestRun?.active &&
                item.latestRun.status !== 'NeedsAttention' &&
                item.latestRun.status !== 'Paused',
            ),
          );
          return tableResult(result);
        }}
        toolBarRender={() => [
          <Button
            key="new"
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setEditing(undefined);
              setOpen(true);
            }}
          >
            新建计划任务
          </Button>,
        ]}
      />
      <ScheduleForm
        open={open}
        schedule={editing}
        onClose={() => setOpen(false)}
        onSaved={reload}
      />
      <RunHistory
        schedule={historySchedule}
        onClose={() => setHistorySchedule(undefined)}
        onChanged={reload}
      />
    </PageContainer>
  );
}
