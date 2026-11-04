import {
  type ActionType,
  PageContainer,
  type ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { useLocation } from '@umijs/max';
import { Alert, Button, Modal } from 'antd';
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { tableResult, useTablePreferences } from '@/components/ssl-manager';
import BatchPanel, {
  DeploymentStateTag,
} from '@/components/ssl-manager/deployment/BatchPanel';
import DeployModal from '@/components/ssl-manager/deployment/DeployModal';
import {
  deploymentDateText,
  isDeploymentActive,
} from '@/components/ssl-manager/deployment/presentation';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import type {
  DeploymentBatch,
  DeploymentPlan,
} from '@/services/ssl-manager/deploymentTypes';

export default function Deployments() {
  const location = useLocation();
  const actionRef = useRef<ActionType>(null);
  const tablePreferences = useTablePreferences('deployments');
  const [error, setError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [batchId, setBatchId] = useState('');
  const [batch, setBatch] = useState<DeploymentBatch>();
  const [hasActive, setHasActive] = useState(false);
  const [retryPlan, setRetryPlan] = useState<DeploymentPlan>();
  const retryCertificate = useMemo(
    () =>
      retryPlan
        ? {
            id: retryPlan.certificate.certificateId,
            domain: retryPlan.certificate.domain,
            status: 'Issued',
          }
        : undefined,
    [retryPlan],
  );
  const sequence = useRef(0);

  useEffect(() => {
    setBatchId(new URLSearchParams(location.search).get('batchId') || '');
  }, [location.search]);
  const refresh = useCallback(async () => {
    if (!batchId) return;
    const current = sequence.current;
    const result = await deploymentApi.batch(batchId);
    if (current !== sequence.current) return;
    setDetailError(result.success ? '' : result.message);
    if (result.success && result.data) setBatch(result.data);
  }, [batchId]);

  useEffect(() => {
    sequence.current += 1;
    setBatch(undefined);
    setDetailError('');
    refresh();
    return () => {
      sequence.current += 1;
    };
  }, [refresh]);

  useEffect(() => {
    if (!hasActive && !isDeploymentActive(batch?.status)) return undefined;
    const timer = window.setInterval(() => {
      if (document.hidden) return;
      if (hasActive) actionRef.current?.reload();
      if (isDeploymentActive(batch?.status)) refresh();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [hasActive, batch?.status, refresh]);

  const columns: ProColumns<DeploymentBatch>[] = [
    { title: '证书域名', dataIndex: 'certificateDomain', width: 230 },
    {
      title: '状态',
      dataIndex: 'status',
      width: 180,
      search: false,
      render: (_, item) => <DeploymentStateTag state={item.status} />,
    },
    {
      title: '目标数量',
      search: false,
      width: 100,
      render: (_, item) => item.tasks.length,
    },
    {
      title: '创建时间',
      dataIndex: 'createdAtUtc',
      width: 190,
      search: false,
      render: (_, item) => deploymentDateText(item.createdAtUtc),
    },
    {
      title: '证书指纹',
      dataIndex: 'fingerprint',
      width: 320,
      ellipsis: true,
      search: false,
    },
    {
      title: '操作',
      valueType: 'option',
      width: 110,
      render: (_, item) => (
        <Button type="link" onClick={() => setBatchId(item.id)}>
          查看进度
        </Button>
      ),
    },
  ];
  return (
    <PageContainer
      title="部署记录"
      subTitle="每个目标独立记录结果；文件写入、平台更新和 HTTPS 生效分别验证"
    >
      {error && (
        <Alert type="error" title={error} style={{ marginBottom: 16 }} />
      )}
      <ProTable<DeploymentBatch>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        {...tablePreferences}
        scroll={{ x: 1200 }}
        request={async ({ current, pageSize, certificateDomain }) => {
          const result = await deploymentApi.batches({
            page: current,
            pageSize,
            search: certificateDomain,
          });
          setError(result.success ? '' : result.message);
          setHasActive(
            (result.data?.items || []).some((item) =>
              isDeploymentActive(item.status),
            ),
          );
          return tableResult(result);
        }}
      />
      <Modal
        open={!!batchId}
        title="部署批次详情"
        width={1150}
        onCancel={() => setBatchId('')}
        footer={<Button onClick={() => setBatchId('')}>关闭</Button>}
      >
        {detailError && (
          <Alert
            type="error"
            title={detailError}
            style={{ marginBottom: 16 }}
          />
        )}
        {batch ? (
          <BatchPanel
            batch={batch}
            onRefresh={refresh}
            onRetryPlan={(plan) => {
              setBatchId('');
              setRetryPlan(plan);
            }}
          />
        ) : (
          !detailError && <span>正在读取部署记录…</span>
        )}
      </Modal>
      <DeployModal
        certificate={retryCertificate}
        initialPlan={retryPlan}
        onClose={() => {
          setRetryPlan(undefined);
          actionRef.current?.reload();
        }}
      />
    </PageContainer>
  );
}
