import { history } from '@umijs/max';
import {
  Alert,
  Button,
  Descriptions,
  Modal,
  Select,
  Space,
  Table,
  Tag,
} from 'antd';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useResultMessage } from '@/components/ssl-manager';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import { normalizeDeploymentDomain } from '@/services/ssl-manager/deploymentSource';
import type {
  DeploymentBatch,
  DeploymentPlan,
  DeploymentTarget,
} from '@/services/ssl-manager/deploymentTypes';
import type { Certificate } from '@/services/ssl-manager/types';
import BatchPanel from './BatchPanel';
import {
  deploymentActionNames,
  deploymentDateText,
  isDeploymentActive,
} from './presentation';

/** 选择目标后先预览；提交重试沿用同一幂等键，网络失败不产生重复部署。 */
export default function DeployModal({
  certificate,
  initialPlan,
  onClose,
}: {
  certificate?: Pick<Certificate, 'id' | 'domain' | 'status'> &
    Partial<Pick<Certificate, 'isStaging' | 'canDeploy'>>;
  initialPlan?: DeploymentPlan;
  onClose: () => void;
}) {
  const showResult = useResultMessage();
  const [targets, setTargets] = useState<DeploymentTarget[]>([]);
  const [targetIds, setTargetIds] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [planning, setPlanning] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [plan, setPlan] = useState<DeploymentPlan>();
  const [batch, setBatch] = useState<DeploymentBatch>();
  const requestSequence = useRef(0);
  const idempotencyKey = useRef('');
  const rollbackPlan =
    plan?.targets.some((item) => item.plan.action === 'Rollback') ||
    batch?.operationType === 'Rollback';

  useEffect(() => {
    const sequence = ++requestSequence.current;
    setTargets([]);
    setTargetIds(initialPlan?.targets.map((item) => item.targetId) || []);
    setPlan(initialPlan);
    setBatch(undefined);
    setError('');
    setPlanning(false);
    setSubmitting(false);
    idempotencyKey.current = initialPlan ? crypto.randomUUID() : '';
    if (!certificate) return undefined;
    setLoading(true);
    const loadTargets = async () => {
      // 目标选择不截断在第一页，避免较多目标时漏掉可部署的配置。
      const all: DeploymentTarget[] = [];
      for (let page = 1; ; page += 1) {
        const result = await deploymentApi.targets({ page, pageSize: 200 });
        if (sequence !== requestSequence.current) return;
        if (!result.success || !result.data) {
          setLoading(false);
          setError(result.message);
          return;
        }
        all.push(...result.data.items);
        if (!result.data.items.length || all.length >= result.data.total) break;
      }
      setLoading(false);
      // 续签只会改变证书 ID；按主域名匹配既有文件映射，未回填的历史配置保守处理。
      setTargets(
        all.filter(
          (item) =>
            item.enabled &&
            (item.configuration?.sourceDomain
              ? normalizeDeploymentDomain(item.configuration.sourceDomain) ===
                normalizeDeploymentDomain(certificate.domain)
              : !item.configuration?.sourceCertificateId ||
                item.configuration.sourceCertificateId === certificate.id),
        ),
      );
    };
    loadTargets();
    return () => {
      requestSequence.current += 1;
    };
  }, [certificate, initialPlan]);

  const refreshBatch = useCallback(async () => {
    if (!batch?.id) return;
    const sequence = requestSequence.current;
    const result = await deploymentApi.batch(batch.id);
    if (sequence !== requestSequence.current) return;
    if (result.success && result.data) {
      setBatch(result.data);
      setError('');
    } else setError(result.message);
  }, [batch?.id]);

  useEffect(() => {
    if (!certificate || !batch || !isDeploymentActive(batch.status))
      return undefined;
    const timer = window.setTimeout(refreshBatch, 2500);
    return () => window.clearTimeout(timer);
  }, [certificate, batch, refreshBatch]);

  const createPlan = async () => {
    if (!certificate || !targetIds.length) return;
    const sequence = requestSequence.current;
    setPlanning(true);
    setError('');
    const result = await deploymentApi.plan(
      certificate.id,
      targetIds.map((targetId) => ({ targetId })),
    );
    if (sequence !== requestSequence.current) return;
    setPlanning(false);
    if (result.success && result.data) {
      setPlan(result.data);
      idempotencyKey.current = crypto.randomUUID();
    } else setError(result.message);
  };

  const submit = async () => {
    if (!plan) return;
    const sequence = requestSequence.current;
    setSubmitting(true);
    setError('');
    const result = await deploymentApi.submit(
      plan.batchId,
      plan.planRevision,
      idempotencyKey.current,
    );
    if (sequence !== requestSequence.current) return;
    setSubmitting(false);
    if (result.success && result.data) {
      setBatch(result.data);
      showResult(result, '部署任务已提交');
    } else {
      setError(result.message);
      if (result.code === 'PLAN_STALE') setPlan(undefined);
    }
  };

  return (
    <Modal
      title={`${rollbackPlan ? '恢复备份文件' : '部署证书'}${certificate?.domain ? ` · ${certificate.domain}` : ''}`}
      open={!!certificate}
      width={1100}
      onCancel={onClose}
      footer={
        <Space>
          {batch ? (
            <Button
              onClick={() => {
                onClose();
                history.push(
                  `/deployments?batchId=${encodeURIComponent(batch.id)}`,
                );
              }}
            >
              查看部署记录
            </Button>
          ) : (
            <>
              <Button
                onClick={createPlan}
                loading={planning}
                disabled={!targetIds.length || submitting}
              >
                生成部署计划
              </Button>
              <Button
                type="primary"
                onClick={submit}
                loading={submitting}
                disabled={
                  !plan ||
                  planning ||
                  new Date(plan.expiresAtUtc).getTime() <= Date.now()
                }
              >
                {rollbackPlan ? '确认恢复文件' : '确认部署'}
              </Button>
            </>
          )}
          <Button onClick={onClose}>{batch ? '关闭' : '取消'}</Button>
        </Space>
      }
    >
      {error && (
        <Alert
          type="error"
          title={error}
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}
      {batch ? (
        <BatchPanel
          batch={batch}
          onRefresh={refreshBatch}
          onRetryPlan={(nextPlan) => {
            requestSequence.current += 1;
            setBatch(undefined);
            setPlan(nextPlan);
            setTargetIds(nextPlan.targets.map((item) => item.targetId));
            idempotencyKey.current = crypto.randomUUID();
            setError('');
          }}
        />
      ) : (
        <>
          {rollbackPlan && (
            <Alert
              type="warning"
              showIcon
              title="只恢复原任务的备份文件，不会自动执行 reload、重启或其他后置命令。服务当前证书需另行核对。"
              style={{ marginBottom: 16 }}
            />
          )}
          <Alert
            type="info"
            showIcon
            title="提交前先核对目标、覆盖范围和命令。关闭此窗口不会取消已提交的后台部署。"
            style={{ marginBottom: 16 }}
          />
          <Select
            mode="multiple"
            aria-label="选择部署目标"
            placeholder="选择一个或多个已启用的部署目标"
            loading={loading}
            disabled={planning || submitting}
            style={{ width: '100%', marginBottom: 16 }}
            value={targetIds}
            options={targets.map((target) => ({
              value: target.id,
              label: `${target.name} · ${target.endpoint}${target.configuration?.sourceDomain ? ` · 绑定域名：${target.configuration.sourceDomain}` : ''}`,
            }))}
            onChange={(ids) => {
              setTargetIds(ids);
              setPlan(undefined);
              idempotencyKey.current = '';
            }}
            showSearch={{ optionFilterProp: 'label' }}
          />
          {!loading && targets.length === 0 && !error && (
            <Alert
              type="warning"
              title="还没有已启用的部署目标"
              description={
                <Button
                  type="link"
                  onClick={() => {
                    onClose();
                    history.push('/deployment-targets');
                  }}
                >
                  前往创建部署目标
                </Button>
              }
            />
          )}
          {plan && (
            <>
              <Descriptions
                size="small"
                column={2}
                items={[
                  {
                    key: 'domains',
                    label: '证书域名',
                    span: 2,
                    children: (
                      <Space wrap>
                        {plan.certificate.domains.map((domain) => (
                          <Tag key={domain}>{domain}</Tag>
                        ))}
                      </Space>
                    ),
                  },
                  {
                    key: 'expiry',
                    label: '证书到期',
                    children: deploymentDateText(plan.certificate.notAfterUtc),
                  },
                  {
                    key: 'planExpiry',
                    label: '计划有效期',
                    children: deploymentDateText(plan.expiresAtUtc),
                  },
                  {
                    key: 'fingerprint',
                    label: '证书指纹',
                    span: 2,
                    children: (
                      <span style={{ overflowWrap: 'anywhere' }}>
                        {plan.certificate.fingerprint}
                      </span>
                    ),
                  },
                ]}
              />
              <Table<DeploymentPlan['targets'][number]>
                size="small"
                rowKey="taskId"
                dataSource={plan.targets}
                pagination={false}
                style={{ marginTop: 16 }}
                columns={[
                  { title: '目标', dataIndex: 'targetName', width: 180 },
                  {
                    title: '执行动作',
                    width: 140,
                    render: (_, item) =>
                      deploymentActionNames[item.plan.action] ||
                      item.plan.action,
                  },
                  {
                    title: '变更范围',
                    render: (_, item) => (
                      <>
                        <div>{item.plan.summary}</div>
                        {item.plan.filePaths?.map((file) => (
                          <div key={file} style={{ overflowWrap: 'anywhere' }}>
                            {file}
                          </div>
                        ))}
                        {!!item.plan.siteIds?.length && (
                          <div>
                            {item.executorKey.startsWith('synology.')
                              ? '关联服务'
                              : '关联站点'}
                            ：{item.plan.siteIds.join('、')}
                          </div>
                        )}
                        {item.plan.warnings?.map((warning) => (
                          <Alert
                            key={warning}
                            type="warning"
                            title={warning}
                            style={{ marginTop: 8 }}
                          />
                        ))}
                      </>
                    ),
                  },
                ]}
              />
            </>
          )}
        </>
      )}
    </Modal>
  );
}
