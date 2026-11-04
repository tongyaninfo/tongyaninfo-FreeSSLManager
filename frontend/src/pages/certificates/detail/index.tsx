import {
  ModalForm,
  PageContainer,
  ProFormSelect,
} from '@ant-design/pro-components';
import { history, useAccess, useParams } from '@umijs/max';
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Modal,
  Select,
  Space,
  Table,
} from 'antd';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import DeployModal from '@/components/ssl-manager/deployment/DeployModal';
import {
  dateText,
  providerNames,
  ReadonlyNotice,
  StatusTag,
  useResultMessage,
} from '@/components/ssl-manager';
import {
  certificateApi,
  downloadCertificate,
} from '@/services/ssl-manager/api';
import {
  certificateCapabilities,
  certificateDownloadFormats,
  certificateEnvironmentName,
  certificateUsage,
} from '@/services/ssl-manager/certificatePresentation';
import type {
  CertificateDetail,
  CertificateTask,
  ValidationRecord,
} from '@/services/ssl-manager/types';

/** 证书签发与验证记录清理分别展示，清理失败不覆盖已签发状态。 */
export default function Detail() {
  const { id = '' } = useParams<{ id: string }>();
  const access = useAccess();
  const showResult = useResultMessage();
  const [detail, setDetail] = useState<CertificateDetail>();
  const loadSequence = useRef(0);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [downloadOpen, setDownloadOpen] = useState(false);
  const [deployOpen, setDeployOpen] = useState(false);
  const [format, setFormat] = useState('nginx');
  const [downloading, setDownloading] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const load = useCallback(async () => {
    const sequence = ++loadSequence.current;
    setLoading(true);
    const result = await certificateApi.detail(id);
    if (sequence !== loadSequence.current) return;
    if (result.success) {
      setDetail(result.data);
      setError('');
    } else setError(result.message);
    setLoading(false);
  }, [id]);
  useEffect(() => {
    setDetail(undefined);
    load();
    return () => {
      loadSequence.current += 1;
    };
  }, [load]);
  const certificate = detail?.certificate;
  const pending =
    certificate &&
    (['PendingValidation', 'Processing', 'Revoking'].includes(
      certificate.status,
    ) ||
      ['Pending', 'Running', 'RetryPending'].includes(
        certificate.cleanupStatus ?? '',
      ));
  useEffect(() => {
    if (!pending) return undefined;
    const timer = window.setInterval(load, 10000);
    return () => window.clearInterval(timer);
  }, [pending, load]);
  const capabilities = certificateCapabilities(certificate);
  return (
    <PageContainer
      title={certificate?.domain || '证书详情'}
      subTitle={certificate?.alias}
      onBack={() => history.push('/certificates')}
      extra={
        <Space>
          <Button loading={loading} onClick={load}>
            刷新状态
          </Button>
          {access.canAdmin && (
            <>
              <Button
                danger
                disabled={!capabilities.cancel}
                loading={cancelling}
                onClick={async () => {
                  setCancelling(true);
                  const result = await certificateApi.cancel(id);
                  setCancelling(false);
                  if (showResult(result, '取消审核请求已提交')) load();
                }}
              >
                取消审核
              </Button>
              <Button
                disabled={!capabilities.download}
                onClick={() => setDownloadOpen(true)}
              >
                下载证书
              </Button>
              <Button
                disabled={!capabilities.deploy}
                onClick={() => setDeployOpen(true)}
              >
                部署
              </Button>
              <Button
                danger
                disabled={!capabilities.revoke}
                onClick={() => setRevokeOpen(true)}
              >
                吊销证书
              </Button>
            </>
          )}
        </Space>
      }
    >
      <DeployModal
        certificate={deployOpen ? certificate : undefined}
        onClose={() => setDeployOpen(false)}
      />
      <ReadonlyNotice />
      {error && (
        <Alert
          type="error"
          title={error}
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}
      {certificate && (
        <>
          <Card title="证书信息" style={{ marginBottom: 16 }}>
            <Descriptions
              column={{ xs: 1, md: 2 }}
              items={[
                {
                  key: 'domain',
                  label: '绑定域名',
                  children: certificate.domain,
                },
                {
                  key: 'provider',
                  label: '云平台',
                  children: providerNames[certificate.provider],
                },
                {
                  key: 'type',
                  label: '签发环境',
                  children: certificateEnvironmentName(certificate),
                },
                {
                  key: 'account',
                  label: '所属账号',
                  children: certificate.accountName || certificate.accountId,
                },
                {
                  key: 'id',
                  label: '云端证书 ID',
                  children: certificate.certificateId || '待云平台返回',
                },
                {
                  key: 'status',
                  label: '证书状态',
                  children: <StatusTag value={certificate.status} />,
                },
                {
                  key: 'raw',
                  label: '平台原始状态',
                  children: certificate.rawStatus || '—',
                },
                {
                  key: 'start',
                  label: '有效期开始',
                  children: dateText(certificate.notBeforeUtc),
                },
                {
                  key: 'end',
                  label: '有效期截止',
                  children: dateText(certificate.notAfterUtc),
                },
                {
                  key: 'mode',
                  label: '验证方式',
                  children: certificate.validationMode,
                },
                {
                  key: 'cleanup',
                  label: '验证记录清理',
                  children: <StatusTag value={certificate.cleanupStatus} />,
                },
                {
                  key: 'auto',
                  label: '自动清理',
                  children: certificate.autoCleanup ? '开启' : '关闭',
                },
                {
                  key: 'sync',
                  label: '最近同步',
                  children: dateText(certificate.syncedAtUtc),
                },
              ]}
            />
            <Alert
              type={!certificate.isStaging ? 'info' : 'warning'}
              showIcon
              title={certificateUsage(certificate)}
              style={{ marginBottom: 16 }}
            />
            {certificate.status === 'SubmissionUnknown' && (
              <Alert
                type="warning"
                title="申请提交结果待核对。请先同步证书或核对云平台后台，确认后再处理，避免重复占用额度。"
                showIcon
              />
            )}
            {certificate.errorMessage && (
              <Alert type="error" title={certificate.errorMessage} showIcon />
            )}
          </Card>
          <Card
            title="域名验证与 DNS 清理"
            style={{ marginBottom: 16 }}
            extra={
              access.canAdmin && (
                <Button
                  loading={retrying}
                  disabled={
                    !certificate.autoCleanup ||
                    !['Failed', 'RetryPending', 'PartialFailed'].includes(
                      certificate.cleanupStatus ?? '',
                    )
                  }
                  onClick={async () => {
                    setRetrying(true);
                    const result = await certificateApi.retryCleanup(id);
                    setRetrying(false);
                    if (showResult(result, '清理重试已提交')) load();
                  }}
                >
                  重试清理
                </Button>
              )
            }
          >
            <Alert
              type="info"
              title="自动清理只作用于本次申请创建的验证记录。复用的已有记录和记录值已变化的记录不会直接删除。"
              showIcon
              style={{ marginBottom: 16 }}
            />
            <Table<ValidationRecord>
              rowKey={(item, index) => item.id || `${item.name}-${index}`}
              size="small"
              dataSource={detail.validations}
              pagination={false}
              scroll={{ x: 1000 }}
              columns={[
                { title: '域名', dataIndex: 'domain' },
                { title: '主机记录 / 文件路径', dataIndex: 'name' },
                { title: '类型', dataIndex: 'type' },
                {
                  title: '记录值 / 文件内容',
                  dataIndex: 'value',
                  render: (value) => (
                    <span style={{ overflowWrap: 'anywhere' }}>{value}</span>
                  ),
                },
                {
                  title: '本次创建',
                  dataIndex: 'createdBySystem',
                  render: (value) => (value ? '是' : '否 / 云平台托管'),
                },
                {
                  title: '状态',
                  dataIndex: 'status',
                  render: (value) => <StatusTag value={value} />,
                },
                { title: '说明', dataIndex: 'message' },
              ]}
            />
          </Card>
          <Card title="异步任务进度">
            <Table<CertificateTask>
              rowKey={(item, index) => item.id || String(index)}
              size="small"
              dataSource={detail.tasks}
              pagination={false}
              scroll={{ x: 1000 }}
              columns={[
                { title: '任务', dataIndex: 'kind' },
                {
                  title: '状态',
                  dataIndex: 'status',
                  render: (value) => <StatusTag value={value} />,
                },
                { title: '尝试次数', dataIndex: 'attempts' },
                { title: '处理结果', dataIndex: 'message' },
                {
                  title: '创建时间',
                  dataIndex: 'createdAtUtc',
                  render: (value) => dateText(value),
                },
                {
                  title: '下次处理',
                  dataIndex: 'nextRunAtUtc',
                  render: (value) => dateText(value),
                },
                { title: '请求 ID', dataIndex: 'requestId' },
              ]}
            />
          </Card>
        </>
      )}
      <Modal
        title="下载 SSL 证书"
        open={downloadOpen}
        onCancel={() => setDownloadOpen(false)}
        footer={
          <Space>
            <Button onClick={() => setDownloadOpen(false)}>取消</Button>
            <Button
              type="primary"
              disabled={!capabilities.download}
              loading={downloading}
              onClick={async () => {
                setDownloading(true);
                const result = await downloadCertificate(
                  id,
                  format,
                  certificate?.domain,
                );
                setDownloading(false);
                if (showResult(result, '证书已下载')) setDownloadOpen(false);
              }}
            >
              下载
            </Button>
          </Space>
        }
      >
        <Alert
          type="warning"
          title="下载包可能包含证书私钥，请妥善保存。下载操作会记录审计日志。"
          showIcon
          style={{ marginBottom: 16 }}
        />
        <Select
          aria-label="服务器格式"
          style={{ width: '100%' }}
          value={format}
          onChange={setFormat}
          options={
            certificate
              ? certificateDownloadFormats(certificate).map(
                  ({ key, label }) => ({ value: key, label }),
                )
              : []
          }
        />
      </Modal>
      <ModalForm
        title="吊销 SSL 证书"
        open={revokeOpen}
        onOpenChange={setRevokeOpen}
        modalProps={{
          destroyOnHidden: true,
          okText: '确认吊销',
          okButtonProps: { danger: true },
        }}
        onFinish={async (values) => {
          const result = await certificateApi.revoke(id, values.reason);
          if (!showResult(result, '吊销申请已提交')) return false;
          load();
          return true;
        }}
      >
        <Alert
          title="吊销操作不可撤回，可能影响使用此证书的网站服务。请确认已替换证书。"
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
        />
        <ProFormSelect
          name="reason"
          label="吊销原因"
          options={[
            { label: '私钥泄露', value: 'keyCompromise' },
            { label: '证书已被替换', value: 'superseded' },
            { label: '停止使用', value: 'cessationOfOperation' },
          ]}
          rules={[{ required: true, message: '请选择吊销原因' }]}
        />
      </ModalForm>
    </PageContainer>
  );
}
