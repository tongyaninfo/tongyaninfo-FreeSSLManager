import { PlusOutlined, SyncOutlined } from '@ant-design/icons';
import {
  type ActionType,
  PageContainer,
  type ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { history, useAccess, useIntl } from '@umijs/max';
import {
  Alert,
  App,
  Button,
  Descriptions,
  Dropdown,
  Modal,
  Select,
  Space,
  Table,
} from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import {
  dateText,
  providerNames,
  ReadonlyNotice,
  StatusTag,
  statusNames,
  tableResult,
  useCloudAccounts,
  useResultMessage,
  useTableKeyboardPagination,
  useTablePreferences,
} from '@/components/ssl-manager';
import DeployModal from '@/components/ssl-manager/deployment/DeployModal';
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
  Certificate,
  CertificateDetail,
  CertificateTask,
  ValidationRecord,
} from '@/services/ssl-manager/types';

export default function Certificates() {
  const intl = useIntl();
  const t = (id: string, fallback: string) =>
    intl.formatMessage({ id, defaultMessage: fallback });
  const access = useAccess();
  const showResult = useResultMessage();
  const { modal } = App.useApp();
  const { accounts, error: accountError } = useCloudAccounts();
  const actionRef = useRef<ActionType>(null);
  const pageState = useRef({ current: 1, pageSize: 20, total: 0 });
  const tablePreferences = useTablePreferences('certificates');
  const trackPage = useTableKeyboardPagination(actionRef, pageState);
  const [accountId, setAccountId] = useState<string>();
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState('');
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detail, setDetail] = useState<CertificateDetail>();
  const [detailId, setDetailId] = useState('');
  const [downloadFormat, setDownloadFormat] = useState('nginx');
  const [downloadingIds, setDownloadingIds] = useState<Set<string>>(
    () => new Set(),
  );
  const [revoking, setRevoking] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [hasDeleting, setHasDeleting] = useState(false);
  const [deployingCertificate, setDeployingCertificate] =
    useState<Certificate>();

  // 按证书分别记录下载进度，避免其他行或详情弹窗显示无关的加载状态。
  const handleDownload = async (id: string, format: string, domain: string) => {
    if (downloadingIds.has(id)) return;
    setDownloadingIds((ids) => new Set(ids).add(id));
    try {
      const result = await downloadCertificate(id, format, domain);
      showResult(result, '证书已下载');
    } finally {
      setDownloadingIds((ids) => {
        const remaining = new Set(ids);
        remaining.delete(id);
        return remaining;
      });
    }
  };

  // 云端删除通常是异步任务。列表存在“删除中”证书时定时刷新，避免用户手动刷新。
  useEffect(() => {
    if (!hasDeleting) return undefined;
    const timer = window.setInterval(() => {
      actionRef.current?.reload();
    }, 10_000);
    return () => window.clearInterval(timer);
  }, [hasDeleting]);
  const openDetail = async (item: Certificate) => {
    setDetailId(item.id);
    setDetail(undefined);
    setDetailOpen(true);
    setDetailLoading(true);
    const result = await certificateApi.detail(item.id);
    setDetailLoading(false);
    if (result.success) setDetail(result.data);
    else showResult(result);
  };
  const reloadAfterAction = () => {
    setDetailOpen(false);
    setDetail(undefined);
    setSelectedRowKeys([]);
    actionRef.current?.reload();
  };
  /** 批量接口的成功只表示请求已处理，删除结果必须逐张核对后再提示或关闭详情。 */
  const handleDelete = async (ids: string[]) => {
    const result = await certificateApi.delete(ids);
    if (!result.success) return showResult(result);
    const items = result.data ?? [];
    const accepted = new Set(
      items.filter((item) => item.success).map((item) => item.id),
    );
    setSelectedRowKeys((keys) =>
      keys.filter((key) => !accepted.has(String(key))),
    );
    const failures = ids.flatMap((id) => {
      const item = items.find((value) => value.id === id);
      if (item?.success) return [];
      return [
        `${id}：${item?.message || item?.code || '服务器未返回该证书的删除结果，请刷新核对'}`,
      ];
    });
    if (failures.length > 0)
      return showResult({
        ...result,
        success: false,
        message: failures.join('；'),
      });
    const messages = [
      ...new Set(items.map((item) => item.message).filter(Boolean)),
    ];
    return showResult(
      result,
      messages.join('；') || result.message || '删除请求已处理',
    );
  };
  const columns: ProColumns<Certificate>[] = [
    {
      title: '列表范围',
      dataIndex: 'freeOnly',
      hideInTable: true,
      initialValue: 'false',
      valueEnum: { true: '仅免费证书', false: '全部证书' },
    },
    {
      title: t('ssl.column.boundDomain', '绑定域名'),
      dataIndex: 'domain',
      render: (_, item) => (
        <Button type="link" onClick={() => openDetail(item)}>
          {item.domain || '待补充域名'}
        </Button>
      ),
    },
    {
      title: t('ssl.column.alias', '备注名称'),
      dataIndex: 'alias',
      search: false,
    },
    {
      title: t('ssl.field.provider', '云平台'),
      dataIndex: 'provider',
      valueEnum: {
        TencentCloud: providerNames.TencentCloud,
        Aliyun: providerNames.Aliyun,
        Acme: providerNames.Acme,
      },
    },
    {
      title: t('ssl.column.account', '所属配置'),
      dataIndex: 'accountName',
      search: false,
    },
    {
      title: '收费属性',
      dataIndex: 'isFree',
      search: false,
      render: (_, item) =>
        item.isFree === true
          ? '免费证书'
          : item.isFree === false
            ? '付费证书'
            : '类型待核对',
    },
    {
      title: t('ssl.column.certificateStatus', '证书状态'),
      dataIndex: 'status',
      search: true,
      valueEnum: Object.fromEntries(
        [
          'PendingValidation',
          'Processing',
          'Issued',
          'Expired',
          'Deleting',
          'Revoking',
          'Revoked',
          'Failed',
          'Cancelled',
          'SubmissionUnknown',
          'Unknown',
        ].map((status) => [status, statusNames[status]]),
      ),
      render: (_, item) => <StatusTag value={item.status} />,
    },
    {
      title: '签发环境',
      dataIndex: 'isStaging',
      search: false,
      render: (_, item) => (
        <span title={certificateUsage(item)}>
          {certificateEnvironmentName(item)}
        </span>
      ),
    },
    {
      title: t('ssl.column.expiry', '到期时间'),
      dataIndex: 'notAfterUtc',
      search: false,
      render: (_, item) => dateText(item.notAfterUtc),
    },
    {
      title: t('ssl.column.actions', '操作'),
      valueType: 'option',
      render: (_, item) => (
        <Space size={0} wrap>
          <Button type="link" onClick={() => openDetail(item)}>
            详情
          </Button>
          {access.canAdmin && (
            <>
              <Dropdown
                trigger={['hover']}
                placement="bottomLeft"
                disabled={!certificateCapabilities(item).download}
                menu={{
                  items: certificateDownloadFormats(item),
                  onClick: ({ key }) =>
                    handleDownload(item.id, key, item.domain),
                }}
              >
                <Button
                  type="link"
                  disabled={!certificateCapabilities(item).download}
                  loading={downloadingIds.has(item.id)}
                >
                  下载
                </Button>
              </Dropdown>
              <Button
                type="link"
                disabled={!certificateCapabilities(item).deploy}
                onClick={() => setDeployingCertificate(item)}
              >
                部署
              </Button>
              <Button
                type="link"
                disabled={!certificateCapabilities(item).revoke}
                loading={revoking && detailId === item.id}
                onClick={() =>
                  modal.confirm({
                    title: '确认吊销证书',
                    content: `将吊销 ${item.domain || '该证书'}，吊销后证书将失去信任，是否继续？`,
                    okText: '确认吊销',
                    cancelText: '取消',
                    okButtonProps: { danger: true },
                    onOk: async () => {
                      setRevoking(true);
                      setDetailId(item.id);
                      const result = await certificateApi.revoke(
                        item.id,
                        '管理员在证书列表发起吊销',
                      );
                      setRevoking(false);
                      if (showResult(result, '吊销请求已提交'))
                        actionRef.current?.reload();
                    },
                  })
                }
              >
                吊销
              </Button>
              <Button
                type="link"
                disabled={!certificateCapabilities(item).cancel}
                loading={cancelling && detailId === item.id}
                onClick={() =>
                  modal.confirm({
                    title: '确认取消审核',
                    content: `将取消 ${item.domain || '该证书'} 的云端申请审核，取消后可删除本地记录，是否继续？`,
                    okText: '确认取消',
                    cancelText: '返回',
                    okButtonProps: { danger: true },
                    onOk: async () => {
                      setCancelling(true);
                      setDetailId(item.id);
                      const result = await certificateApi.cancel(item.id);
                      setCancelling(false);
                      if (showResult(result, '取消审核请求已提交'))
                        actionRef.current?.reload();
                    },
                  })
                }
              >
                取消审核
              </Button>
              {item.provider !== 'Cloudflare' && (
                <Button
                  type="link"
                  danger
                  disabled={!certificateCapabilities(item).remove}
                  loading={deleting && detailId === item.id}
                  onClick={() =>
                    modal.confirm({
                      title: '确认删除证书',
                      content: `将从云平台删除并移除本地记录中的 ${item.domain || '该证书'}（仅允许删除已过期、已吊销或已取消证书），是否继续？`,
                      okText: '确认删除',
                      cancelText: '取消',
                      okButtonProps: { danger: true },
                      onOk: async () => {
                        setDeleting(true);
                        setDetailId(item.id);
                        await handleDelete([item.id]);
                        setDeleting(false);
                        actionRef.current?.reload();
                      },
                    })
                  }
                >
                  删除
                </Button>
              )}
            </>
          )}
        </Space>
      ),
    },
  ];
  return (
    <PageContainer
      title={intl.formatMessage({
        id: 'ssl.page.certificates.title',
        defaultMessage: 'SSL 证书管理',
      })}
      subTitle={intl.formatMessage({
        id: 'ssl.page.certificates.subtitle',
        defaultMessage:
          '同步云端证书、跟踪申请进度，并在签发成功后清理本次创建的验证记录',
      })}
    >
      <ReadonlyNotice />
      <Alert
        type="info"
        showIcon
        title="免费额度、证书有效期及 API 能力以云平台实际返回为准。结果待核对的申请请先同步查询，避免重复提交。"
        style={{ marginBottom: 16 }}
      />
      {(error || accountError) && (
        <Alert
          type="error"
          title={error || accountError}
          style={{ marginBottom: 16 }}
        />
      )}
      <ProTable<Certificate>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        {...tablePreferences}
        rowSelection={
          access.canAdmin
            ? {
                selectedRowKeys,
                onChange: (keys) => setSelectedRowKeys(keys),
                getCheckboxProps: (item) => ({
                  disabled: !certificateCapabilities(item).remove,
                }),
              }
            : undefined
        }
        // 默认展开三个查询条件；避免 ProTable 按当前窗口宽度自动退化成只显示两个。
        search={{ defaultFormItemsNumber: 3 }}
        scroll={{ x: 1400 }}
        request={async ({ current, pageSize, ...params }) => {
          const result = await certificateApi.list({
            ...params,
            search: params.domain,
            status: params.status,
            // 默认展示云端同步的完整证书快照；需要时再切换为“仅免费证书”。
            freeOnly: params.freeOnly === 'true' || params.freeOnly === true,
            page: current,
            pageSize,
          });
          const items = result.data?.items ?? [];
          setHasDeleting(
            result.success && items.some((item) => item.status === 'Deleting'),
          );
          setError(result.success ? '' : result.message);
          trackPage(current, pageSize, result.data?.total);
          return tableResult(result);
        }}
        toolBarRender={() =>
          access.canAdmin
            ? [
                <Select
                  key="account"
                  aria-label="选择证书账号"
                  placeholder="选择证书账号"
                  style={{ width: 260 }}
                  value={accountId}
                  onChange={setAccountId}
                  options={accounts
                    .filter(
                      (item) =>
                        item.provider !== 'Cloudflare' &&
                        item.enabled &&
                        item.useForCertificates,
                    )
                    .map((item) => ({
                      label: `${providerNames[item.provider]} / ${item.name}`,
                      value: item.id,
                    }))}
                />,
                <Button
                  key="sync"
                  icon={<SyncOutlined />}
                  loading={syncing}
                  disabled={!accountId}
                  onClick={async () => {
                    if (!accountId) return;
                    setSyncing(true);
                    const result = await certificateApi.sync(accountId);
                    setSyncing(false);
                    showResult(result, '证书同步完成');
                    actionRef.current?.reload();
                  }}
                >
                  同步证书
                </Button>,
                <Button
                  key="apply"
                  type="primary"
                  icon={<PlusOutlined />}
                  onClick={() => history.push('/certificates/apply')}
                >
                  申请免费证书
                </Button>,
                ...(selectedRowKeys.length > 0
                  ? [
                      <Button
                        key="delete-selected"
                        danger
                        onClick={() =>
                          modal.confirm({
                            title: '确认删除证书',
                            content: `将从云平台删除并移除本地记录中的 ${selectedRowKeys.length} 张已过期、已吊销或已取消证书。云端删除可能因关联资源或权限失败，是否继续？`,
                            okText: '确认删除',
                            cancelText: '取消',
                            okButtonProps: { danger: true },
                            onOk: async () => {
                              await handleDelete(selectedRowKeys.map(String));
                              actionRef.current?.reload();
                            },
                          })
                        }
                      >
                        删除已选证书
                      </Button>,
                    ]
                  : []),
              ]
            : []
        }
      />
      <DeployModal
        certificate={deployingCertificate}
        onClose={() => setDeployingCertificate(undefined)}
      />
      <Modal
        title={`证书详情${detail?.certificate?.domain ? ` · ${detail.certificate.domain}` : ''}`}
        open={detailOpen}
        width={1000}
        confirmLoading={detailLoading}
        onCancel={() => setDetailOpen(false)}
        footer={
          detail?.certificate ? (
            <Space>
              <Select
                aria-label="下载格式"
                value={downloadFormat}
                onChange={setDownloadFormat}
                style={{ minWidth: 220 }}
                popupMatchSelectWidth={240}
                options={certificateDownloadFormats(detail.certificate).map(
                  ({ key, label }) => ({ value: key, label }),
                )}
              />
              <Button
                disabled={
                  !access.canAdmin ||
                  !certificateCapabilities(detail.certificate).download
                }
                loading={downloadingIds.has(detailId)}
                onClick={() =>
                  handleDownload(
                    detailId,
                    downloadFormat,
                    detail.certificate.domain,
                  )
                }
              >
                下载
              </Button>
              {access.canAdmin && (
                <Button
                  disabled={!certificateCapabilities(detail.certificate).deploy}
                  onClick={() => setDeployingCertificate(detail.certificate)}
                >
                  部署
                </Button>
              )}
              {detail.certificate.provider !== 'Cloudflare' && (
                <Button
                  danger
                  disabled={
                    !access.canAdmin ||
                    !certificateCapabilities(detail.certificate).remove
                  }
                  loading={deleting}
                  onClick={() =>
                    modal.confirm({
                      title: '确认删除证书',
                      content:
                        '仅允许删除已过期、已吊销或已取消证书。云平台确认删除后才会移除本地记录，是否继续？',
                      okText: '确认删除',
                      cancelText: '取消',
                      okButtonProps: { danger: true },
                      onOk: async () => {
                        setDeleting(true);
                        const success = await handleDelete([detailId]);
                        setDeleting(false);
                        if (success) reloadAfterAction();
                        else actionRef.current?.reload();
                      },
                    })
                  }
                >
                  删除
                </Button>
              )}
              <Button
                danger
                disabled={
                  !access.canAdmin ||
                  !certificateCapabilities(detail.certificate).cancel
                }
                loading={cancelling}
                onClick={() =>
                  modal.confirm({
                    title: '确认取消审核',
                    content:
                      '将取消云端证书申请审核，取消后可以删除证书记录，是否继续？',
                    okText: '确认取消',
                    cancelText: '返回',
                    okButtonProps: { danger: true },
                    onOk: async () => {
                      setCancelling(true);
                      const result = await certificateApi.cancel(detailId);
                      setCancelling(false);
                      if (showResult(result, '取消审核请求已提交'))
                        reloadAfterAction();
                    },
                  })
                }
              >
                取消审核
              </Button>
              <Button
                danger
                disabled={
                  !access.canAdmin ||
                  !certificateCapabilities(detail.certificate).revoke
                }
                loading={revoking}
                onClick={() =>
                  modal.confirm({
                    title: '确认吊销证书',
                    content: '吊销后证书将失去信任，是否继续？',
                    okText: '确认吊销',
                    cancelText: '取消',
                    okButtonProps: { danger: true },
                    onOk: async () => {
                      setRevoking(true);
                      const result = await certificateApi.revoke(
                        detailId,
                        '管理员在证书详情发起吊销',
                      );
                      setRevoking(false);
                      if (showResult(result, '吊销请求已提交')) {
                        setDetailOpen(false);
                        actionRef.current?.reload();
                      }
                    },
                  })
                }
              >
                吊销
              </Button>
              <Button onClick={() => setDetailOpen(false)}>关闭</Button>
            </Space>
          ) : (
            <Button onClick={() => setDetailOpen(false)}>关闭</Button>
          )
        }
      >
        {detail?.certificate && (
          <>
            <Descriptions
              size="small"
              column={2}
              items={[
                {
                  key: 'domain',
                  label: '绑定域名',
                  children: detail.certificate.domain || '—',
                },
                {
                  key: 'provider',
                  label: '云平台',
                  children:
                    providerNames[detail.certificate.provider] ||
                    detail.certificate.provider,
                },
                {
                  key: 'type',
                  label: '签发环境',
                  children: certificateEnvironmentName(detail.certificate),
                },
                {
                  key: 'account',
                  label: '所属配置',
                  children:
                    detail.certificate.accountName ||
                    detail.certificate.accountId,
                },
                {
                  key: 'status',
                  label: '证书状态',
                  children: <StatusTag value={detail.certificate.status} />,
                },
                {
                  key: 'raw',
                  label: '平台原始状态',
                  children: detail.certificate.rawStatus || '—',
                },
                {
                  key: 'start',
                  label: '有效期开始',
                  children: dateText(detail.certificate.notBeforeUtc),
                },
                {
                  key: 'end',
                  label: '有效期截止',
                  children: dateText(detail.certificate.notAfterUtc),
                },
              ]}
            />
            <Alert
              type={!detail.certificate.isStaging ? 'info' : 'warning'}
              showIcon
              title={certificateUsage(detail.certificate)}
              style={{ marginTop: 16 }}
            />
            <Table<ValidationRecord>
              size="small"
              rowKey={(item, index) => item.id || `${item.name}-${index}`}
              dataSource={detail.validations}
              pagination={false}
              style={{ marginTop: 16 }}
              columns={[
                {
                  title: t('ssl.field.validationRecord', '验证记录'),
                  dataIndex: 'name',
                },
                {
                  title: t('ssl.column.recordType', '类型'),
                  dataIndex: 'type',
                },
                {
                  title: t('ssl.column.recordValue', '值'),
                  dataIndex: 'value',
                  ellipsis: true,
                },
                {
                  title: t('ssl.field.status', '状态'),
                  dataIndex: 'status',
                  render: (value) => <StatusTag value={value} />,
                },
              ]}
            />
            <Table<CertificateTask>
              size="small"
              rowKey={(item, index) => item.id || String(index)}
              dataSource={detail.tasks}
              pagination={false}
              style={{ marginTop: 16 }}
              columns={[
                { title: '任务', dataIndex: 'kind' },
                {
                  title: '状态',
                  dataIndex: 'status',
                  render: (value) => <StatusTag value={value} />,
                },
                { title: '处理结果', dataIndex: 'message' },
              ]}
            />
          </>
        )}
      </Modal>
    </PageContainer>
  );
}
