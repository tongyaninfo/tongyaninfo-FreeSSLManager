import { PlusOutlined, SyncOutlined } from '@ant-design/icons';
import {
  type ActionType,
  ModalForm,
  PageContainer,
  type ProColumns,
  ProFormDigit,
  ProFormSelect,
  ProFormText,
  ProTable,
} from '@ant-design/pro-components';
import { useAccess, useIntl } from '@umijs/max';
import { Alert, App, Button, Select, Space, Switch, Table } from 'antd';
import React, { useRef, useState } from 'react';
import {
  dateText,
  providerNames,
  ReadonlyNotice,
  StatusTag,
  tableResult,
  useTableKeyboardPagination,
  useTablePreferences,
  useCloudAccounts,
  useResultMessage,
} from '@/components/ssl-manager';
import { domainApi } from '@/services/ssl-manager/api';
import type { DnsRecord, DnsZone } from '@/services/ssl-manager/types';

export default function Domains() {
  const intl = useIntl();
  const t = (id: string, fallback: string) =>
    intl.formatMessage({ id, defaultMessage: fallback });
  const access = useAccess();
  const showResult = useResultMessage();
  const { modal } = App.useApp();
  const { accounts, error: accountError } = useCloudAccounts();
  const actionRef = useRef<ActionType>(null);
  const pageState = useRef({ current: 1, pageSize: 20, total: 0 });
  const tablePreferences = useTablePreferences('domains');
  const trackPage = useTableKeyboardPagination(actionRef, pageState);
  const [accountId, setAccountId] = useState<string>();
  const [syncing, setSyncing] = useState(false);
  const [zone, setZone] = useState<DnsZone>();
  const [recordsByZone, setRecordsByZone] = useState<
    Record<string, DnsRecord[]>
  >({});
  const [recordsLoading, setRecordsLoading] = useState<Record<string, boolean>>(
    {},
  );
  const [mutatingId, setMutatingId] = useState('');
  const [recordOpen, setRecordOpen] = useState(false);
  const [editing, setEditing] = useState<DnsRecord>();
  const [error, setError] = useState('');
  const [expandedRowKeys, setExpandedRowKeys] = useState<string[]>([]);
  const loadRecords = async (selected: DnsZone) => {
    setRecordsLoading((current) => ({ ...current, [selected.id]: true }));
    const result = await domainApi.records(selected.id);
    if (showResult(result)) {
      setRecordsByZone((current) => ({
        ...current,
        [selected.id]: result.data ?? [],
      }));
    }
    setRecordsLoading((current) => ({ ...current, [selected.id]: false }));
  };
  const toggleExpanded = (selected: DnsZone) => {
    setZone(selected);
    const expanded = expandedRowKeys.includes(selected.id);
    setExpandedRowKeys((current) =>
      expanded
        ? current.filter((key) => key !== selected.id)
        : [...current, selected.id],
    );
  };
  const columns: ProColumns<DnsZone>[] = [
    {
      title: t('ssl.field.domain', '域名'),
      dataIndex: 'name',
      render: (_, item) => (
        <Button type="link" onClick={() => toggleExpanded(item)}>
          {item.name || item.domain}
        </Button>
      ),
    },
    {
      title: t('ssl.field.provider', '云平台'),
      dataIndex: 'provider',
      valueEnum: providerNames,
    },
    {
      title: t('ssl.column.account', '所属配置'),
      dataIndex: 'accountName',
      search: false,
    },
    {
      title: t('ssl.field.lastSyncAt', '同步时间'),
      dataIndex: 'syncedAtUtc',
      search: false,
      render: (_, item) => dateText(item.syncedAtUtc),
    },
    {
      title: t('ssl.column.actions', '操作'),
      valueType: 'option',
      render: (_, item) => (
        <Button type="link" onClick={() => toggleExpanded(item)}>
          解析记录
        </Button>
      ),
    },
  ];
  return (
    <PageContainer
      title={intl.formatMessage({
        id: 'ssl.page.domains.title',
        defaultMessage: '域名管理',
      })}
      subTitle={intl.formatMessage({
        id: 'ssl.page.domains.subtitle',
        defaultMessage: '从 DNS 托管账号同步域名，并管理域名验证所需的解析记录',
      })}
    >
      <ReadonlyNotice />
      {(error || accountError) && (
        <Alert
          type="error"
          title={error || accountError}
          style={{ marginBottom: 16 }}
        />
      )}
      <ProTable<DnsZone>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        {...tablePreferences}
        expandable={{
          expandedRowKeys,
          expandedRowRender: (item) => (
            <div>
              <Space style={{ marginBottom: 12 }}>
                <Button
                  loading={recordsLoading[item.id]}
                  onClick={() => loadRecords(item)}
                >
                  刷新记录
                </Button>
                {access.canAdmin && (
                  <Button
                    type="primary"
                    icon={<PlusOutlined />}
                    onClick={() => {
                      setZone(item);
                      setEditing(undefined);
                      setRecordOpen(true);
                    }}
                  >
                    新增解析记录
                  </Button>
                )}
              </Space>
              <Table<DnsRecord>
                rowKey="id"
                size="small"
                loading={recordsLoading[item.id]}
                dataSource={recordsByZone[item.id] ?? []}
                pagination={{ pageSize: 10, size: 'small' }}
                scroll={{ x: 900 }}
                columns={[
                  {
                    title: t('ssl.column.hostRecord', '主机记录'),
                    dataIndex: 'name',
                  },
                  {
                    title: t('ssl.column.recordType', '类型'),
                    dataIndex: 'type',
                  },
                  {
                    title: t('ssl.column.recordValue', '记录值'),
                    dataIndex: 'value',
                    ellipsis: true,
                  },
                  { title: t('ssl.column.ttl', 'TTL'), dataIndex: 'ttl' },
                  { title: t('ssl.column.line', '线路'), dataIndex: 'line' },
                  {
                    title: '状态',
                    render: (_, record) =>
                      record.status !== 'Enabled' &&
                      record.status !== 'Disabled' ? (
                        <StatusTag value="Unknown" />
                      ) : (
                        <Switch
                          checked={record.status === 'Enabled'}
                          checkedChildren="启用"
                          unCheckedChildren="停用"
                          disabled={
                            !access.canAdmin || item.provider === 'Cloudflare'
                          }
                          title={
                            item.provider === 'Cloudflare'
                              ? 'Cloudflare 不提供单条 DNS 记录停用；代理状态不等于 DNS 启用状态。'
                              : undefined
                          }
                          loading={mutatingId === record.id}
                          onChange={async (enabled) => {
                            setMutatingId(record.id);
                            const result = await domainApi.recordStatus(
                              item.id,
                              record.id,
                              enabled,
                            );
                            setMutatingId('');
                            if (showResult(result, '状态已更新'))
                              loadRecords(item);
                          }}
                        />
                      ),
                  },
                  {
                    title: '操作',
                    render: (_, record) =>
                      access.canAdmin ? (
                        <Space>
                          <Button
                            type="link"
                            onClick={() => {
                              setZone(item);
                              setEditing(record);
                              setRecordOpen(true);
                            }}
                          >
                            编辑
                          </Button>
                          <Button
                            type="link"
                            danger
                            onClick={() =>
                              modal.confirm({
                                title: '确认删除 DNS 记录',
                                content: `将删除 ${record.name} 的 ${record.type} 记录，可能影响域名解析，是否继续？`,
                                okText: '确认删除',
                                cancelText: '取消',
                                okButtonProps: { danger: true },
                                onOk: async () => {
                                  const result = await domainApi.deleteRecord(
                                    item.id,
                                    record.id,
                                  );
                                  if (showResult(result, '记录已删除'))
                                    loadRecords(item);
                                },
                              })
                            }
                          >
                            删除
                          </Button>
                        </Space>
                      ) : (
                        '—'
                      ),
                  },
                ]}
              />
            </div>
          ),
          onExpand: (expanded, item) => {
            if (expanded) {
              setZone(item);
              if (recordsByZone[item.id] === undefined) loadRecords(item);
            }
          },
          onExpandedRowsChange: (keys) =>
            setExpandedRowKeys(keys.map((key) => String(key))),
        }}
        scroll={{ x: 900 }}
        request={async ({ current, pageSize, ...params }) => {
          const result = await domainApi.list({
            ...params,
            page: current,
            pageSize,
          });
          setError(result.success ? '' : result.message);
          trackPage(current, pageSize, result.data?.total);
          return tableResult(result);
        }}
        toolBarRender={() =>
          access.canAdmin
            ? [
                <Select
                  key="account"
                  aria-label="选择 DNS 账号"
                  placeholder="选择 DNS 账号"
                  style={{ width: 260 }}
                  value={accountId}
                  onChange={setAccountId}
                  options={accounts
                    .filter((item) => item.enabled && item.useForDns)
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
                    const result = await domainApi.sync(accountId);
                    setSyncing(false);
                    if (showResult(result, '域名同步完成'))
                      actionRef.current?.reload();
                  }}
                >
                  同步域名
                </Button>,
              ]
            : []
        }
      />
      <ModalForm
        key={editing?.id || 'new-record'}
        title={editing ? '编辑 DNS 解析记录' : '新增 DNS 解析记录'}
        open={recordOpen}
        onOpenChange={setRecordOpen}
        modalProps={{ destroyOnHidden: true }}
        initialValues={editing || { name: '@', type: 'TXT', ttl: 600 }}
        onFinish={async (values) => {
          if (!zone) return false;
          const result = await domainApi.saveRecord(
            zone.id,
            editing?.id,
            values,
          );
          if (!showResult(result, '解析记录已保存')) return false;
          loadRecords(zone);
          return true;
        }}
      >
        <ProFormText
          name="name"
          label="主机记录"
          extra="根域名填写 @；子域名填写相对主机记录，例如 _dnsauth"
          rules={[{ required: true }]}
        />
        <ProFormSelect
          name="type"
          label="记录类型"
          valueEnum={{
            A: 'A',
            AAAA: 'AAAA',
            CNAME: 'CNAME',
            TXT: 'TXT',
            MX: 'MX',
            NS: 'NS',
            SRV: 'SRV',
            CAA: 'CAA',
          }}
          rules={[{ required: true }]}
        />
        <ProFormText name="value" label="记录值" rules={[{ required: true }]} />
        <ProFormDigit
          name="ttl"
          label="TTL（秒）"
          min={1}
          rules={[{ required: true }]}
        />
        <ProFormText
          name="line"
          label="解析线路"
          placeholder="留空使用平台默认线路"
        />
        <ProFormDigit
          name="mx"
          label="MX 优先级"
          min={0}
          extra="MX 记录时填写"
        />
      </ModalForm>
    </PageContainer>
  );
}
