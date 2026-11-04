import {
  type ActionType,
  PageContainer,
  type ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import { Alert, Tag } from 'antd';
import { useIntl } from '@umijs/max';
import React, { useRef, useState } from 'react';
import {
  dateText,
  tableResult,
  useTableKeyboardPagination,
  useTablePreferences,
} from '@/components/ssl-manager';
import { auditApi } from '@/services/ssl-manager/api';
import type { AuditLog } from '@/services/ssl-manager/types';

export default function Audit() {
  const intl = useIntl();
  const t = (id: string, fallback: string) =>
    intl.formatMessage({ id, defaultMessage: fallback });
  const actionRef = useRef<ActionType>(null);
  const pageState = useRef({ current: 1, pageSize: 20, total: 0 });
  const tablePreferences = useTablePreferences('audit');
  const trackPage = useTableKeyboardPagination(actionRef, pageState);
  const [error, setError] = useState('');
  const columns: ProColumns<AuditLog>[] = [
    {
      title: t('ssl.column.time', '时间'),
      dataIndex: 'createdAtUtc',
      search: false,
      width: 180,
      ellipsis: true,
      render: (_, item) => dateText(item.createdAtUtc),
    },
    {
      title: t('ssl.column.operator', '操作人'),
      dataIndex: 'username',
      width: 120,
      ellipsis: true,
    },
    {
      title: t('ssl.column.actions', '操作'),
      dataIndex: 'action',
      width: 140,
      ellipsis: true,
    },
    { title: '资源 ID', dataIndex: 'resourceId', width: 180, ellipsis: true },
    {
      title: t('ssl.column.result', '结果'),
      dataIndex: 'success',
      valueEnum: { true: '成功', false: '失败' },
      width: 90,
      render: (_, item) => (
        <Tag color={item.success ? 'success' : 'error'}>
          {item.success ? '成功' : '失败'}
        </Tag>
      ),
    },
    {
      title: t('ssl.column.resultCode', '结果代码'),
      dataIndex: 'code',
      search: false,
      width: 170,
      ellipsis: true,
    },
    {
      title: t('ssl.column.description', '说明'),
      dataIndex: 'message',
      search: false,
      width: 420,
      ellipsis: true,
    },
  ];
  return (
    <PageContainer
      title={intl.formatMessage({
        id: 'ssl.page.audit.title',
        defaultMessage: '审计日志',
      })}
      subTitle={intl.formatMessage({
        id: 'ssl.page.audit.subtitle',
        defaultMessage:
          '记录配置、DNS、证书及用户管理操作，日志不包含云密钥或私钥内容',
      })}
    >
      {error && (
        <Alert type="error" title={error} style={{ marginBottom: 16 }} />
      )}
      <ProTable<AuditLog>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        {...tablePreferences}
        // 给说明列保留稳定宽度，避免长消息换成每行仅显示几个字而撑高整行。
        scroll={{ x: 1300 }}
        request={async ({ current, pageSize, ...params }) => {
          const result = await auditApi.list({
            ...params,
            page: current,
            pageSize,
          });
          setError(result.success ? '' : result.message);
          trackPage(current, pageSize, result.data?.total);
          return tableResult(result);
        }}
      />
    </PageContainer>
  );
}
