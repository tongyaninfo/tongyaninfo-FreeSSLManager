import {
  type ActionType,
  type ProColumns,
  ProTable,
} from '@ant-design/pro-components';
import {
  Alert,
  Button,
  Descriptions,
  Drawer,
  Space,
  Spin,
  Typography,
} from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import {
  dateText,
  tableResult,
  useTableKeyboardPagination,
  useTablePreferences,
} from '@/components/ssl-manager';
import { mailApi } from '@/services/ssl-manager/mail';
import type { MailMessageDto } from '@/services/ssl-manager/mailTypes';
import { MailOutcome, MailStatus, mailStatusNames } from './presentation';

type Props = { revision: number; onCompose: () => void };

/** 列表只读本系统发件，服务端负责筛选分页；详情按需读取正文。 */
export default function MailMessages({ revision, onCompose }: Props) {
  const actionRef = useRef<ActionType>(null);
  const pageState = useRef({ current: 1, pageSize: 20, total: 0 });
  const tablePreferences = useTablePreferences('mail-messages');
  const trackPage = useTableKeyboardPagination(actionRef, pageState);
  const [error, setError] = useState('');
  const [selectedId, setSelectedId] = useState('');
  useEffect(() => {
    actionRef.current?.reload();
  }, [revision]);

  const columns: ProColumns<MailMessageDto>[] = [
    {
      title: '主题 / 收件人',
      dataIndex: 'search',
      hideInTable: true,
      fieldProps: { placeholder: '搜索主题或收件人' },
    },
    {
      title: '主题',
      dataIndex: 'subject',
      search: false,
      width: 260,
      ellipsis: true,
      render: (_, item) => (
        <Button
          type="link"
          style={{ maxWidth: '100%', padding: 0 }}
          onClick={() => setSelectedId(item.id)}
        >
          <Typography.Text ellipsis style={{ maxWidth: 250 }}>
            {item.subject}
          </Typography.Text>
        </Button>
      ),
    },
    {
      title: '收件人',
      dataIndex: 'to',
      search: false,
      width: 260,
      ellipsis: true,
      render: (_, item) => item.to.join('；'),
    },
    {
      title: '发送邮箱',
      dataIndex: 'fromAddress',
      search: false,
      width: 220,
      ellipsis: true,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 180,
      valueType: 'select',
      valueEnum: mailStatusNames,
      render: (_, item) => <MailStatus status={item.status} />,
    },
    {
      title: '发送人',
      dataIndex: 'createdByName',
      search: false,
      width: 130,
      ellipsis: true,
    },
    {
      title: '创建时间',
      dataIndex: 'createdAtUtc',
      search: false,
      width: 190,
      render: (_, item) => dateText(item.createdAtUtc),
    },
    {
      title: '结果说明',
      dataIndex: 'message',
      search: false,
      width: 300,
      ellipsis: true,
    },
    {
      title: '操作',
      valueType: 'option',
      fixed: 'right',
      width: 90,
      render: (_, item) => (
        <Button type="link" onClick={() => setSelectedId(item.id)}>
          查看
        </Button>
      ),
    },
  ];
  return (
    <>
      {error && (
        <Alert
          type="error"
          showIcon
          title={error}
          style={{ marginBottom: 16 }}
        />
      )}
      <ProTable<MailMessageDto>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        {...tablePreferences}
        scroll={{ x: 1630 }}
        headerTitle="本系统发件记录"
        toolBarRender={() => [
          <Button type="primary" key="send" onClick={onCompose}>
            发送邮件
          </Button>,
        ]}
        request={async ({ current, pageSize, search, status }) => {
          const result = await mailApi.messages({
            page: current,
            pageSize,
            search,
            status,
          });
          setError(result.success ? '' : result.message);
          trackPage(current, pageSize, result.data?.total);
          return tableResult(result);
        }}
        pagination={{ defaultPageSize: 20 }}
      />
      {selectedId && (
        <MailDetail id={selectedId} onClose={() => setSelectedId('')} />
      )}
    </>
  );
}

function MailDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const [data, setData] = useState<MailMessageDto>();
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let current = true;
    setLoading(true);
    setData(undefined);
    setError('');
    void mailApi
      .message(id)
      .then((result) => {
        if (!current) return;
        if (result.success && result.data) setData(result.data);
        else setError(result.message || '读取邮件详情失败');
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [id, revision]);
  return (
    <Drawer
      open
      title="发件详情"
      onClose={onClose}
      size="min(780px, 100vw)"
      destroyOnHidden
      extra={
        <Button
          onClick={() => setRevision((value) => value + 1)}
          loading={loading}
        >
          刷新结果
        </Button>
      }
    >
      {error && (
        <Alert
          type="error"
          showIcon
          title={error}
          style={{ marginBottom: 16 }}
        />
      )}
      {loading && <Spin />}
      {data && (
        <Space orientation="vertical" size={16} style={{ width: '100%' }}>
          <MailOutcome status={data.status} />
          <Descriptions
            column={1}
            size="small"
            items={[
              { key: 'subject', label: '主题', children: data.subject },
              { key: 'from', label: '发送邮箱', children: data.fromAddress },
              { key: 'to', label: '收件人', children: data.to.join('；') },
              {
                key: 'status',
                label: '状态',
                children: <MailStatus status={data.status} />,
              },
              {
                key: 'operator',
                label: '发送人',
                children: data.createdByName,
              },
              {
                key: 'created',
                label: '创建时间',
                children: dateText(data.createdAtUtc),
              },
              {
                key: 'completed',
                label: '完成时间',
                children: dateText(data.completedAtUtc || undefined),
              },
              {
                key: 'result',
                label: '结果说明',
                children: data.message || '—',
              },
            ]}
          />
          <div style={{ width: '100%' }}>
            <Typography.Title level={5}>邮件正文</Typography.Title>
            <Typography.Paragraph
              style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}
            >
              {data.body || '（无正文）'}
            </Typography.Paragraph>
          </div>
        </Space>
      )}
    </Drawer>
  );
}
