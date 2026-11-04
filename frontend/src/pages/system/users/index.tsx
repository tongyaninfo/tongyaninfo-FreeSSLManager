import { PlusOutlined } from '@ant-design/icons';
import {
  type ActionType,
  ModalForm,
  PageContainer,
  type ProColumns,
  ProFormSelect,
  ProFormSwitch,
  ProFormText,
  ProTable,
} from '@ant-design/pro-components';
import { Alert, Button, Tag } from 'antd';
import { useIntl } from '@umijs/max';
import React, { useRef, useState } from 'react';
import {
  tableResult,
  useResultMessage,
  useTableKeyboardPagination,
  useTablePreferences,
} from '@/components/ssl-manager';
import { userApi } from '@/services/ssl-manager/api';
import type { ManagedUser } from '@/services/ssl-manager/types';

export default function Users() {
  const intl = useIntl();
  const t = (id: string, fallback: string) =>
    intl.formatMessage({ id, defaultMessage: fallback });
  const actionRef = useRef<ActionType>(null);
  const pageState = useRef({ current: 1, pageSize: 20, total: 0 });
  const tablePreferences = useTablePreferences('users');
  const trackPage = useTableKeyboardPagination(actionRef, pageState);
  const showResult = useResultMessage();
  const [editing, setEditing] = useState<ManagedUser>();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState('');
  const columns: ProColumns<ManagedUser>[] = [
    { title: t('ssl.column.username', '用户名'), dataIndex: 'username' },
    {
      title: t('ssl.column.displayName', '显示名称'),
      dataIndex: 'displayName',
      search: false,
      render: (_, item) => item.displayName,
    },
    {
      title: t('ssl.column.role', '角色'),
      dataIndex: 'role',
      valueEnum: { admin: '管理员', viewer: '只读用户' },
      render: (_, item) => (
        <Tag color={item.role === 'admin' ? 'blue' : undefined}>
          {item.role === 'admin' ? '管理员' : '只读用户'}
        </Tag>
      ),
    },
    {
      title: t('ssl.field.status', '状态'),
      dataIndex: 'enabled',
      search: false,
      render: (_, item) => (item.enabled ? '启用' : '停用'),
    },
    {
      title: t('ssl.column.actions', '操作'),
      valueType: 'option',
      render: (_, item) => (
        <Button
          type="link"
          onClick={() => {
            setEditing(item);
            setOpen(true);
          }}
        >
          编辑
        </Button>
      ),
    },
  ];
  return (
    <PageContainer
      title={intl.formatMessage({
        id: 'ssl.page.users.title',
        defaultMessage: '用户管理',
      })}
      subTitle={intl.formatMessage({
        id: 'ssl.page.users.subtitle',
        defaultMessage: '管理员管理平台配置与云资源；只读用户查看域名和证书',
      })}
    >
      <Alert
        title="修改密码时填写新密码，留空保留原密码。平台会阻止禁用或降级最后一位管理员。"
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />
      {error && (
        <Alert type="error" title={error} style={{ marginBottom: 16 }} />
      )}
      <ProTable<ManagedUser>
        rowKey="id"
        actionRef={actionRef}
        columns={columns}
        {...tablePreferences}
        request={async ({ current, pageSize, ...params }) => {
          const result = await userApi.list({
            ...params,
            search: params.username,
            page: current,
            pageSize,
          });
          setError(result.success ? '' : result.message);
          trackPage(current, pageSize, result.data?.total);
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
            新增用户
          </Button>,
        ]}
      />
      <ModalForm
        key={editing?.id || 'new'}
        title={editing ? '编辑用户' : '新增用户'}
        open={open}
        onOpenChange={setOpen}
        modalProps={{ destroyOnHidden: true }}
        initialValues={
          editing
            ? { ...editing, displayName: editing.displayName }
            : { role: 'viewer', enabled: true }
        }
        onFinish={async (values) => {
          const result = await userApi.save(editing?.id, values);
          if (!showResult(result, '用户已保存')) return false;
          actionRef.current?.reload();
          return true;
        }}
      >
        <ProFormText
          name="username"
          label="用户名"
          disabled={Boolean(editing)}
          rules={[{ required: true }, { min: 3, message: '至少 3 个字符' }]}
        />
        <ProFormText name="displayName" label="显示名称" />
        <ProFormText.Password
          name="password"
          label={editing ? '新密码（留空保留）' : '密码'}
          fieldProps={{ autoComplete: 'new-password' }}
          rules={[
            { required: !editing, message: '请输入密码' },
            { min: 12, message: '密码至少 12 个字符' },
          ]}
        />
        <ProFormSelect
          name="role"
          label="用户角色"
          valueEnum={{ admin: '管理员', viewer: '只读用户' }}
          rules={[{ required: true }]}
        />
        <ProFormSwitch name="enabled" label="启用用户" />
      </ModalForm>
    </PageContainer>
  );
}
