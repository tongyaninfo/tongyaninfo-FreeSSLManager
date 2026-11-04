import { useAccess, useIntl } from '@umijs/max';
import { Alert, App, Tag } from 'antd';
import React, { useEffect, useState } from 'react';
import { accountApi } from '@/services/ssl-manager/api';
import type {
  ApiResult,
  CloudAccount,
  PageResult,
} from '@/services/ssl-manager/types';

export const providerNames = {
  TencentCloud: '腾讯云',
  Aliyun: '阿里云',
  Cloudflare: 'Cloudflare',
  Acme: "Let's Encrypt / ACME",
};
export const statusNames: Record<string, string> = {
  PendingValidation: '待验证',
  Processing: '审核中',
  Issued: '已签发',
  Expired: '已过期',
  Revoking: '吊销中',
  Revoked: '已吊销',
  Deleting: '删除中',
  Failed: '失败',
  Cancelled: '已取消',
  SubmissionUnknown: '提交结果待核对',
  Unknown: '待核对',
  Pending: '等待处理',
  Running: '处理中',
  Succeeded: '已完成',
  Completed: '已完成',
  RetryPending: '等待重试',
  NotRequired: '无需清理',
  Enabled: '启用',
  Disabled: '停用',
};
export function StatusTag({ value }: { value?: string }) {
  const intl = useIntl();
  const statusId: Record<string, string> = {
    PendingValidation: 'ssl.status.verifying',
    Processing: 'ssl.status.processing',
    Issued: 'ssl.status.issued',
    Expired: 'ssl.status.expired',
    Revoked: 'ssl.status.revoked',
    Cancelled: 'ssl.status.cancelled',
    Failed: 'ssl.status.failed',
    Deleting: 'ssl.status.processing',
    Revoking: 'ssl.status.processing',
    Enabled: 'ssl.status.enabled',
    Disabled: 'ssl.status.disabled',
    Pending: 'ssl.status.pending',
    Unknown: 'ssl.status.pending',
    SubmissionUnknown: 'ssl.status.pending',
    Running: 'ssl.status.processing',
    Succeeded: 'ssl.status.active',
    Completed: 'ssl.status.active',
  };
  const color = ['Issued', 'Succeeded', 'Completed', 'Enabled'].includes(
    value ?? '',
  )
    ? 'success'
    : ['Failed', 'Expired', 'Revoked', 'Cancelled', 'Disabled'].includes(
          value ?? '',
        )
      ? 'error'
      : 'processing';
  const fallback = statusNames[value ?? ''] || value || '—';
  return (
    <Tag color={color}>
      {statusId[value ?? '']
        ? intl.formatMessage({
            id: statusId[value ?? ''],
            defaultMessage: fallback,
          })
        : fallback}
    </Tag>
  );
}
export function ReadonlyNotice() {
  const access = useAccess();
  const intl = useIntl();
  return access.canAdmin ? null : (
    <Alert
      type="info"
      showIcon
      title={intl.formatMessage({
        id: 'ssl.message.readonlyNotice',
        defaultMessage:
          '当前账号为只读用户，可查看域名与证书，写操作和证书下载需要管理员权限。',
      })}
      style={{ marginBottom: 16 }}
    />
  );
}
export function useCloudAccounts() {
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    accountApi.options().then((result) => {
      if (!active) return;
      if (result.success) setAccounts(result.data ?? []);
      else setError(result.message);
    });
    return () => {
      active = false;
    };
  }, []);
  return {
    accounts,
    error,
    options: accounts.map((account) => ({
      label: `${providerNames[account.provider]} / ${account.name}`,
      value: account.id,
    })),
  };
}
export function useResultMessage() {
  const { message } = App.useApp();
  return <T,>(result: ApiResult<T>, success?: string) => {
    if (result.success) {
      if (success) message.success(success);
      return true;
    }
    message.error(result.message || '操作失败');
    return false;
  };
}
export function tableResult<T>(result: ApiResult<PageResult<T>>) {
  return {
    success: result.success,
    data: result.data?.items ?? [],
    total: result.data?.total ?? 0,
  };
}
export function dateText(value?: string) {
  return value
    ? new Date(value).toLocaleString('zh-CN', { hour12: false })
    : '—';
}

export {
  useTableKeyboardPagination,
  useTablePreferences,
} from './tablePreferences';
