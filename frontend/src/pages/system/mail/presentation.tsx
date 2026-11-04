import { Alert, Tag } from 'antd';
import React from 'react';

export const mailStatusNames: Record<string, string> = {
  Sending: '发送中',
  Accepted: '已提交邮件服务器',
  Failed: '发送失败',
  Unknown: '结果待核验',
};

export function MailStatus({ status }: { status: string }) {
  const color =
    status === 'Accepted'
      ? 'success'
      : status === 'Failed'
        ? 'error'
        : status === 'Unknown'
          ? 'warning'
          : 'processing';
  return <Tag color={color}>{mailStatusNames[status] || status}</Tag>;
}

/** 已提交仅表示 SMTP 受理；结果未知时不能以重发替代核验。 */
export function MailOutcome({ status }: { status: string }) {
  if (status === 'Unknown')
    return (
      <Alert
        type="warning"
        showIcon
        title="发送结果待核验"
        description="尚不能确认邮件服务器是否已受理。请核对原发件记录或收件箱，避免重复发送。"
      />
    );
  if (status === 'Accepted')
    return (
      <Alert
        type="success"
        showIcon
        title="邮件已提交邮件服务器"
        description="服务器受理不代表邮件最终送达或已被阅读。"
      />
    );
  return null;
}
