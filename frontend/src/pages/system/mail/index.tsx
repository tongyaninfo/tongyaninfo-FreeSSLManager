import { PageContainer } from '@ant-design/pro-components';
import { useAccess } from '@umijs/max';
import { Result, Tabs } from 'antd';
import React, { useEffect, useState } from 'react';
import ComposeMail from './Compose';
import ExpiryReminders from './ExpiryReminders';
import MailMessages from './Messages';
import MailSettings from './Settings';

/** 邮件入口仅面向管理员；服务器仍逐接口校验权限。 */
export default function MailManagement() {
  const access = useAccess();
  const [expired, setExpired] = useState(false);
  const [tab, setTab] = useState('messages');
  const [compose, setCompose] = useState<'mail' | 'test'>();
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const expire = () => {
      setExpired(true);
      setCompose(undefined);
    };
    window.addEventListener('ssl-auth-expired', expire);
    return () => window.removeEventListener('ssl-auth-expired', expire);
  }, []);
  if (expired) return null;
  if (!access.canAdmin) return <Result status="403" title="无邮件管理权限" />;
  return (
    <PageContainer
      title="邮件管理"
      subTitle="配置系统发送邮箱，查看本系统提交的邮件记录"
    >
      <Tabs
        activeKey={tab}
        onChange={setTab}
        destroyOnHidden
        items={[
          {
            key: 'messages',
            label: '发件记录',
            children: (
              <MailMessages
                revision={revision}
                onCompose={() => setCompose('mail')}
              />
            ),
          },
          {
            key: 'expiry-reminders',
            label: '到期提醒',
            children: <ExpiryReminders />,
          },
          {
            key: 'settings',
            label: '邮箱设置',
            children: (
              <MailSettings
                onTest={() => setCompose('test')}
                onSaved={() => setRevision((value) => value + 1)}
              />
            ),
          },
        ]}
      />
      {compose && (
        <ComposeMail
          test={compose === 'test'}
          onRecorded={() => setRevision((value) => value + 1)}
          onClose={() => {
            setCompose(undefined);
            setTab('messages');
          }}
        />
      )}
    </PageContainer>
  );
}
