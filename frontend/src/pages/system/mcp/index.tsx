import { PageContainer } from '@ant-design/pro-components';
import { useAccess } from '@umijs/max';
import { Result, Tabs } from 'antd';
import React, { useEffect, useState } from 'react';
import AllowRules from './AllowRules';
import CallLogs from './CallLogs';
import Clients from './Clients';
import McpSettings from './Settings';

/** 会话失效立即卸载所有管理内容，丢弃一次展示的客户端秘密和未保存输入。 */
export default function McpManagement() {
  const access = useAccess();
  const [expired, setExpired] = useState(false);
  const [tab, setTab] = useState('settings');
  const [clientId, setClientId] = useState('');
  useEffect(() => {
    const expire = () => setExpired(true);
    window.addEventListener('ssl-auth-expired', expire);
    return () => window.removeEventListener('ssl-auth-expired', expire);
  }, []);
  if (expired) return null;
  if (!access.canAdmin) return <Result status="403" title="无 MCP 管理权限" />;
  return (
    <PageContainer
      title="MCP 配置"
      subTitle="控制外部 AI 客户端的接入、业务范围及每次调用记录"
    >
      <Tabs
        activeKey={tab}
        onChange={setTab}
        destroyOnHidden
        items={[
          { key: 'settings', label: '服务设置', children: <McpSettings /> },
          {
            key: 'clients',
            label: '接入客户端',
            children: (
              <Clients
                onConfigureRules={(id) => {
                  setClientId(id);
                  setTab('rules');
                }}
              />
            ),
          },
          {
            key: 'rules',
            label: '调用白名单',
            children: <AllowRules initialClientId={clientId} />,
          },
          { key: 'logs', label: '调用日志', children: <CallLogs /> },
        ]}
      />
    </PageContainer>
  );
}
