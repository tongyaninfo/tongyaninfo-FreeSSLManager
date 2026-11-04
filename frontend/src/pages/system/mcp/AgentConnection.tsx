import { Alert, Button, Space } from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import {
  agentConnectionInstruction,
  copyMcpText,
  type AgentConnectionProfile,
} from './connectionInstructions';

/** 只保存复制状态，不把含 Key 的接入指令放入组件状态、浏览器存储或日志。 */
export default function AgentConnection({
  profile,
  apiKey,
}: {
  profile: AgentConnectionProfile;
  apiKey?: string;
}) {
  const [message, setMessage] = useState('');
  const [error, setError] = useState(false);
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  const oauthRequiresHttps =
    profile.authenticationType === 'OAuth' &&
    !profile.mcpUrl.startsWith('https:');
  const ready = !!profile.instanceId && !!profile.mcpUrl && !oauthRequiresHttps;
  return (
    <Space orientation="vertical" style={{ width: '100%' }}>
      {apiKey && (
        <Alert
          type="warning"
          showIcon
          title="完整指令包含本次 API Key，复制并粘贴会把密钥交给目标 Agent。"
          description="仅发送给你信任的 Agent。此按钮不会注册服务，也不会自动发送密钥；指令不保存在浏览器或日志中，关闭此窗口后无法再次生成包含该密钥的指令。"
        />
      )}
      <Button
        disabled={!ready}
        onClick={async () => {
          if (!active.current || !ready) return;
          try {
            await copyMcpText(agentConnectionInstruction(profile, apiKey));
            if (active.current) {
              setError(false);
              setMessage(
                '接入指令已复制，请粘贴给目标 Agent；是否完成注册以 Agent 的实际配置结果为准。',
              );
            }
          } catch {
            if (active.current) {
              setError(true);
              setMessage('浏览器未允许复制，请检查剪贴板权限后重试。');
            }
          }
        }}
      >
        {apiKey ? '复制完整接入指令（含本次密钥）' : '复制 Agent 接入指令'}
      </Button>
      {!ready && (
        <Alert
          type="info"
          title={
            oauthRequiresHttps
              ? '当前地址不支持 OAuth 接入，请使用 HTTPS 地址，或通过 API Key 管理复制内网 HTTP 接入指令。'
              : '请先保存服务基址以生成固定实例与 MCP 地址。'
          }
        />
      )}
      {message && (
        <Alert type={error ? 'warning' : 'success'} title={message} />
      )}
    </Space>
  );
}
