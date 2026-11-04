import { Alert, Descriptions, Tag, Typography } from 'antd';
import React from 'react';
import type { McpCallContext } from '@/services/ssl-manager/mcpTypes';

/** 旧日志不补造上下文；只展示服务端白名单脱敏后的有界快照。 */
export function parseMcpContext(value?: string): McpCallContext | undefined {
  if (!value) return undefined;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
      return undefined;
    const record = parsed as Record<string, unknown>;
    return {
      transportScheme:
        record.transportScheme === 'http' || record.transportScheme === 'https'
          ? record.transportScheme
          : undefined,
      userAgent:
        typeof record.userAgent === 'string' ? record.userAgent : undefined,
      systemName:
        typeof record.systemName === 'string' ? record.systemName : undefined,
      instanceId:
        typeof record.instanceId === 'string' ? record.instanceId : undefined,
      clientName:
        typeof record.clientName === 'string' ? record.clientName : undefined,
      clientVersion:
        typeof record.clientVersion === 'string'
          ? record.clientVersion
          : undefined,
      input: record.input,
      output: record.output,
      inputCaptured: record.inputCaptured === true,
      outputCaptured: record.outputCaptured === true,
      inputTruncated: record.inputTruncated === true,
      outputTruncated: record.outputTruncated === true,
      truncated: record.truncated === true,
    };
  } catch {
    return undefined;
  }
}

function Payload({
  label,
  value,
  captured,
  truncated,
}: {
  label: string;
  value: unknown;
  captured?: boolean;
  truncated?: boolean;
}) {
  return (
    <section aria-label={`MCP ${label}快照`} style={{ marginTop: 20 }}>
      <Typography.Title level={5}>
        {label}{' '}
        <Tag>{captured ? (truncated ? '已截断' : '已采集') : '未采集'}</Tag>
      </Typography.Title>
      {captured ? (
        <Typography.Paragraph
          copyable={{ text: JSON.stringify(value ?? null, null, 2) }}
        >
          <pre
            style={{ whiteSpace: 'pre-wrap', maxHeight: 360, overflow: 'auto' }}
          >
            {JSON.stringify(value ?? null, null, 2)}
          </pre>
        </Typography.Paragraph>
      ) : (
        <Typography.Text type="secondary">
          本次调用未采集{label}，历史日志不会补录。
        </Typography.Text>
      )}
    </section>
  );
}

export default function AuditContext({
  contextJson,
}: {
  contextJson?: string;
}) {
  const context = parseMcpContext(contextJson);
  if (!context)
    return (
      <Alert type="info" title="未采集调用上下文" style={{ marginTop: 20 }} />
    );
  return (
    <section aria-label="MCP 调用上下文" style={{ marginTop: 20 }}>
      <Descriptions
        column={1}
        size="small"
        items={[
          {
            key: 'transport',
            label: '传输协议',
            children: context.transportScheme?.toUpperCase() || '未采集',
          },
          {
            key: 'ua',
            label: 'User-Agent（自报）',
            children: context.userAgent || '未采集',
          },
          {
            key: 'system',
            label: '调用时系统名称',
            children: context.systemName || '未采集',
          },
          {
            key: 'instance',
            label: '调用时系统实例 ID',
            children: context.instanceId || '未采集',
          },
          {
            key: 'client',
            label: '客户端（自报）',
            children: `${context.clientName || '未采集'} / ${context.clientVersion || '版本未采集'}`,
          },
        ]}
      />
      <Alert
        type="info"
        showIcon
        title="入参和出参仅为受控字段快照"
        description="服务端按字段白名单脱敏并限制长度，不保存 API Key、OAuth 令牌、云账号凭据、证书私钥或完整聊天。客户端名称、版本和 User-Agent 均为自报信息，不能代替 API Key 核验身份。"
      />
      {context.truncated && (
        <Tag color="warning" style={{ marginTop: 8 }}>
          调用上下文超限，已截断
        </Tag>
      )}
      <Payload
        label="入参"
        value={context.input}
        captured={context.inputCaptured}
        truncated={context.inputTruncated}
      />
      <Payload
        label="出参"
        value={context.output}
        captured={context.outputCaptured}
        truncated={context.outputTruncated}
      />
    </section>
  );
}
