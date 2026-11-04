import {
  Alert,
  Button,
  Card,
  Collapse,
  Form,
  Input,
  InputNumber,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Typography,
} from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import { useResultMessage } from '@/components/ssl-manager';
import { mailApi } from '@/services/ssl-manager/mail';
import type {
  MailSettingsDto,
  MailSettingsInput,
} from '@/services/ssl-manager/mailTypes';

type Props = { onTest: () => void; onSaved: () => void };

/** 仅维护一套 SMTP 配置，授权码保留在服务端，不回填到表单。 */
export default function MailSettings({ onTest, onSaved }: Props) {
  const [form] = Form.useForm<MailSettingsInput>();
  const showResult = useResultMessage();
  const [settings, setSettings] = useState<MailSettingsDto>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<'save' | 'probe'>();
  const [dirty, setDirty] = useState(false);
  const [probe, setProbe] = useState<{ success: boolean; message: string }>();
  const [revision, setRevision] = useState(0);
  const active = useRef(true);
  const pending = useRef(false);
  useEffect(() => {
    active.current = true;
    let current = true;
    setLoading(true);
    setError('');
    void mailApi
      .settings()
      .then((result) => {
        if (!current) return;
        if (!result.success || !result.data) {
          setError(result.message || '读取邮箱设置失败');
          return;
        }
        setSettings(result.data);
        form.setFieldsValue({
          ...result.data,
          port: result.data.port || 465,
          security: result.data.security || 'SslOnConnect',
          username:
            result.data.username === result.data.fromAddress
              ? ''
              : result.data.username,
          password: '',
        });
        setDirty(false);
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
      active.current = false;
      // 页面卸载后丢弃输入，密码从不保存到浏览器存储。
      form.setFieldValue('password', '');
    };
  }, [form, revision]);

  const save = async (values: MailSettingsInput) => {
    if (pending.current) return;
    pending.current = true;
    setBusy('save');
    setError('');
    setProbe(undefined);
    try {
      const fromAddress = values.fromAddress.trim();
      const result = await mailApi.saveSettings({
        ...values,
        host: values.host.trim(),
        fromAddress,
        fromName: values.fromName?.trim() || '',
        username: values.username?.trim() || fromAddress,
        password: values.password || '',
      });
      if (!active.current) return;
      if (showResult(result, '邮箱设置已保存') && result.data) {
        setSettings(result.data);
        form.setFieldValue('password', '');
        setDirty(false);
        onSaved();
      } else setError(result.message);
    } finally {
      pending.current = false;
      if (active.current) setBusy(undefined);
    }
  };

  const testConnection = async () => {
    if (pending.current) return;
    pending.current = true;
    setBusy('probe');
    setProbe(undefined);
    try {
      const result = await mailApi.probe();
      if (active.current)
        setProbe({
          success: result.success,
          message:
            result.message ||
            (result.success ? '连接与认证成功' : '连接检测失败'),
        });
    } finally {
      pending.current = false;
      if (active.current) setBusy(undefined);
    }
  };

  return (
    <Card style={{ maxWidth: 820 }}>
      <Typography.Paragraph type="secondary">
        1. 在邮箱服务商开启 SMTP 并获取授权码。2. 保存以下设置并检测连接。3.
        发送测试邮件后到收件箱核对。
      </Typography.Paragraph>
      {error && (
        <Alert
          type="error"
          showIcon
          title={error}
          action={
            !settings && (
              <Button
                size="small"
                onClick={() => setRevision((value) => value + 1)}
              >
                重新加载
              </Button>
            )
          }
          style={{ marginBottom: 16 }}
        />
      )}
      <Spin spinning={loading}>
        <Form<MailSettingsInput>
          form={form}
          layout="vertical"
          disabled={loading || Boolean(busy) || !settings}
          initialValues={{ port: 465, security: 'SslOnConnect', enabled: true }}
          onValuesChange={() => {
            setDirty(true);
            setProbe(undefined);
          }}
          onFinish={save}
          autoComplete="off"
        >
          <Form.Item
            name="host"
            label="SMTP 服务器"
            rules={[
              {
                required: true,
                whitespace: true,
                message: '请输入 SMTP 服务器',
              },
            ]}
          >
            <Input placeholder="例如 smtp.example.com" maxLength={253} />
          </Form.Item>
          <Form.Item
            name="fromAddress"
            label="发送邮箱"
            rules={[
              { required: true, type: 'email', message: '请输入有效邮箱地址' },
            ]}
          >
            <Input placeholder="例如 notice@example.com" maxLength={254} />
          </Form.Item>
          <Form.Item
            name="password"
            label="授权码 / 密码"
            extra={
              settings?.hasPassword
                ? '已保存授权码；留空保留原值。'
                : '优先填写邮箱服务商提供的 SMTP 授权码。'
            }
            rules={[
              {
                required: !settings?.hasPassword,
                message: '请输入 SMTP 授权码或密码',
              },
            ]}
          >
            <Input.Password
              autoComplete="new-password"
              maxLength={4096}
              placeholder={
                settings?.hasPassword ? '已配置，留空保留' : '请输入授权码'
              }
            />
          </Form.Item>
          <Collapse
            ghost
            style={{ marginBottom: 16 }}
            items={[
              {
                key: 'advanced',
                label: '高级设置',
                forceRender: true,
                children: (
                  <>
                    <Space wrap align="start" style={{ width: '100%' }}>
                      <Form.Item
                        name="port"
                        label="端口"
                        rules={[{ required: true, message: '请输入端口' }]}
                      >
                        <InputNumber min={1} max={65535} precision={0} />
                      </Form.Item>
                      <Form.Item
                        name="security"
                        label="连接安全"
                        rules={[{ required: true }]}
                      >
                        <Select
                          style={{ width: 240 }}
                          options={[
                            {
                              value: 'SslOnConnect',
                              label: 'SSL/TLS（通常为 465）',
                            },
                            {
                              value: 'StartTls',
                              label: 'STARTTLS（通常为 587）',
                            },
                          ]}
                        />
                      </Form.Item>
                    </Space>
                    <Form.Item
                      name="username"
                      label="登录账号"
                      extra="留空使用发送邮箱，仅在服务商要求不同账号时填写。"
                    >
                      <Input autoComplete="off" maxLength={254} />
                    </Form.Item>
                    <Form.Item name="fromName" label="发件人名称（可选）">
                      <Input
                        maxLength={100}
                        placeholder="例如 SSL 证书管理平台"
                      />
                    </Form.Item>
                    <Form.Item
                      name="enabled"
                      label="启用邮件发送"
                      valuePropName="checked"
                    >
                      <Switch />
                    </Form.Item>
                  </>
                ),
              },
            ]}
          />
          <Space wrap>
            <Button type="primary" htmlType="submit" loading={busy === 'save'}>
              保存设置
            </Button>
            <Button
              onClick={testConnection}
              loading={busy === 'probe'}
              disabled={!settings?.configured || dirty || Boolean(busy)}
            >
              检测连接
            </Button>
            <Button
              onClick={onTest}
              disabled={
                !settings?.configured ||
                !settings.enabled ||
                dirty ||
                Boolean(busy)
              }
            >
              发送测试邮件
            </Button>
            {settings?.configured && (
              <Tag color={settings.enabled ? 'success' : 'default'}>
                {settings.enabled ? '发送已启用' : '发送已停用'}
              </Tag>
            )}
          </Space>
        </Form>
      </Spin>
      <Typography.Paragraph
        type="secondary"
        style={{ marginTop: 16, marginBottom: probe ? 16 : 0 }}
      >
        {dirty
          ? '设置已修改，请先保存再检测或发送。'
          : '检测连接只验证服务器连接与认证，不会发送邮件。'}
      </Typography.Paragraph>
      {probe && (
        <Alert
          showIcon
          type={probe.success ? 'success' : 'error'}
          title={probe.message}
        />
      )}
    </Card>
  );
}
