import {
  Alert,
  App,
  Button,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Typography,
} from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import { mailApi } from '@/services/ssl-manager/mail';
import type {
  MailMessageDto,
  MailSendInput,
} from '@/services/ssl-manager/mailTypes';
import { MailOutcome, MailStatus } from './presentation';
import { createMailRequestId } from './requestId';

type Props = {
  test?: boolean;
  onClose: () => void;
  onRecorded: () => void;
};
type FormValues = Omit<MailSendInput, 'requestId'>;

/** 一份草稿固定一个请求 ID；结果不明时停止提交并查询原发件记录。 */
export default function ComposeMail({
  test = false,
  onClose,
  onRecorded,
}: Props) {
  const [form] = Form.useForm<FormValues>();
  const { modal } = App.useApp();
  const [requestId] = useState(createMailRequestId);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [uncertain, setUncertain] = useState(false);
  const [record, setRecord] = useState<MailMessageDto>();
  const pending = useRef(false);
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);

  const send = async (values: FormValues) => {
    if (pending.current || record || uncertain) return;
    pending.current = true;
    setBusy(true);
    setError('');
    try {
      const result = await mailApi.send({
        requestId,
        to: values.to.map((address) => address.trim()),
        subject: values.subject.trim(),
        body: values.body,
      });
      if (!active.current) return;
      if (result.data) {
        setRecord(result.data);
        onRecorded();
      } else {
        setError(result.message || '发送失败');
        if (
          ['NETWORK_ERROR', 'INVALID_RESPONSE', 'SYSTEM_ERROR'].includes(
            result.code,
          )
        ) {
          setUncertain(true);
          onRecorded();
        }
      }
    } finally {
      pending.current = false;
      if (active.current) setBusy(false);
    }
  };

  const confirmSend = async () => {
    if (pending.current || record || uncertain) return;
    const values = await form.validateFields();
    modal.confirm({
      title: test ? '确认发送测试邮件' : '确认发送邮件',
      content: (
        <>
          <Typography.Paragraph>
            收件人：{values.to.join('；')}
          </Typography.Paragraph>
          <Typography.Paragraph>
            邮件将立即提交 SMTP
            服务器。服务器受理不代表最终送达，请在发件记录和收件箱中核对结果。
          </Typography.Paragraph>
        </>
      ),
      okText: '确认发送',
      cancelText: '取消',
      onOk: () => send(values),
    });
  };

  return (
    <Modal
      open
      title={test ? '发送测试邮件' : '发送邮件'}
      onCancel={onClose}
      mask={{ closable: !busy }}
      closable={!busy}
      keyboard={!busy}
      width={720}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={onClose} disabled={busy}>
            {record || uncertain ? '关闭并查看发件记录' : '取消'}
          </Button>
          {!record && !uncertain && (
            <Button
              type="primary"
              loading={busy}
              onClick={() => void confirmSend().catch(() => undefined)}
            >
              发送
            </Button>
          )}
        </Space>
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
      {uncertain && (
        <div style={{ marginBottom: 16 }}>
          <MailOutcome status="Unknown" />
        </div>
      )}
      {record && (
        <Space
          orientation="vertical"
          style={{ width: '100%', marginBottom: 16 }}
        >
          <MailStatus status={record.status} />
          <MailOutcome status={record.status} />
          {record.message && (
            <Typography.Text>{record.message}</Typography.Text>
          )}
          <Typography.Text type="secondary">
            发件记录：{record.id}
          </Typography.Text>
        </Space>
      )}
      <Form<FormValues>
        form={form}
        layout="vertical"
        disabled={busy || Boolean(record) || uncertain}
        initialValues={
          test
            ? {
                to: [],
                subject: 'SSL 证书管理平台测试邮件',
                body: '这是一封来自 SSL 证书管理平台的测试邮件，用于确认邮件发送配置。收到此邮件即表示本次测试邮件已投递到您的邮箱。',
              }
            : { to: [] }
        }
      >
        <Form.Item
          name="to"
          label="收件人"
          extra="输入邮箱后按回车，多个邮箱可用逗号或分号分隔，最多 50 个。"
          rules={[
            {
              required: true,
              type: 'array',
              min: 1,
              message: '请至少填写一个收件邮箱',
            },
            {
              type: 'array',
              max: 50,
              message: '每封邮件最多填写 50 个收件人',
            },
            {
              validator: (_, addresses: string[] | undefined) =>
                !addresses?.some(
                  (address) =>
                    address.trim().length > 254 ||
                    !/^[^@\s]+@[^@\s]+$/.test(address.trim()),
                )
                  ? Promise.resolve()
                  : Promise.reject(new Error('请检查收件邮箱格式')),
            },
          ]}
        >
          <Select
            mode="tags"
            tokenSeparators={[',', ';', '，', '；', ' ', '\n']}
            placeholder="例如 recipient@example.com"
            open={false}
          />
        </Form.Item>
        <Form.Item
          name="subject"
          label="主题"
          rules={[
            { required: true, whitespace: true, message: '请输入邮件主题' },
          ]}
        >
          <Input maxLength={300} readOnly={test} />
        </Form.Item>
        <Form.Item
          name="body"
          label="正文"
          rules={[
            { required: true, whitespace: true, message: '请输入邮件正文' },
          ]}
        >
          <Input.TextArea
            rows={test ? 4 : 8}
            maxLength={100000}
            readOnly={test}
          />
        </Form.Item>
      </Form>
    </Modal>
  );
}
