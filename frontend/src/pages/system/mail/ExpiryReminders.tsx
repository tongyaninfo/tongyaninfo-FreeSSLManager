import { useAccess } from '@umijs/max';
import {
  Alert,
  Button,
  Card,
  Form,
  InputNumber,
  Modal,
  Result,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd';
import React, { useEffect, useRef, useState } from 'react';
import { dateText } from '@/components/ssl-manager';
import { mailApi } from '@/services/ssl-manager/mail';
import type {
  ExpiryReminderAlert,
  ExpiryReminderAlertStatus,
  ExpiryReminderSettingsInput,
  ExpiryReminderSettingsSummary,
} from '@/services/ssl-manager/mailTypes';
import type { PageResult } from '@/services/ssl-manager/types';
import { MailStatus } from './presentation';

const statusNames: Record<ExpiryReminderAlertStatus, string> = {
  Active: '预警中',
  Resolved: '已解除',
  Ignored: '已忽略',
};
const unknownResultCodes = new Set([
  'NETWORK_ERROR',
  'INVALID_RESPONSE',
  'SYSTEM_ERROR',
]);
type AlertQuery = {
  status: ExpiryReminderAlertStatus | 'All';
  page: number;
  pageSize: number;
};

function settingsValues(
  value: ExpiryReminderSettingsSummary,
): ExpiryReminderSettingsInput {
  return {
    enabled: value.enabled,
    daysBeforeExpiry: value.daysBeforeExpiry,
    repeatIntervalDays: value.repeatIntervalDays,
    recipients: value.recipients,
  };
}

/** 仅管理员维护提醒；实际检查和发送由后端执行，页面不触发发信。 */
export default function ExpiryReminders() {
  const access = useAccess();
  return access.canAdmin ? (
    <ExpiryReminderContent />
  ) : (
    <Result status="403" title="无到期提醒管理权限" />
  );
}

function ExpiryReminderContent() {
  const [form] = Form.useForm<ExpiryReminderSettingsInput>();
  const enabled = Form.useWatch('enabled', form);
  const active = useRef(true);
  const pending = useRef(false);
  const settingsRequest = useRef(0);
  const alertsRequest = useRef(0);
  const [settings, setSettings] = useState<ExpiryReminderSettingsSummary>();
  const [settingsLoading, setSettingsLoading] = useState(true);
  const [settingsError, setSettingsError] = useState('');
  const [settingsRevision, setSettingsRevision] = useState(0);
  const [query, setQuery] = useState<AlertQuery>({
    status: 'Active',
    page: 1,
    pageSize: 20,
  });
  const [alerts, setAlerts] = useState<PageResult<ExpiryReminderAlert>>();
  const [alertsLoading, setAlertsLoading] = useState(true);
  const [alertsError, setAlertsError] = useState('');
  const [alertsRevision, setAlertsRevision] = useState(0);
  const [busy, setBusy] = useState<'save' | 'ignore'>();
  const [selected, setSelected] = useState<ExpiryReminderAlert>();
  const [notice, setNotice] = useState('');
  const [denied, setDenied] = useState(false);

  const clearAuthorization = () => {
    active.current = false;
    settingsRequest.current++;
    alertsRequest.current++;
    form.resetFields();
    setSettings(undefined);
    setAlerts(undefined);
    setSelected(undefined);
    setSettingsError('');
    setAlertsError('');
    setNotice('');
    setDenied(true);
  };
  const authorizationFailed = (code: string) => {
    if (code !== 'UNAUTHORIZED' && code !== 'FORBIDDEN') return false;
    clearAuthorization();
    return true;
  };

  useEffect(() => {
    active.current = true;
    const expire = () => clearAuthorization();
    window.addEventListener('ssl-auth-expired', expire);
    return () => {
      active.current = false;
      settingsRequest.current++;
      alertsRequest.current++;
      window.removeEventListener('ssl-auth-expired', expire);
    };
  }, []);

  useEffect(() => {
    const request = ++settingsRequest.current;
    setSettingsLoading(true);
    setSettingsError('');
    void mailApi
      .expiryReminderSettings()
      .then((result) => {
        if (
          !active.current ||
          request !== settingsRequest.current ||
          authorizationFailed(result.code)
        )
          return;
        if (result.success && result.data) {
          setSettings(result.data);
          form.setFieldsValue(settingsValues(result.data));
        } else setSettingsError(result.message || '读取到期提醒设置失败。');
      })
      .catch(() => {
        if (active.current && request === settingsRequest.current)
          setSettingsError('读取到期提醒设置失败，请重试。');
      })
      .finally(() => {
        if (active.current && request === settingsRequest.current)
          setSettingsLoading(false);
      });
  }, [form, settingsRevision]);

  useEffect(() => {
    const request = ++alertsRequest.current;
    setAlertsLoading(true);
    setAlertsError('');
    void mailApi
      .expiryReminderAlerts({
        page: query.page,
        pageSize: query.pageSize,
        status: query.status === 'All' ? undefined : query.status,
      })
      .then((result) => {
        if (
          !active.current ||
          request !== alertsRequest.current ||
          authorizationFailed(result.code)
        )
          return;
        if (result.success && result.data) setAlerts(result.data);
        else {
          setAlerts(undefined);
          setAlertsError(result.message || '读取预警列表失败。');
        }
      })
      .catch(() => {
        if (active.current && request === alertsRequest.current) {
          setAlerts(undefined);
          setAlertsError('读取预警列表失败，请重试。');
        }
      })
      .finally(() => {
        if (active.current && request === alertsRequest.current)
          setAlertsLoading(false);
      });
  }, [query, alertsRevision]);

  const save = async (values: ExpiryReminderSettingsInput) => {
    if (pending.current || !active.current) return;
    pending.current = true;
    setBusy('save');
    setSettingsError('');
    setNotice('');
    // 按大小写无关的邮箱去重，保留首个地址的展示形式。
    const recipients = values.recipients?.map((value) => value.trim()) || [];
    const uniqueRecipients = recipients.filter(
      (value, index) =>
        recipients.findIndex(
          (candidate) => candidate.toLowerCase() === value.toLowerCase(),
        ) === index,
    );
    try {
      const result = await mailApi.saveExpiryReminderSettings({
        enabled: values.enabled,
        daysBeforeExpiry: values.daysBeforeExpiry,
        repeatIntervalDays: values.repeatIntervalDays,
        recipients: uniqueRecipients,
      });
      if (!active.current || authorizationFailed(result.code)) return;
      if (result.success && result.data) {
        setSettings(result.data);
        form.setFieldsValue(settingsValues(result.data));
        setNotice('到期提醒设置已保存，后台将按规则检查；本次保存未发送邮件。');
      } else
        setSettingsError(
          unknownResultCodes.has(result.code)
            ? '保存结果暂时无法确认，请重新加载规则核对。'
            : result.message || '保存到期提醒设置失败。',
        );
    } catch {
      if (active.current)
        setSettingsError('保存结果暂时无法确认，请重新加载规则核对。');
    } finally {
      pending.current = false;
      if (active.current) setBusy(undefined);
    }
  };

  const ignore = async () => {
    if (pending.current || !active.current || !selected) return;
    pending.current = true;
    setBusy('ignore');
    setAlertsError('');
    setNotice('');
    try {
      const result = await mailApi.ignoreExpiryReminderAlert(selected.id);
      if (!active.current || authorizationFailed(result.code)) return;
      if (result.success) {
        setSelected(undefined);
        setNotice('已忽略该预警，后续提醒已停止。');
        setAlertsRevision((value) => value + 1);
      } else {
        setAlertsError(result.message || '忽略预警失败。');
        if (unknownResultCodes.has(result.code)) {
          setSelected(undefined);
          setAlertsError('忽略请求结果暂时无法确认，请刷新预警列表核对。');
        }
      }
    } catch {
      if (active.current) {
        setSelected(undefined);
        setAlertsError('忽略请求结果暂时无法确认，请刷新预警列表核对。');
      }
    } finally {
      pending.current = false;
      if (active.current) setBusy(undefined);
    }
  };

  if (denied)
    return (
      <Result status="403" title="登录或管理权限已失效，已清除到期提醒信息。" />
    );
  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      {notice && <Alert type="success" showIcon title={notice} />}
      <Card title="到期提醒规则">
        <Typography.Paragraph type="secondary">
          证书进入提前天数范围后首次预警，随后按重复间隔提醒；0
          天表示仅首次提醒。未解除的预警在证书过期后仍继续提醒；有效期更新至范围外、撤销或删除后自动解除。
        </Typography.Paragraph>
        {settingsError && (
          <Alert
            type="error"
            showIcon
            title={settingsError}
            style={{ marginBottom: 16 }}
            action={
              <Button
                size="small"
                disabled={Boolean(busy)}
                onClick={() => setSettingsRevision((value) => value + 1)}
              >
                重新加载规则
              </Button>
            }
          />
        )}
        {settings && !settings.smtpConfigured && (
          <Alert
            type="warning"
            showIcon
            title="尚未配置 SMTP，提醒暂时无法发送。"
            description="可先保存规则，再到“邮箱设置”配置并启用系统发送邮箱。"
            style={{ marginBottom: 16 }}
          />
        )}
        {settings?.smtpConfigured && !settings.smtpEnabled && (
          <Alert
            type="warning"
            showIcon
            title="系统邮件发送已停用，提醒暂时无法发送。"
            description="可先保存规则，在“邮箱设置”启用邮件发送后按规则提醒。"
            style={{ marginBottom: 16 }}
          />
        )}
        <Spin spinning={settingsLoading}>
          <Form<ExpiryReminderSettingsInput>
            form={form}
            layout="vertical"
            style={{ maxWidth: 820 }}
            initialValues={{
              enabled: false,
              daysBeforeExpiry: 30,
              repeatIntervalDays: 1,
              recipients: [],
            }}
            disabled={settingsLoading || Boolean(busy) || !settings}
            onFinish={save}
          >
            <Form.Item
              name="enabled"
              label="启用证书到期提醒"
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
            <Space wrap align="start">
              <Form.Item
                name="daysBeforeExpiry"
                label="提前提醒天数"
                rules={[
                  {
                    required: true,
                    type: 'number',
                    min: 1,
                    max: 365,
                    message: '提前天数须为 1～365 的整数',
                  },
                  {
                    validator: (_, value) =>
                      Number.isInteger(value)
                        ? Promise.resolve()
                        : Promise.reject(new Error('请填写整数天数')),
                  },
                ]}
              >
                <InputNumber min={1} max={365} precision={0} />
              </Form.Item>
              <Form.Item
                name="repeatIntervalDays"
                label="重复提醒间隔（天）"
                extra="0 表示仅首次提醒"
                rules={[
                  {
                    required: true,
                    type: 'number',
                    min: 0,
                    max: 365,
                    message: '重复间隔须为 0～365 的整数',
                  },
                  {
                    validator: (_, value) =>
                      Number.isInteger(value)
                        ? Promise.resolve()
                        : Promise.reject(new Error('请填写整数天数')),
                  },
                ]}
              >
                <InputNumber min={0} max={365} precision={0} />
              </Form.Item>
            </Space>
            <Form.Item
              name="recipients"
              label="提醒收件人"
              dependencies={['enabled']}
              extra="输入邮箱后按回车，可用逗号或分号分隔，最多 50 个。"
              rules={[
                {
                  validator: (_, values: string[] = []) => {
                    if (enabled && values.length === 0)
                      return Promise.reject(
                        new Error('启用提醒时请至少填写一个收件邮箱'),
                      );
                    if (values.length > 50)
                      return Promise.reject(
                        new Error('最多填写 50 个收件邮箱'),
                      );
                    if (
                      values.some(
                        (value) =>
                          value.trim().length > 254 ||
                          !/^[^@\s]+@[^@\s]+$/.test(value.trim()),
                      )
                    )
                      return Promise.reject(new Error('请检查收件邮箱格式'));
                    return Promise.resolve();
                  },
                },
              ]}
            >
              <Select
                mode="tags"
                tokenSeparators={[',', ';', '，', '；', ' ', '\n']}
                open={false}
                placeholder="例如 recipient@example.com"
              />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={busy === 'save'}>
              保存提醒设置
            </Button>
          </Form>
        </Spin>
      </Card>
      <Card
        title="到期预警"
        extra={
          <Button
            disabled={Boolean(busy)}
            loading={alertsLoading}
            onClick={() => setAlertsRevision((value) => value + 1)}
          >
            刷新预警
          </Button>
        }
      >
        <Space wrap style={{ marginBottom: 16 }}>
          <Typography.Text>预警状态</Typography.Text>
          <Select
            aria-label="预警状态"
            style={{ width: 160 }}
            value={query.status}
            disabled={Boolean(busy)}
            options={[
              { value: 'Active', label: '预警中' },
              { value: 'Resolved', label: '已解除' },
              { value: 'Ignored', label: '已忽略' },
              { value: 'All', label: '全部状态' },
            ]}
            onChange={(status) =>
              setQuery((value) => ({ ...value, status, page: 1 }))
            }
          />
        </Space>
        {alertsError && (
          <Alert
            type="error"
            showIcon
            title={alertsError}
            style={{ marginBottom: 16 }}
          />
        )}
        <Table<ExpiryReminderAlert>
          rowKey="id"
          loading={alertsLoading}
          dataSource={alerts?.items || []}
          scroll={{ x: 1500 }}
          pagination={{
            current: query.page,
            pageSize: query.pageSize,
            total: alerts?.total || 0,
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100],
            disabled: Boolean(busy) || alertsLoading,
            showTotal: (total) => `共 ${total} 条预警`,
            onChange: (page, pageSize) =>
              setQuery((value) => ({ ...value, page, pageSize })),
          }}
          columns={[
            { title: '域名', dataIndex: 'domain', width: 200 },
            {
              title: '别名 / 云账号',
              width: 200,
              render: (_, item) => (
                <>
                  {item.alias || '—'}
                  <br />
                  <Typography.Text type="secondary">
                    {item.accountName || '—'}
                  </Typography.Text>
                </>
              ),
            },
            {
              title: '证书到期时间',
              dataIndex: 'notAfterUtc',
              width: 180,
              render: (value) => dateText(value),
            },
            {
              title: '预警状态',
              dataIndex: 'status',
              width: 110,
              render: (status: ExpiryReminderAlertStatus) => (
                <Tag
                  color={
                    status === 'Active'
                      ? 'warning'
                      : status === 'Resolved'
                        ? 'success'
                        : undefined
                  }
                >
                  {statusNames[status]}
                </Tag>
              ),
            },
            {
              title: '首次发现',
              dataIndex: 'firstDetectedAtUtc',
              width: 180,
              render: (value) => dateText(value),
            },
            {
              title: '最近尝试',
              dataIndex: 'lastAttemptAtUtc',
              width: 180,
              render: (value) => dateText(value || undefined),
            },
            {
              title: '下次提醒',
              dataIndex: 'nextReminderAtUtc',
              width: 180,
              render: (value) => dateText(value || undefined),
            },
            {
              title: '最近邮件结果',
              dataIndex: 'lastMailStatus',
              width: 190,
              render: (value) =>
                value === 'NotSubmitted' ? (
                  <Tag>尚未提交 SMTP</Tag>
                ) : value ? (
                  <MailStatus status={value} />
                ) : (
                  '尚未发送'
                ),
            },
            { title: '结果说明', dataIndex: 'message', width: 260 },
            {
              title: '操作',
              fixed: 'right',
              width: 100,
              render: (_, item) =>
                item.status === 'Active' ? (
                  <Button
                    type="link"
                    disabled={Boolean(busy)}
                    onClick={() => setSelected(item)}
                  >
                    忽略
                  </Button>
                ) : (
                  '—'
                ),
            },
          ]}
        />
      </Card>
      <Modal
        open={Boolean(selected)}
        title="忽略证书到期预警"
        okText="确认忽略"
        cancelText="取消"
        confirmLoading={busy === 'ignore'}
        closable={!busy}
        keyboard={!busy}
        mask={{ closable: !busy }}
        onCancel={() => {
          if (!pending.current) setSelected(undefined);
        }}
        onOk={() => void ignore()}
      >
        <Typography.Paragraph>
          忽略 {selected?.domain || '该证书'}{' '}
          的本次到期预警后，仅停止后续提醒；已经提交的邮件仍可能送达。
        </Typography.Paragraph>
      </Modal>
    </Space>
  );
}
