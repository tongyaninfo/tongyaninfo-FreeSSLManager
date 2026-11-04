import {
  ArrowRightOutlined,
  BookOutlined,
  CheckCircleOutlined,
  PlusOutlined,
  SettingOutlined,
  CloudServerOutlined,
  GlobalOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { PageContainer } from '@ant-design/pro-components';
import { Link, useAccess, useIntl, useModel } from '@umijs/max';
import {
  Alert,
  Button,
  Card,
  Col,
  Empty,
  List,
  Progress,
  Row,
  Space,
  Tag,
  Typography,
} from 'antd';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  accountApi,
  certificateApi,
  domainApi,
} from '@/services/ssl-manager/api';
import type {
  Certificate,
  CloudAccount,
  DnsZone,
  PageResult,
  Provider,
} from '@/services/ssl-manager/types';
import { providerNames, StatusTag } from '@/components/ssl-manager';
import {
  formatCertificateExpiry,
  getExpiringCertificates,
} from './certificateSummary';
import './index.css';

type DashboardData = {
  accounts: CloudAccount[];
  domains: DnsZone[];
  certificates: Certificate[];
};

const PAGE_SIZE = 200;
const certificateStatuses = [
  'Issued',
  'Processing',
  'PendingValidation',
  'Expired',
  'Revoked',
  'Failed',
  'Cancelled',
  'Deleting',
  'Revoking',
  'Unknown',
];

/** 将分页接口完整读取，保证仪表盘分布统计不会只统计第一页。 */
async function loadAll<T>(
  load: (
    page: number,
    pageSize: number,
  ) => Promise<{
    success: boolean;
    code: string;
    message: string;
    data?: PageResult<T>;
  }>,
): Promise<{ items: T[]; error?: string }> {
  const first = await load(1, PAGE_SIZE);
  if (!first.success || !first.data) {
    return { items: [], error: first.message || '读取统计数据失败。' };
  }
  const pageCount = Math.ceil(first.data.total / PAGE_SIZE);
  if (pageCount <= 1) return { items: first.data.items };
  const rest = await Promise.all(
    Array.from({ length: pageCount - 1 }, (_, index) =>
      load(index + 2, PAGE_SIZE),
    ),
  );
  const failed = rest.find((result) => !result.success || !result.data);
  if (failed && !failed.success) {
    return { items: [], error: failed.message || '读取统计数据失败。' };
  }
  return {
    items: [
      ...first.data.items,
      ...rest.flatMap((result) => result.data?.items ?? []),
    ],
  };
}

const Dashboard: React.FC = () => {
  const intl = useIntl();
  const access = useAccess();
  const { initialState } = useModel('@@initialState');
  const t = (
    id: string,
    fallback: string,
    values?: Record<string, string | number>,
  ) => intl.formatMessage({ id, defaultMessage: fallback }, values);
  const locale = intl.locale.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en-US';
  const [data, setData] = useState<DashboardData>({
    accounts: [],
    domains: [],
    certificates: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    const [accounts, domains, certificates] = await Promise.all([
      accountApi.options(),
      loadAll((page, pageSize) => domainApi.list({ page, pageSize })),
      loadAll((page, pageSize) =>
        certificateApi.list({ page, pageSize, freeOnly: false }),
      ),
    ]);
    const errors = [
      accounts.success ? '' : accounts.message,
      domains.error ?? '',
      certificates.error ?? '',
    ].filter(Boolean);
    if (errors.length > 0) setError(errors.join('；'));
    setData({
      accounts: accounts.success ? (accounts.data ?? []) : [],
      domains: domains.items,
      certificates: certificates.items,
    });
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const statusCounts = useMemo(() => {
    const counts = new Map<string, number>();
    data.certificates.forEach((item) => {
      counts.set(item.status, (counts.get(item.status) ?? 0) + 1);
    });
    return certificateStatuses
      .map((status) => ({ status, count: counts.get(status) ?? 0 }))
      .concat(
        [...counts.entries()]
          .filter(([status]) => !certificateStatuses.includes(status))
          .map(([status, count]) => ({ status, count })),
      )
      .filter((item) => item.count > 0);
  }, [data.certificates]);

  const expiring = useMemo(
    () => getExpiringCertificates(data.certificates, Date.now()),
    [data.certificates],
  );
  const expiringPreview = expiring.slice(0, 8);

  const providerCounts = useMemo(() => {
    const counts = new Map<Provider, number>();
    data.certificates.forEach((item) => {
      counts.set(item.provider, (counts.get(item.provider) ?? 0) + 1);
    });
    return (['TencentCloud', 'Aliyun', 'Acme'] as Provider[]).map(
      (provider) => ({
        key: provider,
        provider,
        count: counts.get(provider) ?? 0,
      }),
    );
  }, [data.certificates]);

  const issued = data.certificates.filter(
    (item) => item.status === 'Issued',
  ).length;
  const expired = data.certificates.filter(
    (item) => item.status === 'Expired',
  ).length;
  const statusTotal = Math.max(data.certificates.length, 1);
  const metrics = [
    {
      key: 'accounts',
      icon: <CloudServerOutlined />,
      label: t('ssl.dashboard.accounts', '启用的云账号'),
      value: data.accounts.length,
      detail: t('ssl.dashboard.accountsHint', '连接你的云端资源'),
      to: access.canAdmin ? '/configuration' : undefined,
    },
    {
      key: 'domains',
      icon: <GlobalOutlined />,
      label: t('ssl.dashboard.domains', '托管域名'),
      value: data.domains.length,
      detail: t('ssl.dashboard.domainsHint', '集中查看 DNS 与解析'),
      to: '/domains',
    },
    {
      key: 'certificates',
      icon: <SafetyCertificateOutlined />,
      label: t('ssl.dashboard.certificates', 'SSL 证书'),
      value: data.certificates.length,
      detail: t('ssl.dashboard.certificatesHint', '掌握证书全生命周期'),
      to: '/certificates',
    },
    {
      key: 'expiring',
      icon: <WarningOutlined />,
      label: t('ssl.dashboard.expiring', '30 天内到期'),
      value: expiring.length,
      detail: t('ssl.dashboard.expiringHint', '及时关注到期与续期'),
      to: '/certificates',
    },
  ];
  const shortcuts = [
    ...(access.canAdmin
      ? [
          {
            to: '/certificates/apply',
            icon: <PlusOutlined />,
            title: t('ssl.page.certificates.apply', '申请免费 SSL 证书'),
            detail: t('ssl.dashboard.applyHint', '开始新的证书申请'),
          },
          {
            to: '/configuration',
            icon: <SettingOutlined />,
            title: t('ssl.menu.configuration', '配置管理'),
            detail: t('ssl.dashboard.configureHint', '管理云账号与同步计划'),
          },
        ]
      : []),
    {
      to: '/domains',
      icon: <GlobalOutlined />,
      title: t('ssl.menu.domains', '域名管理'),
      detail: t('ssl.dashboard.domainsHint', '集中查看 DNS 与解析'),
    },
    {
      to: '/welcome',
      icon: <BookOutlined />,
      title: t('ssl.dashboard.guide', '使用指南'),
      detail: t('ssl.dashboard.guideHint', '了解配置与操作流程'),
    },
  ];

  return (
    <PageContainer title={false} breadcrumb={{ items: [] }}>
      <div
        className={`ty-ssl-dashboard${initialState?.settings?.navTheme === 'realDark' ? ' is-dark' : ''}`}
      >
        <section className="ty-ssl-dashboard__hero">
          <div>
            <span className="ty-ssl-dashboard__eyebrow">
              FREE SSL / WORKSPACE
            </span>
            <h1>{t('ssl.dashboard.workspace', '证书管理工作台')}</h1>
            <p>
              {t(
                'ssl.page.dashboard.subtitle',
                '查看云账号、域名和 SSL 证书的总体运行情况',
              )}
            </p>
          </div>
          <Space wrap>
            <Button
              icon={<ReloadOutlined />}
              loading={loading}
              onClick={() => void load()}
            >
              {t('ssl.dashboard.refresh', '刷新统计')}
            </Button>
            {access.canAdmin && (
              <Link to="/certificates/apply">
                <Button type="primary" icon={<PlusOutlined />}>
                  {t('ssl.common.apply', '申请')}
                </Button>
              </Link>
            )}
          </Space>
        </section>
        {error && (
          <Alert
            type="warning"
            showIcon
            title={error}
            style={{ marginBottom: 20 }}
          />
        )}
        <Row gutter={[18, 18]}>
          {metrics.map((metric) => (
            <Col xs={24} sm={12} xl={6} key={metric.key}>
              <Card
                loading={loading}
                className={`ty-ssl-dashboard__metric ty-ssl-dashboard__metric--${metric.key}`}
              >
                <div className="ty-ssl-dashboard__metric-top">
                  <span>{metric.label}</span>
                  <span className="ty-ssl-dashboard__metric-icon">
                    {metric.icon}
                  </span>
                </div>
                <strong className="ty-ssl-dashboard__number">
                  {metric.value.toLocaleString(locale)}
                </strong>
                <div className="ty-ssl-dashboard__metric-bottom">
                  <span>{metric.detail}</span>
                  {metric.to && (
                    <Link to={metric.to} aria-label={metric.label}>
                      <ArrowRightOutlined />
                    </Link>
                  )}
                </div>
              </Card>
            </Col>
          ))}
        </Row>
        <Row gutter={[20, 20]} className="ty-ssl-dashboard__sections">
          <Col xs={24} xl={16}>
            <Card
              className="ty-ssl-dashboard__panel"
              loading={loading}
              title={
                <Space>
                  <span className="ty-ssl-dashboard__section-mark" />
                  {t('ssl.dashboard.expiringList', '近期到期证书')}
                </Space>
              }
              extra={
                <Link to="/certificates">
                  {t('ssl.dashboard.viewCertificates', '查看证书')}{' '}
                  <ArrowRightOutlined />
                </Link>
              }
            >
              <div className="ty-ssl-dashboard__notice">
                <WarningOutlined />
                <span>
                  {t(
                    'ssl.dashboard.expiringNotice',
                    '30 天内到期 {count} 张，按到期时间展示最近 8 张。',
                    { count: expiring.length },
                  )}
                </span>
              </div>
              <List
                dataSource={expiringPreview}
                locale={{
                  emptyText: (
                    <Empty
                      image={Empty.PRESENTED_IMAGE_SIMPLE}
                      description={t(
                        'ssl.dashboard.noExpiring',
                        '暂无近期到期证书',
                      )}
                    />
                  ),
                }}
                renderItem={(item) => (
                  <List.Item
                    className="ty-ssl-dashboard__certificate"
                    actions={[<StatusTag key="status" value={item.status} />]}
                  >
                    <List.Item.Meta
                      avatar={
                        <span className="ty-ssl-dashboard__certificate-icon">
                          <SafetyCertificateOutlined />
                        </span>
                      }
                      title={
                        <Link to={`/certificates/${item.id}`}>
                          {item.domain || '—'}
                        </Link>
                      }
                      description={
                        <span>
                          {item.alias || item.accountName || '—'}
                          <br />
                          {formatCertificateExpiry(item.notAfterUtc)}
                        </span>
                      }
                    />
                  </List.Item>
                )}
              />
            </Card>
          </Col>
          <Col xs={24} xl={8}>
            <Card
              className="ty-ssl-dashboard__panel"
              title={t('ssl.dashboard.quickAccess', '常用入口')}
            >
              <div className="ty-ssl-dashboard__shortcuts">
                {shortcuts.map((item) => (
                  <Link
                    className="ty-ssl-dashboard__shortcut"
                    key={item.to}
                    to={item.to}
                  >
                    <span className="ty-ssl-dashboard__shortcut-icon">
                      {item.icon}
                    </span>
                    <span>
                      <strong>{item.title}</strong>
                      <small>{item.detail}</small>
                    </span>
                    <ArrowRightOutlined />
                  </Link>
                ))}
              </div>
            </Card>
            <div className="ty-ssl-dashboard__scope">
              <SafetyCertificateOutlined />
              <span>
                {t(
                  'ssl.dashboard.dataHint',
                  '统计来自当前已同步的云端资源，最新状态请在管理页面核对。',
                )}
              </span>
            </div>
          </Col>
        </Row>
        <Row gutter={[20, 20]} className="ty-ssl-dashboard__sections">
          <Col xs={24} xl={12}>
            <Card
              className="ty-ssl-dashboard__panel"
              title={t('ssl.dashboard.status', '证书状态分布')}
              loading={loading}
            >
              <div className="ty-ssl-dashboard__status-summary">
                <span>
                  <CheckCircleOutlined /> {t('ssl.dashboard.issued', '已签发')}{' '}
                  <strong>{issued}</strong>
                </span>
                <span>
                  <WarningOutlined /> {t('ssl.dashboard.expired', '已过期')}{' '}
                  <strong>{expired}</strong>
                </span>
              </div>
              {statusCounts.length === 0 ? (
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description={t('ssl.common.noData', '暂无数据')}
                />
              ) : (
                <Space
                  orientation="vertical"
                  style={{ width: '100%' }}
                  size="middle"
                >
                  {statusCounts.map((item) => (
                    <div key={item.status}>
                      <div className="ty-ssl-dashboard__distribution">
                        <StatusTag value={item.status} />
                        <Typography.Text>{item.count}</Typography.Text>
                      </div>
                      <Progress
                        percent={Math.round((item.count / statusTotal) * 100)}
                        showInfo={false}
                        size="small"
                        strokeColor={
                          item.status === 'Expired' || item.status === 'Failed'
                            ? '#e48a2d'
                            : '#1849a9'
                        }
                      />
                    </div>
                  ))}
                </Space>
              )}
            </Card>
          </Col>
          <Col xs={24} xl={12}>
            <Card
              className="ty-ssl-dashboard__panel"
              title={t('ssl.dashboard.providers', '云平台分布')}
              loading={loading}
            >
              {providerCounts.map((item) => (
                <div className="ty-ssl-dashboard__provider" key={item.key}>
                  <div className="ty-ssl-dashboard__distribution">
                    <span>
                      <CloudServerOutlined />{' '}
                      {providerNames[item.provider] ?? item.provider}
                    </span>
                    <Space>
                      <strong>{item.count}</strong>
                      <Tag>{Math.round((item.count / statusTotal) * 100)}%</Tag>
                    </Space>
                  </div>
                  <Progress
                    percent={Math.round((item.count / statusTotal) * 100)}
                    showInfo={false}
                    strokeColor={
                      item.provider === 'Aliyun' ? '#e48a2d' : '#1849a9'
                    }
                  />
                </div>
              ))}
              <p className="ty-ssl-dashboard__provider-note">
                {t('ssl.dashboard.providerHint', '按证书所属云平台统计')}
              </p>
            </Card>
          </Col>
        </Row>
      </div>
    </PageContainer>
  );
};

export default Dashboard;
