import {
  CloudServerOutlined,
  GlobalOutlined,
  LockOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons';
import {
  LoginForm,
  ProFormCheckbox,
  ProFormText,
} from '@ant-design/pro-components';
import { Helmet, useIntl, useModel } from '@umijs/max';
import { Alert, App } from 'antd';
import React, { startTransition, useState } from 'react';
import { Footer, LangDropdown } from '@/components';
import { authApi, resetCsrfToken } from '@/services/ssl-manager/api';
import Settings from '../../../../config/defaultSettings';
import './index.css';

const getSafeRedirectUrl = (redirect: string | null): string => {
  if (!redirect?.startsWith('/') || redirect.startsWith('//')) return '/';
  try {
    const parsed = new URL(redirect, window.location.origin);
    if (parsed.origin !== window.location.origin) return '/';
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return '/';
  }
};

const Login: React.FC = () => {
  const [error, setError] = useState('');
  const { setInitialState } = useModel('@@initialState');
  const { message } = App.useApp();
  const intl = useIntl();
  const t = (id: string, defaultMessage: string) =>
    intl.formatMessage({ id, defaultMessage });

  const handleSubmit = async (values: {
    username?: string;
    password?: string;
  }) => {
    setError('');
    const result = await authApi.login(values);
    if (!result.success) {
      setError(
        result.message || t('pages.login.failure', '登录失败，请重试！'),
      );
      return false;
    }
    resetCsrfToken();
    const current = await authApi.current();
    if (!current.success) {
      setError(
        current.message || t('pages.login.failure', '登录失败，请重试！'),
      );
      return false;
    }
    // 先更新运行时会话，再导航。若立即导航，布局的权限守卫可能读到旧状态，
    // 将已经登录的用户重新送回登录页，表现为需要登录两次。
    startTransition(() =>
      setInitialState((state) => ({ ...state, currentUser: current.data })),
    );
    message.success(t('pages.login.success', '登录成功！'));
    const redirect = getSafeRedirectUrl(
      new URL(window.location.href).searchParams.get('redirect'),
    );
    // 使用整页导航让 Umi 重新读取 Cookie 会话，避免首次登录时运行时状态更新与路由守卫竞争。
    window.location.assign(redirect);
    return true;
  };

  return (
    <div className="ty-ssl-login">
      <Helmet>
        <title>
          {t('menu.login', '登录')} - {Settings.title}
        </title>
      </Helmet>
      <header className="ty-ssl-login__header">
        <img
          className="ty-ssl-login__brand"
          alt="通研技术"
          src="/assets/brand/tyinfo-logo-horizontal.png"
        />
        <div className="ty-ssl-login__lang">
          <LangDropdown />
        </div>
      </header>
      <main className="ty-ssl-login__main">
        <section className="ty-ssl-login__intro">
          <span className="ty-ssl-login__eyebrow">FREE SSL / CONSOLE</span>
          <h1>{t('ssl.app.name', '通研FREE SSL管理')}</h1>
          <p>{t('ssl.login.subtitle', '云端证书与域名，集中有序管理')}</p>
          <div className="ty-ssl-login__features">
            {[
              {
                icon: <SafetyCertificateOutlined />,
                title: t('ssl.login.certificates', '让证书管理更从容'),
                detail: t(
                  'ssl.login.certificatesDetail',
                  '申请、查看与部署 SSL 证书',
                ),
              },
              {
                icon: <GlobalOutlined />,
                title: t('ssl.login.domains', '让域名管理更清晰'),
                detail: t(
                  'ssl.login.domainsDetail',
                  '集中查看域名与 DNS 解析记录',
                ),
              },
              {
                icon: <CloudServerOutlined />,
                title: t('ssl.login.accounts', '让多云协作更有序'),
                detail: t(
                  'ssl.login.accountsDetail',
                  '统一管理腾讯云与阿里云账号',
                ),
              },
            ].map((item) => (
              <div className="ty-ssl-login__feature" key={item.title}>
                <div className="ty-ssl-login__icon">{item.icon}</div>
                <div>
                  <strong>{item.title}</strong>
                  <span>{item.detail}</span>
                </div>
              </div>
            ))}
          </div>
        </section>
        <section
          className="ty-ssl-login__card"
          aria-labelledby="ssl-login-heading"
        >
          <span className="ty-ssl-login__accent" />
          <h2 id="ssl-login-heading">{t('ssl.login.welcome', '欢迎回来')}</h2>
          <p>
            {t('ssl.login.description', '登录你的账号，进入证书管理工作台。')}
          </p>
          <LoginForm
            contentStyle={{ width: '100%', minWidth: 0 }}
            initialValues={{ autoLogin: true }}
            submitter={{
              searchConfig: {
                submitText: t('ssl.login.submit', '登录管理平台'),
              },
            }}
            onFinish={handleSubmit}
          >
            {error && (
              <Alert
                style={{ marginBottom: 24 }}
                title={error}
                type="error"
                showIcon
              />
            )}
            <ProFormText
              name="username"
              label={t('ssl.login.username', '用户名')}
              fieldProps={{
                size: 'large',
                prefix: <UserOutlined />,
                autoComplete: 'username',
              }}
              placeholder={t('ssl.login.usernamePlaceholder', '请输入用户名')}
              rules={[
                {
                  required: true,
                  message: t('pages.login.username.required', '请输入用户名！'),
                },
              ]}
            />
            <ProFormText.Password
              name="password"
              label={t('ssl.login.password', '密码')}
              fieldProps={{
                size: 'large',
                prefix: <LockOutlined />,
                autoComplete: 'current-password',
              }}
              placeholder={t('ssl.login.passwordPlaceholder', '请输入密码')}
              rules={[
                {
                  required: true,
                  message: t('pages.login.password.required', '请输入密码！'),
                },
              ]}
            />
            <div className="ty-ssl-login__remember">
              <ProFormCheckbox noStyle name="autoLogin">
                {t('pages.login.rememberMe', '自动登录')}
              </ProFormCheckbox>
            </div>
          </LoginForm>
          <div className="ty-ssl-login__note">
            <LockOutlined />
            <span>
              {t(
                'ssl.login.note',
                '请使用管理员分配的账号登录，妥善保管账号信息。',
              )}
            </span>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  );
};

export default Login;
