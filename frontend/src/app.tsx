import type { Settings as LayoutSettings } from '@ant-design/pro-components';
import type { RequestConfig, RunTimeLayoutConfig } from '@umijs/max';
import { history, Link } from '@umijs/max';
import { App } from 'antd';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import React, { useEffect } from 'react';

import {
  AvatarDropdown,
  DocLink,
  ErrorBoundary,
  Footer,
  LangDropdown,
  OfflineBanner,
} from '@/components';
import defaultSettings from '../config/defaultSettings';
import { errorConfig } from './requestErrorConfig';
import { authApi, resetCsrfToken } from './services/ssl-manager/api';
import type { User } from './services/ssl-manager/types';
import { readThemeMode, resolveTheme, type ThemeMode } from './utils/theme';

dayjs.extend(relativeTime);

const AppearanceSettings = React.lazy(
  () => import('./components/AppearanceSettings'),
);

const publicPaths = ['/user/login', '/user/setup'];

export interface AppState {
  currentUser?: User;
  settings?: Partial<LayoutSettings>;
  themeMode?: ThemeMode;
  settingDrawerOpen?: boolean;
  needsSetup?: boolean;
  fetchUserInfo?: () => Promise<User | undefined>;
}

/** 初始化仍以真实后端 Cookie 会话为准，模板 mock 登录接口不会参与。 */
export async function getInitialState(): Promise<AppState> {
  const fetchUserInfo = async () => {
    const result = await authApi.current();
    return result.success ? result.data : undefined;
  };
  const setup = await authApi.setupStatus();
  const needsSetup = setup.success && setup.data?.needsSetup;
  if (needsSetup && !publicPaths.includes(history.location.pathname)) {
    history.replace('/user/setup');
  }
  const currentUser = needsSetup ? undefined : await fetchUserInfo();
  if (
    !needsSetup &&
    !currentUser &&
    !publicPaths.includes(history.location.pathname)
  ) {
    history.replace('/user/login');
  }
  const themeMode = readThemeMode();
  return {
    currentUser,
    settings: {
      ...(defaultSettings as Partial<LayoutSettings>),
      navTheme: resolveTheme(themeMode),
    },
    themeMode,
    settingDrawerOpen: false,
    needsSetup,
    fetchUserInfo,
  };
}

export const layout: RunTimeLayoutConfig = ({ initialState }) => {
  const layoutSettings = (initialState?.settings ??
    defaultSettings) as Partial<LayoutSettings> & {
    colorPrimary?: string;
    token?: {
      [key: string]: unknown;
      sider?: Record<string, unknown>;
    };
  };
  const layoutToken = layoutSettings.token ?? {};
  const selectedMenuColor =
    layoutSettings.colorPrimary ?? defaultSettings.colorPrimary;
  // ProLayout 的 Menu 选中项颜色来自 token.layout.sider，而不是直接读取
  // colorPrimary。每次主题色变化都重新派生该 token，避免选中菜单仍使用黑色。
  const resolvedSettings = {
    ...layoutSettings,
    token: {
      ...layoutToken,
      sider: {
        ...layoutToken.sider,
        colorTextMenuSelected: selectedMenuColor,
      },
    },
  };
  const localeEnabled =
    (layoutSettings as { locale?: boolean })?.locale !== false;
  return {
    menuItemRender: (item, dom) =>
      item.path ? (
        <Link to={item.path} prefetch>
          {dom}
        </Link>
      ) : (
        dom
      ),
    actionsRender: () =>
      [
        <DocLink key="doc" />,
        localeEnabled && <LangDropdown key="lang" />,
      ].filter(Boolean),
    avatarProps: {
      title:
        initialState?.currentUser?.name || initialState?.currentUser?.username,
      render: (_, avatarChildren) => (
        <AvatarDropdown>{avatarChildren}</AvatarDropdown>
      ),
    },
    onPageChange: () => {
      if (
        !initialState?.currentUser &&
        !publicPaths.includes(history.location.pathname)
      ) {
        history.replace(
          initialState?.needsSetup ? '/user/setup' : '/user/login',
        );
      }
    },
    footerRender: () => <Footer />,
    links: [],
    ErrorBoundary,
    childrenRender: (children) => (
      <>
        {children}
        <React.Suspense fallback={null}>
          <AppearanceSettings />
        </React.Suspense>
      </>
    ),
    ...resolvedSettings,
    title: '通研FREE SSL管理',
  };
};

export const request: RequestConfig = { baseURL: '', ...errorConfig };

function SessionEvents() {
  const { message } = App.useApp();
  useEffect(() => {
    const notify = (event: Event) => {
      const detail = (event as CustomEvent<string>).detail;
      if (detail) message.error(detail);
    };
    window.addEventListener('ssl-system-error', notify);
    return () => window.removeEventListener('ssl-system-error', notify);
  }, [message]);
  return null;
}

function SessionBoundary({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    const expire = () => {
      resetCsrfToken();
      history.replace('/user/login');
    };
    window.addEventListener('ssl-auth-expired', expire);
    return () => {
      window.removeEventListener('ssl-auth-expired', expire);
    };
  }, []);
  return (
    <App>
      <SessionEvents />
      {children}
    </App>
  );
}

export function rootContainer(container: React.ReactNode) {
  return (
    <SessionBoundary>
      <OfflineBanner />
      <ErrorBoundary>{container}</ErrorBoundary>
    </SessionBoundary>
  );
}
