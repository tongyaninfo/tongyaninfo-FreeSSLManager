import type { SettingDrawerProps } from '@ant-design/pro-components';
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from '@testing-library/react';
import React, { useState } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AppState } from '@/app';
import AppearanceSettings from './index';

const mocks = vi.hoisted(() => ({
  model: undefined as
    | {
        initialState: AppState;
        setInitialState: React.Dispatch<React.SetStateAction<AppState>>;
      }
    | undefined,
  drawer: undefined as SettingDrawerProps | undefined,
}));

vi.mock('@umijs/max', () => ({
  useModel: () => mocks.model,
  useIntl: () => ({
    formatMessage: ({ defaultMessage }: { defaultMessage?: string }) =>
      defaultMessage,
  }),
}));

// 仅替换框架抽屉，保留真实自动开关、媒体查询订阅与 React 全局状态流。
vi.mock('@ant-design/pro-components', () => ({
  SettingDrawer: (props: SettingDrawerProps) => {
    mocks.drawer = props;
    return (
      <div>
        {props.drawerProps?.extra}
        <button
          type="button"
          onClick={() =>
            props.onSettingChange?.({ ...props.settings, navTheme: 'light' })
          }
        >
          浅色
        </button>
        <button
          type="button"
          onClick={() =>
            props.onSettingChange?.({ ...props.settings, navTheme: 'realDark' })
          }
        >
          深色
        </button>
      </div>
    );
  },
}));

const originalMatchMedia = window.matchMedia;
let dark = false;
let query: MediaQueryList;
let listeners: Set<(event: MediaQueryListEvent) => void>;

function changeSystemTheme(matches: boolean) {
  dark = matches;
  act(() => {
    for (const listener of listeners) {
      listener({ matches } as MediaQueryListEvent);
    }
  });
}

function Harness({ initialState }: { initialState: AppState }) {
  const [state, setState] = useState(initialState);
  mocks.model = { initialState: state, setInitialState: setState };
  return (
    <>
      <AppearanceSettings />
      <output aria-label="当前主题">{state.settings?.navTheme}</output>
      <output aria-label="所选模式">{state.themeMode}</output>
    </>
  );
}

beforeEach(() => {
  localStorage.clear();
  dark = false;
  listeners = new Set();
  query = {
    get matches() {
      return dark;
    },
    addEventListener: vi.fn((_event, callback) => {
      listeners.add(callback as (event: MediaQueryListEvent) => void);
    }),
    removeEventListener: vi.fn((_event, callback) => {
      listeners.delete(callback as (event: MediaQueryListEvent) => void);
    }),
  } as unknown as MediaQueryList;
  window.matchMedia = vi.fn(() => query);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.matchMedia = originalMatchMedia;
});

describe('自动主题与外观设置联动', () => {
  it('开启自动立即应用系统主题，运行中继续跟随，卸载后移除监听', () => {
    dark = true;
    const view = render(
      <Harness
        initialState={{ themeMode: 'light', settings: { navTheme: 'light' } }}
      />,
    );
    expect(listeners.size).toBe(0);
    fireEvent.click(screen.getByRole('switch', { name: '跟随系统' }));
    expect(screen.getByLabelText('当前主题')).toHaveTextContent('realDark');
    expect(screen.getByLabelText('所选模式')).toHaveTextContent('auto');
    expect(mocks.drawer?.settings?.navTheme).toBeUndefined();
    expect(localStorage.getItem('ssl-manager:theme-mode')).toBe('auto');
    expect(listeners.size).toBe(1);
    changeSystemTheme(false);
    expect(screen.getByLabelText('当前主题')).toHaveTextContent('light');
    expect(screen.getByLabelText('所选模式')).toHaveTextContent('auto');
    view.unmount();
    expect(listeners.size).toBe(0);
    expect(query.removeEventListener).toHaveBeenCalledWith(
      'change',
      expect.any(Function),
    );
  });

  it('自动时修改主色与切混合布局保留自动，点击当前同色卡片退出自动', () => {
    dark = true;
    render(
      <Harness
        initialState={{
          themeMode: 'auto',
          settings: {
            navTheme: 'realDark',
            layout: 'side',
            colorPrimary: '#1849a9',
          },
        }}
      />,
    );
    act(() => {
      mocks.drawer?.onSettingChange?.({
        ...mocks.drawer.settings,
        colorPrimary: '#1677ff',
      });
    });
    expect(mocks.model?.initialState.settings?.colorPrimary).toBe('#1677ff');
    expect(screen.getByLabelText('所选模式')).toHaveTextContent('auto');
    act(() => {
      mocks.drawer?.onSettingChange?.({
        ...mocks.drawer.settings,
        layout: 'mix',
        navTheme: 'light',
      });
    });
    expect(mocks.model?.initialState.settings?.layout).toBe('mix');
    expect(screen.getByLabelText('当前主题')).toHaveTextContent('realDark');
    expect(screen.getByLabelText('所选模式')).toHaveTextContent('auto');
    fireEvent.click(screen.getByRole('button', { name: '深色' }));
    expect(screen.getByRole('switch', { name: '跟随系统' })).not.toBeChecked();
    expect(screen.getByLabelText('所选模式')).toHaveTextContent('realDark');
    expect(listeners.size).toBe(0);
    changeSystemTheme(false);
    expect(screen.getByLabelText('当前主题')).toHaveTextContent('realDark');
    expect(localStorage.getItem('ssl-manager:theme-mode')).toBe('realDark');
  });

  it('关闭跟随系统后保持当时的主题，不再受系统变化影响', () => {
    render(
      <Harness
        initialState={{ themeMode: 'auto', settings: { navTheme: 'light' } }}
      />,
    );
    fireEvent.click(screen.getByRole('switch', { name: '跟随系统' }));
    expect(screen.getByLabelText('所选模式')).toHaveTextContent('light');
    changeSystemTheme(true);
    expect(screen.getByLabelText('当前主题')).toHaveTextContent('light');
    expect(listeners.size).toBe(0);
  });
});
