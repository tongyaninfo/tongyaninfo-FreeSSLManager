import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  getSystemTheme,
  readThemeMode,
  resolveTheme,
  saveThemeMode,
  subscribeSystemTheme,
} from './theme';

const originalMatchMedia = window.matchMedia;

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
  window.matchMedia = originalMatchMedia;
});

describe('浏览器主题模式', () => {
  it('保留自动模式意图，重新读取后仍按照当前系统主题解析', () => {
    saveThemeMode('auto');
    let dark = true;
    window.matchMedia = vi.fn(() => ({ matches: dark }) as MediaQueryList);
    expect(readThemeMode()).toBe('auto');
    expect(resolveTheme(readThemeMode())).toBe('realDark');
    dark = false;
    expect(resolveTheme(readThemeMode())).toBe('light');
    expect(readThemeMode()).toBe('auto');
    expect(resolveTheme('realDark')).toBe('realDark');
  });

  it('无效存储和禁用本地存储时回退浅色，保存失败不阻断当前会话', () => {
    localStorage.setItem('ssl-manager:theme-mode', 'unknown');
    expect(readThemeMode()).toBe('light');
    vi.spyOn(window.localStorage, 'getItem').mockImplementation(() => {
      throw new DOMException('Storage disabled', 'SecurityError');
    });
    vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => {
      throw new DOMException('Storage disabled', 'SecurityError');
    });
    expect(readThemeMode()).toBe('light');
    expect(() => saveThemeMode('auto')).not.toThrow();
  });

  it('浏览器没有媒体查询接口时应用浅色且可以安全取消订阅', () => {
    window.matchMedia = undefined as unknown as typeof window.matchMedia;
    const listener = vi.fn();
    expect(getSystemTheme()).toBe('light');
    expect(resolveTheme('auto')).toBe('light');
    const unsubscribe = subscribeSystemTheme(listener);
    expect(listener).toHaveBeenCalledExactlyOnceWith('light');
    expect(unsubscribe).not.toThrow();
  });

  it('兼容旧版 Safari，并取消同一个媒体查询监听', () => {
    let listener: ((event: MediaQueryListEvent) => void) | undefined;
    const query = {
      matches: true,
      addListener: vi.fn((callback: typeof listener) => {
        listener = callback;
      }),
      removeListener: vi.fn(),
    };
    window.matchMedia = vi.fn(() => query as unknown as MediaQueryList);
    const receive = vi.fn();
    const unsubscribe = subscribeSystemTheme(receive);
    expect(receive).toHaveBeenLastCalledWith('realDark');
    listener?.({ matches: false } as MediaQueryListEvent);
    expect(receive).toHaveBeenLastCalledWith('light');
    unsubscribe();
    expect(query.removeListener).toHaveBeenCalledExactlyOnceWith(listener);
  });
});
