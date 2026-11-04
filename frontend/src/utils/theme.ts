/** 用户选择的模式与 ProLayout 实际应用的深浅色分开保存。 */
export type ThemeMode = 'auto' | 'light' | 'realDark';
export type ResolvedTheme = Exclude<ThemeMode, 'auto'>;

const THEME_MODE_KEY = 'ssl-manager:theme-mode';
const SYSTEM_DARK_QUERY = '(prefers-color-scheme: dark)';

export function isThemeMode(value: unknown): value is ThemeMode {
  return value === 'auto' || value === 'light' || value === 'realDark';
}

/** 仅在当前浏览器保存模式；禁用本地存储时仍可正常切换。 */
export function readThemeMode(): ThemeMode {
  try {
    const value = window.localStorage.getItem(THEME_MODE_KEY);
    return isThemeMode(value) ? value : 'light';
  } catch {
    return 'light';
  }
}

export function saveThemeMode(mode: ThemeMode): void {
  try {
    window.localStorage.setItem(THEME_MODE_KEY, mode);
  } catch {
    // 隐私模式或存储配额不足时保留当前会话中的选择。
  }
}

export function getSystemTheme(): ResolvedTheme {
  if (
    typeof window === 'undefined' ||
    typeof window.matchMedia !== 'function'
  ) {
    return 'light';
  }
  return window.matchMedia(SYSTEM_DARK_QUERY).matches ? 'realDark' : 'light';
}

/** auto 只表示用户意图，传给布局与业务页面前统一解析。 */
export function resolveTheme(mode: ThemeMode): ResolvedTheme {
  return mode === 'auto' ? getSystemTheme() : mode;
}

/** 订阅时立即同步，并兼容旧版 Safari 的媒体查询监听接口。 */
export function subscribeSystemTheme(listener: (theme: ResolvedTheme) => void) {
  if (
    typeof window === 'undefined' ||
    typeof window.matchMedia !== 'function'
  ) {
    listener('light');
    return () => undefined;
  }
  const query = window.matchMedia(SYSTEM_DARK_QUERY);
  const onChange = (event: MediaQueryListEvent) => {
    listener(event.matches ? 'realDark' : 'light');
  };
  listener(query.matches ? 'realDark' : 'light');
  if (typeof query.addEventListener === 'function') {
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }
  query.addListener(onChange);
  return () => query.removeListener(onChange);
}
