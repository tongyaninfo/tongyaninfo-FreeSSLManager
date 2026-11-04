import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  history: { location: { pathname: '/domains' }, replace: vi.fn() },
  setupStatus: vi.fn(),
  current: vi.fn(),
}));
vi.mock('@umijs/max', () => ({
  history: mocks.history,
  Link: ({ children }: { children: unknown }) => children,
}));
vi.mock('./services/ssl-manager/api', () => ({
  authApi: { setupStatus: mocks.setupStatus, current: mocks.current },
  resetCsrfToken: vi.fn(),
}));
vi.mock('./requestErrorConfig', () => ({ errorConfig: {} }));

describe('真实会话初始化', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    mocks.history.location.pathname = '/domains';
    mocks.setupStatus.mockResolvedValue({
      success: true,
      data: { needsSetup: false },
    });
    mocks.current.mockResolvedValue({
      success: false,
      code: 'UNAUTHORIZED',
      message: '请登录',
    });
  });
  it('首次启动只能进入管理员初始化', async () => {
    mocks.setupStatus.mockResolvedValue({
      success: true,
      data: { needsSetup: true },
    });
    const { getInitialState } = await import('./app');
    const state = await getInitialState();
    expect(mocks.history.replace).toHaveBeenCalledWith('/user/setup');
    expect(mocks.current).not.toHaveBeenCalled();
    expect(state.needsSetup).toBe(true);
  });
  it('会话失效返回登录页', async () => {
    const { getInitialState } = await import('./app');
    const state = await getInitialState();
    expect(mocks.history.replace).toHaveBeenCalledWith('/user/login');
    expect(state.currentUser).toBeUndefined();
  });
  it('已登录读取后端角色而非演示权限', async () => {
    const user = { id: '2', username: 'readonly', role: 'viewer' };
    mocks.current.mockResolvedValue({ success: true, data: user });
    const { getInitialState } = await import('./app');
    const state = await getInitialState();
    expect(state.currentUser).toEqual(user);
    expect(mocks.history.replace).not.toHaveBeenCalled();
  });
  it('登录页会话失败不重复重定向', async () => {
    mocks.history.location.pathname = '/user/login';
    const { getInitialState } = await import('./app');
    await getInitialState();
    expect(mocks.history.replace).not.toHaveBeenCalled();
  });
  it('刷新恢复自动模式，并在初始化时应用当前系统深色', async () => {
    const matchMedia = window.matchMedia;
    localStorage.setItem('ssl-manager:theme-mode', 'auto');
    window.matchMedia = vi.fn(() => ({ matches: true }) as MediaQueryList);
    try {
      const { getInitialState } = await import('./app');
      const state = await getInitialState();
      expect(state.themeMode).toBe('auto');
      expect(state.settings?.navTheme).toBe('realDark');
    } finally {
      window.matchMedia = matchMedia;
    }
  });
});
