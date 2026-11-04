/** 桌面 IPC 和本地控制命令沿用现有统一返回结构。 */
export interface DesktopResult<T = unknown> {
  success: boolean;
  code: string;
  message: string;
  data?: T;
}

export interface DesktopPreferences {
  closeToTray: boolean;
  launchAtLogin: boolean;
}

export interface BackendStatus {
  phase: 'stopped' | 'starting' | 'ready' | 'restarting' | 'stopping' | 'failed';
  message: string;
  code?: string;
}

export interface DesktopState {
  version: string;
  preferences: DesktopPreferences;
  backend: BackendStatus;
  dataDirectory: string;
}

export interface SnapshotResult {
  snapshotDirectory: string;
  databasePath: string;
  keysDirectory: string;
}

export interface DesktopPaths {
  root: string;
  business: string;
  logs: string;
  backups: string;
  settings: string;
}

/** 只暴露需要的原生操作，不提供任意文件、进程或 IPC 通道访问。 */
export interface DesktopBridge {
  openSettings(): Promise<DesktopResult>;
  getState(): Promise<DesktopResult<DesktopState>>;
  setPreferences(value: DesktopPreferences): Promise<DesktopResult<DesktopState>>;
  exportBackup(password: string): Promise<DesktopResult<{ path: string }>>;
  importBackup(password: string): Promise<DesktopResult>;
  openLogs(): Promise<DesktopResult>;
  openData(): Promise<DesktopResult>;
}

export const success = <T>(data?: T, message = ''): DesktopResult<T> => ({ success: true, code: 'OK', message, data });
export const failure = (code: string, message: string): DesktopResult<never> => ({ success: false, code, message });
