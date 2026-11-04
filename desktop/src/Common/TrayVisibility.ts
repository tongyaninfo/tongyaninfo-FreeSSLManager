export interface TrayPresence {
  isDestroyed(): boolean;
  getBounds(): { width: number; height: number };
}

/** Linux 有些桌面会创建 Tray 对象却没有可见宿主；启动和关闭必须使用相同判断。 */
export function hasVisibleTray(tray: TrayPresence | undefined, platform: string): boolean {
  if (!tray || tray.isDestroyed()) return false;
  if (platform !== 'linux') return true;
  try { const bounds = tray.getBounds(); return bounds.width > 0 && bounds.height > 0; }
  catch { return false; }
}
