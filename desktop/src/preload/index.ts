import { contextBridge, ipcRenderer } from 'electron';
import type { DesktopBridge, DesktopPreferences } from '../Models/DesktopModels';

/** 仅暴露明确的原生动作，不把 ipcRenderer、文件系统或访问令牌交给页面。 */
const desktop: DesktopBridge = Object.freeze({
  openSettings: () => ipcRenderer.invoke('desktop:open-settings'),
  getState: () => ipcRenderer.invoke('desktop:get-state'),
  setPreferences: (value: DesktopPreferences) => ipcRenderer.invoke('desktop:set-preferences', value),
  exportBackup: (password: string) => ipcRenderer.invoke('desktop:export-backup', password),
  importBackup: (password: string) => ipcRenderer.invoke('desktop:import-backup', password),
  openLogs: () => ipcRenderer.invoke('desktop:open-logs'),
  openData: () => ipcRenderer.invoke('desktop:open-data'),
});
contextBridge.exposeInMainWorld('sslDesktop', desktop);
