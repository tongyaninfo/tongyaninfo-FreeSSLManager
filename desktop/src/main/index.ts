import { app, BrowserWindow, dialog, ipcMain, Menu, nativeImage, powerMonitor, session, shell, Tray, type IpcMainInvokeEvent } from 'electron';
import { access, appendFile, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { applicationId, applicationName, ensureDesktopPaths, ensurePrivateDirectory, makeDesktopPaths } from '../Common/Paths';
import { hasVisibleTray } from '../Common/TrayVisibility';
import { BackendProcessService } from '../Service/impl/BackendProcessService';
import { BackupService, restoreStagedDirectory } from '../Service/impl/BackupService';
import { PreferencesService, validatePreferences } from '../Service/impl/PreferencesService';
import { setLinuxAutoStart } from '../Service/impl/AutoStartService';
import { failure, success, type DesktopPaths, type DesktopState } from '../Models/DesktopModels';

app.setName(applicationName); app.setAppUserModelId(applicationId);
const defaultPaths = makeDesktopPaths(app.getPath('appData'));
const override = process.env.SSL_DESKTOP_USER_DATA_DIR;
if (override && (!path.isAbsolute(override) || path.parse(override).root === path.resolve(override))) throw new Error('桌面测试数据根必须是独立绝对目录。');
const root = override ? path.resolve(override) : defaultPaths.root;
const paths: DesktopPaths = { root, business: path.join(root, 'business'), logs: path.join(root, 'logs'),
  backups: path.join(root, 'backups'), settings: path.join(root, 'settings.json') };
app.setPath('userData', root);

let mainWindow: BrowserWindow | undefined; let settingsWindow: BrowserWindow | undefined;
let tray: Tray | undefined; let backend: BackendProcessService; let preferences: PreferencesService;
let quitting = false; let quittingPromise: Promise<void> | undefined; let operation: Promise<unknown> | undefined;
const resources = path.join(app.getAppPath(), 'resources');
const preload = path.join(__dirname, '..', 'preload', 'index.js');
const loadingFile = path.join(resources, 'loading.html'); const settingsFile = path.join(resources, 'desktop-settings.html');
const loadingUrl = pathToFileURL(loadingFile).href; const settingsUrl = pathToFileURL(settingsFile).href;

function isOwnFrame(event: IpcMainInvokeEvent, settingsOnly = false): boolean {
  if (!event.senderFrame || event.senderFrame !== event.sender.mainFrame) return false;
  if (settingsWindow && event.sender === settingsWindow.webContents && event.senderFrame.url === settingsUrl) return true;
  if (settingsOnly || !mainWindow || event.sender !== mainWindow.webContents) return false;
  try { return event.senderFrame.url === loadingUrl || new URL(event.senderFrame.url).origin === backend.origin; } catch { return false; }
}

function state(): DesktopState {
  return { version: app.getVersion(), preferences: preferences.value, backend: backend.status, dataDirectory: paths.business };
}

/** 页面只能在本实例内导航；外部 HTTPS 链接通过系统浏览器打开。 */
function secureWindow(window: BrowserWindow, settings = false): void {
  window.webContents.setWindowOpenHandler(({ url }) => {
    try { const parsed = new URL(url); if (parsed.protocol === 'https:' && !parsed.username && !parsed.password) void shell.openExternal(parsed.href); } catch { /* 拒绝无效链接。 */ }
    return { action: 'deny' };
  });
  window.webContents.on('will-navigate', (event, url) => {
    let allowed = url === (settings ? settingsUrl : loadingUrl);
    try { allowed ||= !settings && new URL(url).origin === backend.origin; } catch { /* 无效导航不放行。 */ }
    if (!allowed) event.preventDefault();
  });
  window.webContents.on('will-attach-webview', event => event.preventDefault());
}

function showMain(): void {
  if (!mainWindow || mainWindow.isDestroyed()) createMainWindow();
  if (mainWindow!.isMinimized()) mainWindow!.restore(); mainWindow!.show(); mainWindow!.focus();
}

function createMainWindow(): void {
  const isolated = session.fromPartition('persist:ssl-manager-desktop');
  mainWindow = new BrowserWindow({ title: applicationName, width: 1380, height: 900, minWidth: 1024, minHeight: 680,
    show: false, webPreferences: { preload, session: isolated, nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true } });
  secureWindow(mainWindow);
  mainWindow.on('close', event => {
    if (quitting) return;
    event.preventDefault();
    if (!preferences.value.closeToTray) { void quit(); return; }
    if (hasVisibleTray(tray, process.platform)) mainWindow!.hide();
    else mainWindow!.minimize();
  });
  mainWindow.webContents.on('render-process-gone', () => {
    if (!quitting && mainWindow && !mainWindow.isDestroyed()) void mainWindow.loadURL(backend.origin ?? loadingUrl);
  });
  void mainWindow.loadURL(backend.origin ?? loadingUrl).catch(() => { /* 后端 ready 事件或用户重试会重新载入。 */ });
  mainWindow.once('ready-to-show', () => {
    const openedAtLogin = process.platform === 'darwin' && app.getLoginItemSettings().wasOpenedAtLogin;
    const hiddenRequested = process.argv.includes('--hidden') || openedAtLogin;
    if (!hiddenRequested) showMain();
    else if (!hasVisibleTray(tray, process.platform)) { showMain(); mainWindow!.minimize(); }
  });
}

function openSettings(): void {
  if (settingsWindow && !settingsWindow.isDestroyed()) { settingsWindow.show(); settingsWindow.focus(); return; }
  settingsWindow = new BrowserWindow({ title: '桌面设置', width: 760, height: 760, minWidth: 650, minHeight: 650,
    autoHideMenuBar: true, webPreferences: { preload, partition: 'ssl-manager-settings', nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true } });
  secureWindow(settingsWindow, true); settingsWindow.on('closed', () => { settingsWindow = undefined; });
  void settingsWindow.loadFile(settingsFile);
}

function updateMenus(): void {
  const template: Electron.MenuItemConstructorOptions[] = [
    { label: '打开主界面', click: showMain }, { label: backend.status.message, enabled: false },
    { type: 'separator' }, { label: '桌面设置与备份', click: openSettings },
    { label: '打开日志目录', click: () => { void shell.openPath(paths.logs); } },
    { label: '重试本地服务', enabled: !operation && !quitting && backend.status.phase !== 'ready', click: () => { void backend.start().catch(showError); } },
    { type: 'separator' }, { label: '完全退出', click: () => { void quit(); } },
  ];
  if (tray && !tray.isDestroyed()) tray.setContextMenu(Menu.buildFromTemplate(template));
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: applicationName, submenu: [{ label: '桌面设置与备份', click: openSettings }, { label: '关于', click: () => { void dialog.showMessageBox({ type: 'info', title: '关于', message: applicationName, detail: `版本 ${app.getVersion()}\n本地 .NET 10 + SQLite，业务数据保存在本机。` }); } },
      { type: 'separator' }, { label: '完全退出', accelerator: process.platform === 'darwin' ? 'Command+Q' : 'Control+Shift+Q', click: () => { void quit(); } }] },
    { label: '编辑', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    { label: '窗口', submenu: [{ label: '打开主界面', click: showMain }, { role: 'minimize' }, { role: 'togglefullscreen' }] },
  ]));
}

async function showError(error: unknown): Promise<void> {
  const message = error instanceof Error ? error.message : '桌面操作未完成。';
  await dialog.showMessageBox({ type: 'error', title: applicationName, message, detail: '原数据和任务记录会保留。可从桌面设置打开日志目录。' });
}

async function quit(): Promise<void> {
  if (quittingPromise) return quittingPromise;
  quitting = true; updateMenus();
  quittingPromise = (async () => {
    try {
      if (operation) await operation.catch(() => {});
      await backend.stop(); tray?.destroy(); app.quit();
    } catch (error) { quitting = false; quittingPromise = undefined; showMain(); await showError(error); }
  })();
  return quittingPromise;
}

async function launchAtLogin(enabled: boolean): Promise<void> {
  if (process.platform === 'linux') {
    const config = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
    await setLinuxAutoStart(config, process.env.APPIMAGE || app.getPath('exe'), enabled);
  } else app.setLoginItemSettings({ openAtLogin: enabled, args: ['--hidden'] });
}

/** 修改类 IPC 仅接受设置窗口顶层页面，密码只在本次操作内使用。 */
function registerIpc(): void {
  ipcMain.handle('desktop:open-settings', event => {
    if (!isOwnFrame(event)) return failure('FORBIDDEN', '此页面不能调用原生功能。'); openSettings(); return success();
  });
  ipcMain.handle('desktop:get-state', event => isOwnFrame(event) ? success(state()) : failure('FORBIDDEN', '此页面不能读取桌面状态。'));
  ipcMain.handle('desktop:set-preferences', async (event, value: unknown) => {
    if (!isOwnFrame(event, true)) return failure('FORBIDDEN', '此页面不能修改桌面设置。');
    if (operation || quitting) return failure('BUSY', '请等待当前操作完成。');
    const previous = preferences.value;
    try {
      const next = validatePreferences(value);
      if (next.launchAtLogin !== previous.launchAtLogin) await launchAtLogin(next.launchAtLogin);
      try { await preferences.save(next); }
      catch (error) { if (next.launchAtLogin !== previous.launchAtLogin) await launchAtLogin(previous.launchAtLogin); throw error; }
      return success(state(), '桌面设置已保存。');
    } catch (error) { return failure('PREFERENCES_FAILED', error instanceof Error ? error.message : '桌面设置未保存。'); }
  });
  ipcMain.handle('desktop:open-logs', async event => { if (!isOwnFrame(event, true)) return failure('FORBIDDEN', '此页面不能打开本地目录。');
    const error = await shell.openPath(paths.logs); return error ? failure('OPEN_FAILED', '无法打开日志目录。') : success(); });
  ipcMain.handle('desktop:open-data', async event => { if (!isOwnFrame(event, true)) return failure('FORBIDDEN', '此页面不能打开本地目录。');
    const error = await shell.openPath(paths.business); return error ? failure('OPEN_FAILED', '无法打开数据目录。') : success(); });
  const backup = new BackupService(app.getVersion());
  const run = async (event: IpcMainInvokeEvent, password: unknown, action: () => Promise<unknown>) => {
    if (!isOwnFrame(event, true)) return failure('FORBIDDEN', '此页面不能管理备份。');
    if (operation || quitting) return failure('BUSY', '请等待当前备份、恢复或退出操作完成。');
    if (typeof password !== 'string' || password.length < 8 || password.length > 1024) return failure('VALIDATION', '请输入至少 8 个字符的备份密码。');
    operation = action(); updateMenus();
    try { return success(await operation, '操作已完成。'); }
    catch (error) { return failure('BACKUP_FAILED', error instanceof Error ? error.message : '备份操作未完成。'); }
    finally { operation = undefined; updateMenus(); }
  };
  ipcMain.handle('desktop:export-backup', (event, password: unknown) => run(event, password, async () => {
    const selected = await dialog.showSaveDialog(settingsWindow!, { title: '导出加密备份', defaultPath: `ssl-manager-${new Date().toISOString().slice(0, 10)}-${Date.now()}.sslbak`, filters: [{ name: 'SSL 管理加密备份', extensions: ['sslbak'] }] });
    if (selected.canceled || !selected.filePath) return { canceled: true };
    const snapshot = path.join(paths.backups, 'snapshot-' + randomUUID()); await ensurePrivateDirectory(snapshot);
    await backend.snapshot(snapshot); await backup.export(snapshot, selected.filePath, password as string);
    return { path: selected.filePath };
  }));
  ipcMain.handle('desktop:import-backup', (event, password: unknown) => run(event, password, async () => {
    const selected = await dialog.showOpenDialog(settingsWindow!, { title: '导入加密备份', properties: ['openFile'], filters: [{ name: 'SSL 管理加密备份', extensions: ['sslbak'] }] });
    if (selected.canceled || !selected.filePaths[0]) return { canceled: true };
    const manifest = await backup.read(selected.filePaths[0], password as string);
    const confirmed = await dialog.showMessageBox(settingsWindow!, { type: 'warning', title: '确认恢复备份', buttons: ['取消', '导入并保留原数据'], defaultId: 0, cancelId: 0,
      message: '使用此备份替换本机业务数据？', detail: `备份：${path.basename(selected.filePaths[0])}\n生成时间：${manifest.createdAtUtc}\n原数据将保留在独立目录；导入后已启用计划会恢复执行。\n跨电脑恢复前，请确保来源电脑上的原客户端已退出。备份是历史快照，生成后发生的云端变更需要核对；请勿在两台电脑上使用同一备份同时启用计划。` });
    if (confirmed.response !== 1) return { canceled: true };
    if (backend.status.phase === 'ready') {
      const snapshot = path.join(paths.backups, 'before-import-' + randomUUID()); await ensurePrivateDirectory(snapshot); await backend.snapshot(snapshot);
    }
    const staged = await backup.stage(manifest, paths.root);
    return restoreStagedDirectory(paths.business, staged, backend);
  }));
}

async function backendDirectory(): Promise<string> {
  if (process.env.SSL_DESKTOP_BACKEND_DIR) {
    if (!path.isAbsolute(process.env.SSL_DESKTOP_BACKEND_DIR)) throw new Error('后端目录必须是绝对路径。');
    return process.env.SSL_DESKTOP_BACKEND_DIR;
  }
  if (app.isPackaged) return path.join(process.resourcesPath, 'backend');
  const platform = process.platform === 'win32' ? 'win' : process.platform === 'darwin' ? 'osx' : 'linux';
  const pointer = JSON.parse(await readFile(path.join(app.getAppPath(), '.artifacts', `current-${platform}-${process.arch}.json`), 'utf8')) as { backendDirectory?: string };
  if (!pointer.backendDirectory || !path.isAbsolute(pointer.backendDirectory)) throw new Error('请先构建当前平台的内置后端。');
  return pointer.backendDirectory;
}

async function bootstrap(): Promise<void> {
  await ensureDesktopPaths(paths);
  if (!app.requestSingleInstanceLock()) { app.quit(); return; }
  await app.whenReady();
  preferences = new PreferencesService(paths.settings); await preferences.load();
  const directory = await backendDirectory();
  const executable = path.join(directory, process.platform === 'win32' ? 'SslManager.Api.exe' : 'SslManager.Api');
  await access(executable, process.platform === 'win32' ? constants.F_OK : constants.X_OK);
  backend = new BackendProcessService({ executable, dataDirectory: paths.business, logsFile: path.join(paths.logs, 'backend.log') });
  const isolated = session.fromPartition('persist:ssl-manager-desktop');
  isolated.webRequest.onBeforeSendHeaders((details, callback) => callback({ requestHeaders: backend.authorize(
    mainWindow && !mainWindow.isDestroyed() && details.webContentsId === mainWindow.webContents.id ? details.url : 'about:blank', details.requestHeaders) }));
  isolated.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  session.fromPartition('ssl-manager-settings').setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  isolated.on('will-download', (event, item, contents) => {
    if (!mainWindow || contents !== mainWindow.webContents) { event.preventDefault(); return; }
    item.setSaveDialogOptions({ title: '保存证书文件', defaultPath: path.join(app.getPath('downloads'), path.basename(item.getFilename())) });
  });
  try {
    const icon = nativeImage.createFromPath(path.join(resources, process.platform === 'darwin' ? 'tray.png' : 'icon.png')); icon.setTemplateImage(process.platform === 'darwin');
    if (!icon.isEmpty()) { tray = new Tray(icon.resize({ width: 20, height: 20 })); tray.setToolTip(applicationName); tray.on('click', showMain); }
  } catch { tray = undefined; }
  registerIpc(); createMainWindow(); updateMenus();
  backend.on('status', updateMenus);
  backend.on('ready', (origin: string) => { if (mainWindow && !mainWindow.isDestroyed()) void mainWindow.loadURL(origin).catch(() => {}); });
  app.on('second-instance', showMain); app.on('activate', showMain);
  app.on('window-all-closed', () => { /* 后台任务由主进程继续管理，完全退出使用明确菜单。 */ });
  app.on('before-quit', event => { if (!quitting || backend.status.phase !== 'stopped') { event.preventDefault(); void quit(); } });
  powerMonitor.on('resume', () => { if (!quitting && !operation) void backend.start().catch(showError); });
  if (process.env.SSL_DESKTOP_TEST_MODE === '1') {
    (globalThis as unknown as { __sslManagerDesktop?: unknown }).__sslManagerDesktop = { backend, paths, openSettings, quit };
  }
  void backend.start().catch(async error => { await appendFile(path.join(paths.logs, 'desktop.log'), `[${new Date().toISOString()}] 本地服务启动未完成。\n`, { mode: 0o600 }); if (backend.status.phase === 'failed') await showError(error); });
}

void bootstrap().catch(async error => {
  try { await app.whenReady(); await showError(error); } finally { app.quit(); }
});
