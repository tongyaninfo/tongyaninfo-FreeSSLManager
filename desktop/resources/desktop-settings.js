'use strict';
// 原生桥仅接受此设置窗口顶层页面，页面不具有文件系统或进程权限。
const bridge = window.sslDesktop;
const element = id => document.getElementById(id);
let busy = false;
function show(result) {
  element('message').textContent = result.message || (result.data?.canceled ? '已取消。' : result.success ? '操作已完成。' : '操作未完成。');
  element('message').className = result.success ? 'success' : 'error';
}
function apply(state) {
  element('version').textContent = `SSL 证书管理 · ${state.version}`;
  element('status').textContent = state.backend.message;
  element('dataDirectory').textContent = state.dataDirectory;
  element('closeToTray').checked = state.preferences.closeToTray;
  element('launchAtLogin').checked = state.preferences.launchAtLogin;
}
async function action(callback, clearPassword = false) {
  if (busy) return;
  busy = true;
  for (const button of document.querySelectorAll('button')) button.disabled = true;
  element('message').textContent = '正在处理，请稍候…';
  try { const result = await callback(); show(result); if (result.success && result.data?.preferences) apply(result.data); }
  catch { show({ success: false, message: '原生操作未完成，请查看日志。' }); }
  finally { if (clearPassword) element('password').value = ''; busy = false; for (const button of document.querySelectorAll('button')) button.disabled = false; }
}
element('save').addEventListener('click', () => action(() => bridge.setPreferences({ closeToTray: element('closeToTray').checked, launchAtLogin: element('launchAtLogin').checked })));
element('export').addEventListener('click', () => action(() => bridge.exportBackup(element('password').value), true));
element('import').addEventListener('click', () => action(() => bridge.importBackup(element('password').value), true));
element('openData').addEventListener('click', () => action(() => bridge.openData()));
element('openLogs').addEventListener('click', () => action(() => bridge.openLogs()));
bridge.getState().then(result => result.success ? apply(result.data) : show(result));
setInterval(() => { if (!busy) bridge.getState().then(result => { if (result.success) element('status').textContent = result.data.backend.message; }).catch(() => {}); }, 2000);
