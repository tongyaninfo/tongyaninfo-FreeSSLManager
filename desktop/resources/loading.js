'use strict';
// 启动页面只读取脱敏状态；实际服务地址与通信凭证不进入页面。
document.getElementById('settings').addEventListener('click', () => window.sslDesktop.openSettings());
async function refresh() {
  try { const result = await window.sslDesktop.getState(); if (result.success) document.getElementById('status').textContent = result.data.backend.message; }
  catch { document.getElementById('status').textContent = '本地服务暂未就绪，请从桌面设置查看日志。'; }
}
refresh(); setInterval(refresh, 1000);
