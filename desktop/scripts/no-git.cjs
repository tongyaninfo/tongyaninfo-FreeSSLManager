'use strict';
// 此保护在构建工具入口之前加载，拒绝调用 Git；不是执行 Git 后再忽略其结果。
const childProcess = require('node:child_process');
const path = require('node:path');
function rejectGit(file, args) {
  const executable = path.basename(String(file)).toLowerCase();
  const text = [file, ...(Array.isArray(args) ? args : [])].join(' ');
  if (/^git(?:\.exe)?$/.test(executable) || /(?:^|[\s;&|"'])git(?:\.exe)?(?:\s|$)/i.test(text) || /[\\/]git(?:\.exe)?(?:\s|$)/i.test(text)) {
    const error = new Error('此桌面构建禁止执行 Git；版本及应用元数据必须显式提供。');
    error.code = 'DESKTOP_GIT_FORBIDDEN';
    throw error;
  }
}
for (const method of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync']) {
  const original = childProcess[method];
  childProcess[method] = function guarded(file, ...args) {
    rejectGit(file, args[0]);
    return Reflect.apply(original, this, [file, ...args]);
  };
}
module.exports = { rejectGit };
