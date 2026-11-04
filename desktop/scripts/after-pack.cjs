'use strict';
const path = require('node:path');
module.exports = async function verifyPackagedResources(context) {
  const { targets, verifyPreparedBackend } = await import('./build-utils.mjs');
  const rid = process.env.DESKTOP_TARGET_RID;
  const target = targets[rid];
  if (!target) throw new Error('打包缺少明确的 .NET RID，拒绝生成安装包。');
  const arch = typeof context.arch === 'number' ? ({ 1: 'x64', 3: 'arm64' })[context.arch] : context.arch;
  if (arch !== target.arch || context.electronPlatformName !== target.platform) throw new Error('Electron 与 .NET 发布架构不一致。');
  const resources = target.platform === 'darwin'
    ? path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`, 'Contents', 'Resources')
    : path.join(context.appOutDir, 'resources');
  await verifyPreparedBackend(path.join(resources, 'backend'), rid, { verifyHashes: true });
};
