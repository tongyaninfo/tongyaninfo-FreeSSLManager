import path from 'node:path';
import { mkdir, chmod, lstat, realpath } from 'node:fs/promises';
import type { DesktopPaths } from '../Models/DesktopModels';

/** 应用标识保持固定，覆盖升级和产品显示名称变化不会切换业务数据目录。 */
export const applicationId = 'com.tongyaninfo.free-ssl-manager';
export const applicationName = 'SSL 证书管理';
export const desktopTokenHeader = 'X-SslManager-Desktop-Token';

export function makeDesktopPaths(appData: string): DesktopPaths {
  const root = path.join(appData, 'tongyaninfo', 'FreeSslManager');
  return { root, business: path.join(root, 'business'), logs: path.join(root, 'logs'),
    backups: path.join(root, 'backups'), settings: path.join(root, 'settings.json') };
}

/** 新建用户目录仅允许当前用户访问；既有符号链接不作为数据根使用。 */
export async function ensurePrivateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('数据位置必须是普通目录。');
  if (process.platform !== 'win32') await chmod(directory, 0o700);
}

export async function ensureDesktopPaths(paths: DesktopPaths): Promise<void> {
  for (const directory of [paths.root, paths.business, paths.logs, paths.backups]) await ensurePrivateDirectory(directory);
}

/** 就绪消息必须来自本次子进程，不能接受其他本机服务冒充健康状态。 */
export function validateBackendOrigin(origin: unknown): string {
  if (typeof origin !== 'string') throw new Error('本地服务地址无效。');
  const url = new URL(origin);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || Number(url.port) < 1 ||
      url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new Error('本地服务必须使用独立回环地址。');
  }
  return url.origin;
}

/** 解包只接受业务数据库和同级密钥文件，拒绝路径穿越、绝对路径和额外内容。 */
export function isBackupPath(name: string): boolean {
  return name === 'data/ssl-manager.db' || name === 'desktop-storage.json' || name === 'snapshot.json' || /^keys\/[A-Za-z0-9._-]+\.xml$/.test(name);
}

export async function assertPlainFile(file: string, root: string): Promise<void> {
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error('备份内容包含非普通文件。');
  const actual = await realpath(file); const base = await realpath(root);
  if (!actual.startsWith(base + path.sep)) throw new Error('备份文件超出快照目录。');
}
