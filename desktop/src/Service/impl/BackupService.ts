import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, open, readFile, readdir, rename } from 'node:fs/promises';
import path from 'node:path';
import { assertPlainFile, ensurePrivateDirectory, isBackupPath } from '../../Common/Paths';
import { decryptManifest, encryptManifest, maxArchiveBytes, maxDatabaseBytes, validateManifest } from '../../Common/BackupArchive';
import type { BackupManifest, IBackupService } from '../IBackupService';

/** 业务数据库与密钥整体加密备份；恢复只写入新目录，既有数据通过重命名保留。 */
export class BackupService implements IBackupService {
  constructor(private readonly applicationVersion: string) {}

  async export(snapshotDirectory: string, destination: string, password: string): Promise<void> {
    const files: BackupManifest['files'] = [];
    const names = ['data/ssl-manager.db', 'desktop-storage.json', 'snapshot.json', ...(await readdir(path.join(snapshotDirectory, 'keys'))).map(name => 'keys/' + name)];
    for (const name of names) {
      if (!isBackupPath(name)) throw new Error('快照密钥目录包含不支持的内容，未导出。');
      const source = path.join(snapshotDirectory, ...name.split('/')); await assertPlainFile(source, snapshotDirectory);
      const info = await lstat(source);
      if (info.size > (name === 'data/ssl-manager.db' ? maxDatabaseBytes : 2 * 1024 * 1024)) throw new Error('备份文件超出支持大小。');
      const content = await readFile(source);
      files.push({ path: name, length: content.length, sha256: createHash('sha256').update(content).digest('hex'), content: content.toString('base64') });
    }
    const bytes = await encryptManifest({ version: 1, applicationVersion: this.applicationVersion, createdAtUtc: new Date().toISOString(), files }, password);
    // 不覆盖已有归档，避免误损用户唯一备份；原生保存对话框可另选文件名。
    const file = await open(destination, 'wx', 0o600);
    try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
  }

  async read(source: string, password: string): Promise<BackupManifest> {
    const info = await lstat(source);
    if (!info.isFile() || info.isSymbolicLink() || info.size > maxArchiveBytes) throw new Error('请选择支持大小以内的普通备份文件。');
    return decryptManifest(await readFile(source), password);
  }

  async stage(manifest: BackupManifest, businessParent: string): Promise<string> {
    validateManifest(manifest);
    const staging = path.join(businessParent, 'business-restore-' + randomUUID()); await ensurePrivateDirectory(staging);
    for (const file of manifest.files) {
      const destination = path.join(staging, ...file.path.split('/'));
      await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
      const handle = await open(destination, 'wx', 0o600);
      try { await handle.writeFile(Buffer.from(file.content, 'base64')); await handle.sync(); } finally { await handle.close(); }
    }
    return staging;
  }
}

export interface RestoreLifecycle { stop(): Promise<void>; start(): Promise<void> }

/** 后端确认退出后才切换目录；新数据无法启动时保留失败现场并恢复原目录。 */
export async function restoreStagedDirectory(business: string, staged: string, lifecycle: RestoreLifecycle,
  move: (source: string, destination: string) => Promise<void> = rename): Promise<{ previousDirectory: string }> {
  const parent = path.dirname(business);
  if (path.dirname(staged) !== parent || !path.basename(staged).startsWith('business-restore-')) throw new Error('恢复暂存目录不属于本应用。');
  for (const directory of [business, staged]) {
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('业务或恢复位置不是普通目录。');
  }
  await lifecycle.stop();
  const previousDirectory = path.join(parent, 'business-before-restore-' + new Date().toISOString().replace(/[:.]/g, '-') + '-' + randomUUID());
  try { await move(business, previousDirectory); }
  catch { await lifecycle.start(); throw new Error('无法切换业务目录，原数据保持不变且原服务已重新启动。'); }
  try { await move(staged, business); }
  catch (error) { await move(previousDirectory, business); await lifecycle.start(); throw error; }
  try { await lifecycle.start(); }
  catch {
    // 确认失败后端退出后再回切，不能在进程仍持有 SQLite 时覆盖数据。
    await lifecycle.stop();
    await move(business, path.join(parent, 'business-failed-restore-' + randomUUID()));
    await move(previousDirectory, business); await lifecycle.start();
    throw new Error('导入数据未通过本地服务校验，已保留失败现场并恢复原数据。');
  }
  return { previousDirectory };
}
