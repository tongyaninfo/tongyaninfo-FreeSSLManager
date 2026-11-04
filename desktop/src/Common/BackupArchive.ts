import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt } from 'node:crypto';
import { gzip, gunzip } from 'node:zlib';
import { promisify } from 'node:util';
import { isBackupPath } from './Paths';
import type { BackupManifest } from '../Service/IBackupService';

const zip = promisify(gzip); const unzip = promisify(gunzip);
const archiveName = 'SslManager.Desktop.Backup';
const aad = Buffer.from(archiveName + ':1', 'utf8');
export const maxArchiveBytes = 512 * 1024 * 1024;
export const maxDatabaseBytes = 256 * 1024 * 1024;

function passwordValid(password: string): void {
  if (typeof password !== 'string' || password.length < 8 || password.length > 1024) throw new Error('备份密码应为 8 至 1024 个字符。');
}
async function keyFor(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => scrypt(password, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 },
    (error, key) => error ? reject(error) : resolve(key)));
}
function fromBase64(value: unknown, limit: number): Buffer {
  if (typeof value !== 'string' || value.length > Math.ceil(limit / 3) * 4 + 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error('备份编码无效。');
  const result = Buffer.from(value, 'base64');
  if (result.length > limit || result.toString('base64') !== value) throw new Error('备份编码无效。');
  return result;
}

/** 格式固定、文件白名单与逐文件摘要先验证，再允许写入任何恢复目录。 */
export function validateManifest(value: unknown): BackupManifest {
  if (!value || typeof value !== 'object') throw new Error('备份清单无效。');
  const manifest = value as BackupManifest;
  if (manifest.version !== 1 || typeof manifest.createdAtUtc !== 'string' || !Number.isFinite(Date.parse(manifest.createdAtUtc)) ||
      typeof manifest.applicationVersion !== 'string' || manifest.applicationVersion.length > 100 ||
      !Array.isArray(manifest.files) || manifest.files.length < 2 || manifest.files.length > 2000) throw new Error('备份清单版本或内容无效。');
  const names = new Set<string>(); let size = 0;
  for (const file of manifest.files) {
    if (!file || typeof file.path !== 'string' || !isBackupPath(file.path) || names.has(file.path) ||
        !Number.isSafeInteger(file.length) || file.length < 1 || typeof file.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256)) throw new Error('备份包含不允许、重复或损坏的文件。');
    const content = fromBase64(file.content, file.path === 'data/ssl-manager.db' ? maxDatabaseBytes : 2 * 1024 * 1024);
    if (content.length !== file.length || createHash('sha256').update(content).digest('hex') !== file.sha256) throw new Error('备份文件完整性校验失败。');
    if (file.path === 'data/ssl-manager.db' && !content.subarray(0, 16).equals(Buffer.from('SQLite format 3\0'))) throw new Error('备份不是有效的 SQLite 文件。');
    if (file.path === 'desktop-storage.json') {
      let marker: unknown;
      try { marker = JSON.parse(content.toString('utf8')); } catch { throw new Error('桌面数据归属标记损坏。'); }
      const storage = marker as Record<string, unknown>;
      // .NET 反序列化忽略属性大小写，因此拒绝 State/state 等影子字段，防止绕过 Ready 校验。
      if (!storage || typeof storage !== 'object' || Array.isArray(storage) || Object.keys(storage).length !== 3 ||
          !Object.keys(storage).every(name => ['application', 'protocol', 'state'].includes(name)) ||
          storage.application !== 'SslManager.Desktop' || storage.protocol !== 1 || storage.state !== 'Ready')
        throw new Error('备份必须来自已完成初始化的同版本桌面数据，不能触发结构迁移。');
    }
    names.add(file.path); size += content.length;
    if (size > maxDatabaseBytes + 16 * 1024 * 1024) throw new Error('备份内容超出支持大小。');
  }
  if (!names.has('data/ssl-manager.db') || !names.has('desktop-storage.json') || !manifest.files.some(file => file.path.startsWith('keys/'))) throw new Error('备份缺少数据库、桌面归属标记或加密密钥。');
  return manifest;
}

/** 导出采用 scrypt 派生密钥和 AES-256-GCM；密码不保存在配置或归档中。 */
export async function encryptManifest(manifest: BackupManifest, password: string): Promise<Buffer> {
  passwordValid(password); validateManifest(manifest);
  const salt = randomBytes(32); const iv = randomBytes(12); const key = await keyFor(password, salt);
  const plain = await zip(Buffer.from(JSON.stringify(manifest), 'utf8'));
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.from(JSON.stringify({ format: archiveName, version: 1, kdf: 'scrypt-n32768-r8-p1',
      salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') }), 'utf8');
  } finally { key.fill(0); plain.fill(0); }
}

export async function decryptManifest(bytes: Buffer, password: string): Promise<BackupManifest> {
  passwordValid(password);
  if (bytes.length > maxArchiveBytes) throw new Error('备份文件过大。');
  try {
    const envelope = JSON.parse(bytes.toString('utf8')) as Record<string, unknown>;
    if (envelope.format !== archiveName || envelope.version !== 1 || envelope.kdf !== 'scrypt-n32768-r8-p1') throw new Error('格式无效。');
    const salt = fromBase64(envelope.salt, 32); const iv = fromBase64(envelope.iv, 12); const tag = fromBase64(envelope.tag, 16);
    if (salt.length !== 32 || iv.length !== 12 || tag.length !== 16) throw new Error('加密参数无效。');
    const ciphertext = fromBase64(envelope.ciphertext, maxArchiveBytes); const key = await keyFor(password, salt);
    let plain: Buffer;
    try { const cipher = createDecipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad); cipher.setAuthTag(tag);
      plain = Buffer.concat([cipher.update(ciphertext), cipher.final()]); }
    finally { key.fill(0); }
    try {
      const decoded = await unzip(plain, { maxOutputLength: maxArchiveBytes });
      try { return validateManifest(JSON.parse(decoded.toString('utf8'))); } finally { decoded.fill(0); }
    } finally { plain.fill(0); }
  } catch { throw new Error('备份密码不正确、文件损坏或包含不允许的内容。'); }
}
