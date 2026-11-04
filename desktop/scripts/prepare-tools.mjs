import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildIdentifier } from './build-utils.mjs';
import { runCommand } from './process-utils.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function toolChecksum(source, filename) {
  const escaped = filename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = new RegExp('"' + escaped + '":\\s*"([a-f0-9]{64})"').exec(source);
  if (!match) throw new Error(`已安装官方打包工具没有 ${filename} 的固定 SHA256，拒绝镜像下载。`);
  return match[1];
}

/** 只从已安装官方 builder 源码取固定 hash；镜像、网络或文件名不能自行决定可信值。 */
export async function prepareTools(platform) {
  const mirror = process.env.SSL_DESKTOP_BUILDER_MIRROR || 'https://github.com/electron-userland/electron-builder-binaries/releases/download';
  const base = new URL(mirror);
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) throw new Error('构建工具源必须使用不含凭据的 HTTPS 地址。');
  const directory = path.join(root, '.artifacts', 'toolsets'); await mkdir(directory, { recursive: true });
  const cacheFile = path.join(directory, `current-${process.platform}-${process.arch}-${platform}.json`);
  try {
    const cached = JSON.parse(await readFile(cacheFile, 'utf8'));
    for (const item of cached.archives) {
      if (createHash('sha256').update(await readFile(item.archive)).digest('hex') !== item.sha256) throw new Error('已缓存构建工具校验失败。');
    }
    return cached.environment;
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const archives = []; const environment = {};
  async function download(release, filename, module, expected, sourceFile) {
    const source = await readFile(sourceFile ?? path.join(root, 'node_modules', 'app-builder-lib', 'out', 'toolsets', module + '.js'), 'utf8');
    const checksum = expected ?? toolChecksum(source, filename);
    const stage = path.join(directory, `${release.replaceAll('@', '-')}-${buildIdentifier()}`); await mkdir(stage);
    const archive = path.join(stage, filename); const extracted = path.join(stage, 'content'); await mkdir(extracted);
    await runCommand('curl', ['--fail', '--location', '--retry', '2', '--connect-timeout', '20', '--max-time', '180', '--output', archive,
      `${base.href.replace(/\/$/, '')}/${release}/${filename}`]);
    if (createHash('sha256').update(await readFile(archive)).digest('hex') !== checksum) throw new Error('构建工具与官方安装包源码固定校验值不一致，未解压或执行。');
    if (filename.endsWith('.tar.gz')) await runCommand('tar', ['-xzf', archive, '-C', extracted]);
    else await runCommand(environment.ELECTRON_BUILDER_7ZIP_PATH, ['x', archive, '-o' + extracted, '-y']);
    archives.push({ archive, sha256: checksum, release, filename });
    let content = extracted;
    // 官方工具 tar 包通常带一层顶级目录，与 builder 自身解包规范化保持一致。
    for (let depth = 0; depth < 3; depth++) {
      const entries = await readdir(content, { withFileTypes: true });
      if (entries.length !== 1 || !entries[0].isDirectory()) break;
      content = path.join(content, entries[0].name);
    }
    return content;
  }
  const host = process.platform === 'darwin' ? `darwin-${process.arch === 'arm64' ? 'arm64' : 'x86_64'}`
    : process.platform === 'win32' ? `win-${process.arch}` : `linux-${process.arch}`;
  const seven = await download('7zip@1.0.0', `7zip-${host}.tar.gz`, '7zip');
  environment.ELECTRON_BUILDER_7ZIP_PATH = path.join(seven, 'bin', process.platform === 'win32' ? '7za.exe' : '7za');
  if (process.platform !== 'win32') await chmod(environment.ELECTRON_BUILDER_7ZIP_PATH, 0o755);
  if (platform === 'win32') {
    const nsis = await download('nsis@1.2.1', 'nsis-bundle-3.12.tar.gz', 'windows');
    environment.ELECTRON_BUILDER_NSIS_DIR = nsis; environment.ELECTRON_BUILDER_NSIS_RESOURCES_DIR = nsis;
  }
  if (platform === 'linux') {
    const fpmHost = process.platform === 'darwin' ? `darwin-${process.arch === 'arm64' ? 'arm64' : 'x86_64'}` : `linux-${process.arch === 'arm64' ? 'arm64v8' : 'amd64'}`;
    const fpm = await download('fpm@2.1.4', `fpm-1.17.0-ruby-3.4.3-${fpmHost}.7z`, 'linux');
    environment.CUSTOM_FPM_PATH = path.join(fpm, 'fpm');
    if (process.platform === 'darwin') environment.LINUX_TOOLS_MAC_PATH = await download('linux-tools-mac@1.0.1', `linux-tools-mac-darwin-${process.arch === 'arm64' ? 'arm64' : 'x86_64'}.tar.gz`, 'linux');
    // static-runtime 打包工具明确固定版本；其源码导出的校验表决定 hash。
    const require = (await import('node:module')).createRequire(import.meta.url);
    const checksum = require('app-builder-lib/out/toolsets/linux.js').appimageChecksums['1.0.3']['appimage-tools-runtime-20251108.tar.gz'];
    environment.APPIMAGE_TOOLS_PATH = await download('appimage@1.0.3', 'appimage-tools-runtime-20251108.tar.gz', 'linux', checksum);
  }
  await writeFile(cacheFile, JSON.stringify({ schemaVersion: 1, environment, archives }, null, 2) + '\n');
  return environment;
}
