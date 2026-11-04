import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildIdentifier, executableArchitecture, hostRid, targets } from './build-utils.mjs';
import { runCommand } from './process-utils.mjs';

const desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** 镜像只提供字节；真实性始终依据已安装官方 npm 包中的完整 SHA256 清单。 */
export function validateElectronArchive(bytes, filename, checksums) {
  const expected = checksums[filename];
  if (typeof expected !== 'string' || !/^[a-f0-9]{64}$/.test(expected)) throw new Error('官方 Electron npm 包没有该目标的有效校验值。');
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== expected) throw new Error('Electron 下载文件与官方 npm 校验值不一致，拒绝解压或打包。');
  return actual;
}

export async function prepareElectron(args = process.argv.slice(2)) {
  let rid = hostRid(); let mirror = process.env.SSL_DESKTOP_ELECTRON_MIRROR || 'https://github.com/electron/electron/releases/download';
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--target') rid = args[++index];
    else if (args[index] === '--mirror') mirror = args[++index];
    else throw new Error(`未知 Electron 准备参数：${args[index]}。`);
  }
  const target = targets[rid]; if (!target) throw new Error('Electron 目标 RID 无效。');
  const base = new URL(mirror);
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) throw new Error('下载源必须是不含凭据的 HTTPS 地址。');
  const metadata = JSON.parse(await readFile(path.join(desktopRoot, 'node_modules', 'electron', 'package.json'), 'utf8'));
  const checksums = JSON.parse(await readFile(path.join(desktopRoot, 'node_modules', 'electron', 'checksums.json'), 'utf8'));
  const filename = `electron-v${metadata.version}-${target.platform}-${target.arch}.zip`;
  if (!checksums[filename]) throw new Error('官方 Electron 包未提供该平台发布物。');
  const buildId = buildIdentifier(); const directory = path.join(desktopRoot, '.artifacts', 'electron', rid, metadata.version, buildId);
  await mkdir(directory, { recursive: true });
  const archive = path.join(directory, filename); const dist = path.join(directory, 'dist');
  const url = `${base.href.replace(/\/$/, '')}/v${metadata.version}/${filename}`;
  await runCommand('curl', ['--fail', '--location', '--retry', '2', '--connect-timeout', '20', '--max-time', '240', '--output', archive, url]);
  const checksum = validateElectronArchive(await readFile(archive), filename, checksums);
  await mkdir(dist);
  if (process.platform === 'darwin') await runCommand('ditto', ['-xk', archive, dist]);
  else if (process.platform === 'win32') {
    const quote = value => "'" + value.replaceAll("'", "''") + "'";
    await runCommand('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Expand-Archive -LiteralPath ${quote(archive)} -DestinationPath ${quote(dist)}`]);
  } else await runCommand('unzip', ['-q', archive, '-d', dist]);
  const executable = target.platform === 'darwin' ? path.join(dist, 'Electron.app', 'Contents', 'MacOS', 'Electron') : path.join(dist, target.platform === 'win32' ? 'electron.exe' : 'electron');
  if (executableArchitecture(await readFile(executable), target.platform) !== target.arch) throw new Error('官方发布物可执行架构不符合目标。');
  const result = { schemaVersion: 1, rid, version: metadata.version, directory: dist, archive, filename, sha256: checksum, source: url };
  await writeFile(path.join(desktopRoot, '.artifacts', 'electron', `current-${rid}.json`), JSON.stringify(result, null, 2) + '\n');
  console.log(`Electron ${target.platform}/${target.arch} 官方 SHA256 与真实可执行架构均已验证：${dist}`);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
  await prepareElectron().catch(error => { console.error(error.message); process.exitCode = 1; });
