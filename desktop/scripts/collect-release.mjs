import { constants } from 'node:fs';
import { copyFile, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { buildIdentifier, executableArchitecture, forbiddenPayload, requireVersion, targets, validateReleaseBinding,
  validateReleasePointer, verifyPreparedBackend, walkFiles } from './build-utils.mjs';
import { runCommand } from './process-utils.mjs';
import { checkRelease } from '../../scripts/release.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = path.resolve(root, '..');
const digest = content => createHash('sha256').update(content).digest('hex');

/** 文件名按安装器实际使用的架构命名，不能用仅改名的产物冒充另一平台。 */
export function releaseFileNames(productName, version, rid) {
  const target = targets[rid];
  if (!target) throw new Error(`未知 RID：${rid}。`);
  if (target.platform === 'win32') return [`${productName}-${version}-win-${target.arch}.exe`];
  if (target.platform === 'darwin') return ['dmg', 'zip'].map(extension => `${productName}-${version}-mac-${target.arch}.${extension}`);
  return [`${productName}-${version}-linux-${target.arch === 'x64' ? 'amd64' : 'arm64'}.deb`,
    `${productName}-${version}-linux-${target.arch === 'x64' ? 'x86_64' : 'arm64'}.AppImage`];
}

export function verifyInstallerFormat(content, name, rid) {
  if (name.endsWith('.exe')) {
    executableArchitecture(content, 'win32'); // NSIS 引导程序本身可为 x86，应用架构另查嵌入前的实际发布目录。
    return 'NSIS/PE';
  }
  if (name.endsWith('.AppImage')) {
    if (content.toString('hex', 8, 11) !== '414902' || executableArchitecture(content, 'linux') !== targets[rid].arch) throw new Error('AppImage 文件头或原生架构不匹配。');
    return 'AppImage type 2';
  }
  if (name.endsWith('.dmg')) {
    if (content.length < 512 || content.toString('ascii', content.length - 512, content.length - 508) !== 'koly') throw new Error('DMG 缺少完整 UDIF 尾部。');
    return 'UDIF/UDZO';
  }
  if (name.endsWith('.zip')) {
    if (content.toString('hex', 0, 4) !== '504b0304') throw new Error('ZIP 缺少文件头。');
    return 'ZIP';
  }
  if (name.endsWith('.deb')) {
    if (content.toString('ascii', 0, 8) !== '!<arch>\n') throw new Error('DEB 缺少 ar 文件头。');
    const members = []; let offset = 8;
    while (offset + 60 <= content.length) {
      const size = Number(content.toString('ascii', offset + 48, offset + 58).trim());
      if (!Number.isSafeInteger(size) || size < 0 || offset + 60 + size > content.length) throw new Error('DEB ar 成员损坏。');
      members.push(content.toString('ascii', offset, offset + 16).trim().replace(/\/$/, ''));
      offset += 60 + size + size % 2;
    }
    if (offset !== content.length || !members.includes('debian-binary') || !members.some(item => item.startsWith('control.tar')) || !members.some(item => item.startsWith('data.tar'))) throw new Error('DEB 缺少控制或应用数据。');
    return 'Debian ar';
  }
  throw new Error('未知安装器格式。');
}

async function verifyApplication(pointer, target, productName, binding) {
  const manifestPath = path.join(pointer.backendDirectory, 'desktop-build-manifest.json');
  const backendManifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  validateReleaseBinding(binding, backendManifest.release);
  const unpacked = target.platform === 'darwin'
    ? path.join(pointer.outputDirectory, target.arch === 'arm64' ? 'mac-arm64' : 'mac', `${productName}.app`, 'Contents')
    : path.join(pointer.outputDirectory, `${target.platform === 'win32' ? 'win' : 'linux'}${target.arch === 'arm64' ? '-arm64' : ''}-unpacked`);
  const resources = path.join(unpacked, target.platform === 'darwin' ? 'Resources' : 'resources');
  const executable = path.join(unpacked, ...(target.platform === 'darwin' ? ['MacOS', productName]
    : [target.platform === 'win32' ? `${productName}.exe` : 'free-ssl-manager']));
  if (executableArchitecture(await readFile(executable), target.platform) !== target.arch) throw new Error(`Electron 架构与 ${target.rid} 不一致。`);
  const backend = path.join(resources, 'backend');
  await verifyPreparedBackend(pointer.backendDirectory, target.rid, { verifyHashes: true });
  await verifyPreparedBackend(backend, target.rid, { verifyHashes: target.platform !== 'darwin' });
  if (backendManifest.applicationVersion !== pointer.version) throw new Error('后端版本与发行版本不一致。');
  if (!backendManifest.files.some(item => item.path.startsWith('wwwroot/') && item.path.endsWith('.js'))) throw new Error('安装包缺少前端 JavaScript 构建资源。');
  // macOS 签名会修改 Mach-O 中的代码签名段；其它托管程序集、配置与界面仍逐字节核对。
  for (const item of backendManifest.files) {
    const actual = await readFile(path.join(backend, item.path));
    if (digest(actual) === item.sha256) continue;
    if (target.platform === 'darwin') {
      try { if (executableArchitecture(actual, 'darwin') === target.arch) continue; } catch { /* 非原生文件不能豁免摘要。 */ }
    }
    throw new Error(`打包后的后端文件与已验证输入不一致：${item.path}。`);
  }
  const { listPackage, extractFile } = createRequire(import.meta.url)('@electron/asar');
  const asar = path.join(resources, 'app.asar');
  if (listPackage(asar).some(name => forbiddenPayload(name.replace(/^\//, '')))) throw new Error('Electron 资源混入运行数据或密钥。');
  const shellFiles = [];
  for (const relative of (await walkFiles(path.join(root, 'dist', 'src'))).filter(name => !name.endsWith('.map'))) {
    const content = await readFile(path.join(root, 'dist', 'src', relative));
    const sha256 = digest(content);
    if (digest(extractFile(asar, `dist/src/${relative}`)) !== sha256) throw new Error(`安装包未使用当前已编译壳：${relative}。`);
    shellFiles.push({ path: `dist/src/${relative}`, sha256 });
  }
  if (target.platform === 'darwin' && process.platform === 'darwin') await runCommand('codesign', ['--verify', '--deep', '--strict', path.dirname(unpacked)]);
  return { electronExecutable: executable, electronArchitecture: target.arch, backendArchitecture: target.arch,
    runtimeArchitecture: target.arch, sqliteArchitecture: target.arch, selfContained: true, databaseIncluded: false,
    backendBuildId: backendManifest.buildId, backendManifestSha256: digest(await readFile(manifestPath)), shellFiles };
}

/** 先验证六个平台与十个必需安装文件，再以排他复制汇总，缺失时绝不报告完整发行。 */
export async function collectRelease() {
  // 汇总历史产物前再次核对本轮应用版本与迁移账本。
  const { binding } = await checkRelease(repositoryRoot);
  const metadata = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const version = requireVersion(metadata.version); const productName = 'SSL证书管理';
  const platforms = []; const artifacts = [];
  for (const target of Object.values(targets)) {
    const pointer = JSON.parse(await readFile(path.join(root, '.artifacts', `current-${target.rid}.json`), 'utf8'));
    validateReleasePointer(pointer, target.rid, version);
    const validation = await verifyApplication(pointer, target, productName, binding);
    for (const name of releaseFileNames(productName, version, target.rid)) {
      const source = path.join(pointer.outputDirectory, name);
      const info = await stat(source);
      if (!info.isFile() || info.size === 0) throw new Error(`缺少有效安装文件：${source}。`);
      const content = await readFile(source);
      const format = verifyInstallerFormat(content, name, target.rid);
      artifacts.push({ file: name, rid: target.rid, platform: target.platform, architecture: target.arch, bytes: info.size,
        format, sha256: digest(content), source });
    }
    platforms.push({ rid: target.rid, platform: target.platform, architecture: target.arch,
      ...validation, sourceManifest: path.join(pointer.backendDirectory, 'desktop-build-manifest.json'), buildId: pointer.buildId });
  }
  if (artifacts.length !== 10) throw new Error('发行必须恰好包含六个 RID 的十个安装文件。');
  const outputDirectory = path.join(root, 'releases', `${version}-${buildIdentifier()}`);
  await mkdir(path.join(outputDirectory, 'manifests'), { recursive: true });
  for (const item of artifacts) {
    const destination = path.join(outputDirectory, item.file);
    await copyFile(item.source, destination, constants.COPYFILE_EXCL);
    if (digest(await readFile(destination)) !== item.sha256) throw new Error(`发行复制校验失败：${item.file}。`);
  }
  for (const item of platforms) await copyFile(item.sourceManifest, path.join(outputDirectory, 'manifests', `${item.rid}.json`), constants.COPYFILE_EXCL);
  const manifest = { schemaVersion: 1, version, release: binding, createdAtUtc: new Date().toISOString(), outputDirectory,
    artifactCount: artifacts.length, signing: { macOS: 'ad-hoc', notarized: false, windows: 'unsigned' },
    backendManifestHashScope: '自包含发布、平台代码签名前；macOS 签名后的原生文件另外验证架构及 codesign 完整性。',
    platforms, artifacts };
  await writeFile(path.join(outputDirectory, 'release-manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  await writeFile(path.join(outputDirectory, 'SHA256SUMS.txt'), artifacts.map(item => `${item.sha256}  ${item.file}`).join('\n') + '\n', { flag: 'wx' });
  await writeFile(path.join(root, '.artifacts', 'current-release.json'), JSON.stringify({ version, outputDirectory, manifest: path.join(outputDirectory, 'release-manifest.json') }, null, 2) + '\n');
  console.log(`已汇总六个 RID 的十个安装文件并完成复制摘要校验：${outputDirectory}`);
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
  await collectRelease().catch(error => { console.error(error.message); process.exitCode = 1; });
