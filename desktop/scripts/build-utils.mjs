import { createHash, randomBytes } from 'node:crypto';
import { cp, mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

/** 每个平台只携带对应架构的本地 .NET 和 SQLite 原生发布物。 */
export const targets = Object.freeze({
  'win-x64': { rid: 'win-x64', platform: 'win32', builder: 'win', arch: 'x64', executable: 'SslManager.Api.exe', runtime: 'coreclr.dll', sqlite: 'e_sqlite3.dll' },
  'win-arm64': { rid: 'win-arm64', platform: 'win32', builder: 'win', arch: 'arm64', executable: 'SslManager.Api.exe', runtime: 'coreclr.dll', sqlite: 'e_sqlite3.dll' },
  'osx-x64': { rid: 'osx-x64', platform: 'darwin', builder: 'mac', arch: 'x64', executable: 'SslManager.Api', runtime: 'libcoreclr.dylib', sqlite: 'libe_sqlite3.dylib' },
  'osx-arm64': { rid: 'osx-arm64', platform: 'darwin', builder: 'mac', arch: 'arm64', executable: 'SslManager.Api', runtime: 'libcoreclr.dylib', sqlite: 'libe_sqlite3.dylib' },
  'linux-x64': { rid: 'linux-x64', platform: 'linux', builder: 'linux', arch: 'x64', executable: 'SslManager.Api', runtime: 'libcoreclr.so', sqlite: 'libe_sqlite3.so' },
  'linux-arm64': { rid: 'linux-arm64', platform: 'linux', builder: 'linux', arch: 'arm64', executable: 'SslManager.Api', runtime: 'libcoreclr.so', sqlite: 'libe_sqlite3.so' },
});

export function hostRid(platform = process.platform, arch = process.arch) {
  const family = { win32: 'win', darwin: 'osx', linux: 'linux' }[platform];
  const rid = `${family}-${arch}`;
  if (!targets[rid]) throw new Error(`不支持的构建目标：${platform}/${arch}。`);
  return rid;
}

export function parseArguments(args) {
  const result = { rid: hostRid(), all: false, prepareOnly: false, packageOnly: false, skipFrontend: false, skipElectron: false, validateOnly: false };
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (flag === '--target') result.rid = args[++index];
    else if (flag === '--all') result.all = true;
    else if (flag === '--prepare-only') result.prepareOnly = true;
    else if (flag === '--package-only') result.packageOnly = true;
    else if (flag === '--skip-frontend') result.skipFrontend = true;
    else if (flag === '--skip-electron') result.skipElectron = true;
    else if (flag === '--validate-only') result.validateOnly = true;
    else throw new Error(`未知构建参数：${flag}。`);
  }
  if (!targets[result.rid]) throw new Error(`未知 RID：${result.rid}。`);
  return result;
}

export function buildIdentifier() {
  return `${new Date().toISOString().replace(/[:.]/g, '-')}-${randomBytes(4).toString('hex')}`;
}

export function requireVersion(version) {
  if (!/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/.test(version)) throw new Error('桌面应用版本必须是明确的语义版本，不能从 Git 推导。');
  return version;
}

/** 指针只标识匹配版本与平台的暂存，不能把旧后端装入新版本外壳。 */
export function validateReleasePointer(pointer, rid, version) {
  if (!pointer || pointer.rid !== rid || pointer.version !== version)
    throw new Error('当前后端暂存的版本或平台不一致，请重新准备本轮后端资源。');
}

/** 相同产品版本也可能对应历史构建，必须继续核对数据库目标和版本清单摘要。 */
export function validateReleaseBinding(expected, actual) {
  if (!expected || !actual || ['version', 'targetMigration', 'manifestSha256'].some(key =>
    typeof expected[key] !== 'string' || expected[key].length === 0 || actual[key] !== expected[key]))
    throw new Error('后端暂存缺少本轮版本清单绑定或绑定不一致，请重新准备后端资源。');
}

export async function walkFiles(directory, relative = '') {
  const result = [];
  for (const item of await readdir(path.join(directory, relative), { withFileTypes: true })) {
    const name = path.posix.join(relative, item.name);
    if (item.isSymbolicLink()) throw new Error(`构建输入不允许符号链接：${name}。`);
    if (item.isDirectory()) result.push(...await walkFiles(directory, name));
    else if (item.isFile()) result.push(name);
  }
  return result.sort();
}

/** 只复制编译输入，实际 App_Data、密钥及所有原配置均不会进入构建暂存。 */
export async function stageBackendSource(source, destination) {
  await mkdir(destination, { recursive: true });
  const excluded = new Set(['app_data', 'bin', 'obj', 'wwwroot', 'properties', '.git']);
  const codeExtensions = new Set(['.cs', '.csproj', '.resx', '.props', '.targets']);
  async function visit(relative) {
    for (const item of await readdir(path.join(source, relative), { withFileTypes: true })) {
      if (item.name.startsWith('.') || excluded.has(item.name.toLowerCase())) continue;
      const next = path.join(relative, item.name);
      if (item.isSymbolicLink()) throw new Error(`后端编译输入不允许符号链接：${next}。`);
      if (item.isDirectory()) await visit(next);
      else if (item.isFile() && (codeExtensions.has(path.extname(item.name).toLowerCase()) || next.split(path.sep)[0] === 'Resources')) {
        // Resources 是明确的发行资源目录，整树保留；运行数据、配置和私钥仍不得混入。
        if (next.split(path.sep)[0] === 'Resources' && (forbiddenPayload(next.split(path.sep).join('/')) ||
          /\.(?:pem|key|pfx|p12|jks|keystore)$/i.test(item.name) || /^appsettings(?:\..+)?\.json$/i.test(item.name)))
          throw new Error(`发行资源包含禁止携带的配置或凭据：${next}。`);
        await mkdir(path.dirname(path.join(destination, next)), { recursive: true });
        await cp(path.join(source, next), path.join(destination, next), { force: false, errorOnExist: true });
      }
    }
  }
  await visit('');
  return path.join(destination, 'SslManager.Api.csproj');
}

export async function copyDirectory(source, destination) {
  const files = await walkFiles(source);
  await mkdir(destination, { recursive: true });
  for (const relative of files) {
    if (relative.split('/').some(part => part.startsWith('.'))) continue;
    await mkdir(path.dirname(path.join(destination, relative)), { recursive: true });
    await cp(path.join(source, relative), path.join(destination, relative), { force: false, errorOnExist: true });
  }
}

export const neutralConfiguration = Object.freeze({
  Worker: { PollSeconds: 15 },
  Logging: { LogLevel: { Default: 'Information', 'Microsoft.AspNetCore': 'Warning' } },
  AllowedHosts: '127.0.0.1',
});

/** 先解析路径再交给 builder，避免它把未展开的绝对路径宏误接到 projectDir 下。 */
export function renderBuilderConfiguration(template, bindings) {
  return template.replace(/\$\{env\.([A-Z0-9_]+)\}/g, (_match, key) => {
    const value = bindings[key];
    if (typeof value !== 'string' || value.length === 0 || /[\r\n\0]/.test(value)) throw new Error(`构建配置缺少安全的明确值：${key}。`);
    // JSON 字符串也是合法 YAML 标量，正确处理 Windows 反斜杠、空格与中文路径。
    return JSON.stringify(value);
  });
}

/** 验证真实可执行文件头，不能把一个平台的后端混进另一个安装包。 */
export function executableArchitecture(buffer, platform) {
  if (platform === 'win32') {
    if (buffer.length < 64 || buffer.toString('ascii', 0, 2) !== 'MZ') throw new Error('Windows 后端缺少 PE 文件头。');
    const offset = buffer.readUInt32LE(0x3c);
    if (offset + 6 > buffer.length || buffer.toString('ascii', offset, offset + 4) !== 'PE\0\0') throw new Error('Windows 后端 PE 文件头损坏。');
    return { 0x8664: 'x64', 0xaa64: 'arm64' }[buffer.readUInt16LE(offset + 4)];
  }
  if (platform === 'darwin') {
    if (buffer.length < 12 || buffer.readUInt32LE(0) !== 0xfeedfacf) throw new Error('macOS 后端缺少单架构 Mach-O 文件头。');
    return { 0x01000007: 'x64', 0x0100000c: 'arm64' }[buffer.readUInt32LE(4)];
  }
  if (buffer.length < 20 || buffer.toString('hex', 0, 4) !== '7f454c46' || buffer[4] !== 2 || buffer[5] !== 1) throw new Error('Linux 后端缺少受支持的 64 位 ELF 文件头。');
  return { 0x3e: 'x64', 0xb7: 'arm64' }[buffer.readUInt16LE(18)];
}

export function forbiddenPayload(relative) {
  const parts = relative.toLowerCase().split('/');
  return parts.some(part => ['app_data', 'keys', 'backups', 'local-run', 'logs', '.git', 'source-api'].includes(part)) ||
    parts.some(part => part === '.env' || part.startsWith('.env.')) ||
    /\.(?:db|sqlite|sqlite3)(?:-(?:wal|shm))?$/.test(relative.toLowerCase()) ||
    /^appsettings\..+\.json$/i.test(relative);
}

/** 邮件模板必须在实际发布目录中存在，避免源码有资源而安装包遗漏。 */
export async function verifyPublishedResources(directory) {
  const relative = 'Resources/Mail/CertificateExpiryWarning.html';
  try {
    const content = await readFile(path.join(directory, relative));
    if (content.length === 0) throw new Error('empty');
  } catch {
    throw new Error(`发布物缺少必需邮件模板：${relative}。`);
  }
}

export async function verifyPreparedBackend(directory, rid, { verifyHashes = false } = {}) {
  const target = targets[rid];
  if (!target) throw new Error(`未知 RID：${rid}。`);
  const files = await walkFiles(directory);
  const forbidden = files.find(forbiddenPayload);
  if (forbidden) throw new Error(`发布物包含禁止携带的运行数据：${forbidden}。`);
  await verifyPublishedResources(directory);
  for (const required of [target.executable, target.runtime, target.sqlite, 'System.Private.CoreLib.dll', 'SslManager.Api.dll', 'SslManager.Api.runtimeconfig.json', 'SslManager.Api.deps.json', 'wwwroot/index.html']) {
    if (!files.includes(required)) throw new Error(`发布物缺少必需文件：${required}。`);
  }
  for (const nativeFile of [target.executable, target.runtime, target.sqlite]) {
    const nativeContent = await readFile(path.join(directory, nativeFile));
    if (executableArchitecture(nativeContent, target.platform) !== target.arch) throw new Error(`后端原生文件架构与目标安装包不一致：${nativeFile}。`);
  }
  if (target.platform !== 'win32' && ((await stat(path.join(directory, target.executable))).mode & 0o111) === 0) throw new Error('后端可执行文件缺少执行权限。');
  const runtime = JSON.parse(await readFile(path.join(directory, 'SslManager.Api.runtimeconfig.json'), 'utf8'));
  if (runtime.runtimeOptions?.tfm !== 'net10.0' || runtime.runtimeOptions.framework || runtime.runtimeOptions.frameworks ||
      !runtime.runtimeOptions.includedFrameworks?.some(item => item.name === 'Microsoft.NETCore.App')) throw new Error('后端不是携带 .NET 10 运行时的自包含发布。');
  const deps = JSON.parse(await readFile(path.join(directory, 'SslManager.Api.deps.json'), 'utf8'));
  if (!deps.runtimeTarget?.name?.endsWith(`/${rid}`)) throw new Error('后端依赖清单 RID 与安装包不一致。');
  const configuration = JSON.parse(await readFile(path.join(directory, 'appsettings.json'), 'utf8'));
  if (JSON.stringify(configuration) !== JSON.stringify(neutralConfiguration)) throw new Error('发布物必须只携带桌面中性配置，不能携带开发或个人配置。');
  if (verifyHashes) {
    const manifest = JSON.parse(await readFile(path.join(directory, 'desktop-build-manifest.json'), 'utf8'));
    if (manifest.rid !== rid || manifest.schemaVersion !== 1) throw new Error('桌面发布清单版本或 RID 不一致。');
    const expectedFiles = manifest.files.map(file => file.path).sort();
    const actualFiles = files.filter(file => file !== 'desktop-build-manifest.json');
    if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) throw new Error('桌面发布文件集合与已验证清单不一致。');
    for (const item of manifest.files) {
      const content = await readFile(path.join(directory, item.path));
      if (content.length !== item.size || createHash('sha256').update(content).digest('hex') !== item.sha256) throw new Error(`桌面发布文件校验失败：${item.path}。`);
    }
  }
  return { rid, platform: target.platform, arch: target.arch, fileCount: files.length };
}

export async function writeBuildManifest(directory, rid, version, buildId, release) {
  if (release !== undefined) {
    validateReleaseBinding(release, release);
    if (release.version !== version) throw new Error('后端构建版本与版本清单绑定不一致。');
  }
  await verifyPreparedBackend(directory, rid);
  const files = [];
  for (const relative of (await walkFiles(directory)).filter(name => name !== 'desktop-build-manifest.json')) {
    const content = await readFile(path.join(directory, relative));
    files.push({ path: relative, size: content.length, sha256: createHash('sha256').update(content).digest('hex') });
  }
  const manifest = { schemaVersion: 1, applicationVersion: version, buildId, rid, platform: targets[rid].platform, arch: targets[rid].arch,
    createdAtUtc: new Date().toISOString(), selfContained: true, databaseIncluded: false,
    ...(release === undefined ? {} : { release }), files };
  await writeFile(path.join(directory, 'desktop-build-manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  return manifest;
}

/** 构建工具在仓库外执行；仅携带实际应用元数据，不伪造仓库或发布地址。 */
export async function createDetachedApplication(desktopRoot, metadata) {
  // 构建目录在仓库外，且不自动删除任何历史构建现场。
  return createApplicationDirectory(desktopRoot, metadata);
}

async function createApplicationDirectory(desktopRoot, metadata) {
  const appDirectory = path.join(os.tmpdir(), `ssl-manager-app-${buildIdentifier()}`);
  await mkdir(appDirectory, { recursive: false });
  await copyDirectory(path.join(desktopRoot, 'dist', 'src'), path.join(appDirectory, 'dist', 'src'));
  await copyDirectory(path.join(desktopRoot, 'resources'), path.join(appDirectory, 'resources'));
  const appPackage = { name: metadata.name, version: requireVersion(metadata.version), description: metadata.description,
    author: metadata.author ?? 'tongyaninfo contributors', license: metadata.license ?? 'Apache-2.0', main: metadata.main, type: metadata.type ?? 'commonjs',
    homepage: metadata.homepage ?? (typeof metadata.repository?.url === 'string' ? metadata.repository.url.replace(/^git\+/, '').replace(/\.git$/, '') : undefined),
    desktopName: 'free-ssl-manager.desktop' };
  await writeFile(path.join(appDirectory, 'package.json'), JSON.stringify(appPackage, null, 2) + '\n', { flag: 'wx' });
  return appDirectory;
}
