import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildIdentifier, copyDirectory, createDetachedApplication, neutralConfiguration, parseArguments, requireVersion,
  stageBackendSource, targets, validateReleaseBinding, validateReleasePointer, verifyPreparedBackend,
  writeBuildManifest, renderBuilderConfiguration, executableArchitecture } from './build-utils.mjs';
import { runCommand } from './process-utils.mjs';
import { checkRelease } from '../../scripts/release.mjs';

const desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = path.resolve(desktopRoot, '..');

/** Windows 上不能直接 spawn npm.cmd（会 EINVAL）；统一通过 npm 的 JS 入口执行。 */
async function runNpm(args, cwd) {
  const npmCli = process.env.npm_execpath;
  if (!npmCli) throw new Error('请通过 npm run 执行打包命令；缺少 npm_execpath，无法安全调用 npm。');
  await runCommand(process.execPath, [npmCli, ...args], { cwd });
}

/** 安装包构建全部使用显式版本、平台和路径，不查询 Git，也不发布到外部服务。 */
export async function build(args = process.argv.slice(2)) {
  const options = parseArguments(args);
  // 在构建与暂存之前确认统一版本及数据库迁移记录完整。
  const { binding } = await checkRelease(repositoryRoot);
  const metadata = JSON.parse(await readFile(path.join(desktopRoot, 'package.json'), 'utf8'));
  const version = requireVersion(metadata.version);
  const selected = options.all ? Object.values(targets) : [targets[options.rid]];
  const incomplete = [];
  if (!options.skipFrontend && !options.validateOnly) await runNpm(['run', 'build'], path.join(repositoryRoot, 'frontend'));
  if (!options.skipElectron && !options.validateOnly) await runNpm(['run', 'build:electron'], desktopRoot);
  await stat(path.join(repositoryRoot, 'frontend', 'dist', 'index.html'));
  const icons = options.prepareOnly || options.validateOnly ? undefined : await (await import('./generate-icons.mjs')).generateIcons();
  for (const target of selected) {
    if (options.validateOnly) {
      const current = JSON.parse(await readFile(path.join(desktopRoot, '.artifacts', `current-${target.rid}.json`), 'utf8'));
      validateReleasePointer(current, target.rid, version);
      const prepared = JSON.parse(await readFile(path.join(current.backendDirectory, 'desktop-build-manifest.json'), 'utf8'));
      validateReleaseBinding(binding, prepared.release);
      console.log(JSON.stringify(await verifyPreparedBackend(current.backendDirectory, target.rid, { verifyHashes: true })));
      continue;
    }
    const buildId = buildIdentifier();
    const directory = path.join(desktopRoot, '.artifacts', version, target.rid, buildId);
    let backendDirectory = path.join(directory, 'stage', 'backend');
    let backendBuildId = buildId;
    if (options.packageOnly) {
      // 壳代码调整后重打包可复用已校验的后端，不覆盖或删除之前的安装包。
      const current = JSON.parse(await readFile(path.join(desktopRoot, '.artifacts', `current-${target.rid}.json`), 'utf8'));
      validateReleasePointer(current, target.rid, version);
      backendDirectory = current.backendDirectory;
      backendBuildId = current.backendBuildId ?? current.buildId;
      await verifyPreparedBackend(backendDirectory, target.rid, { verifyHashes: true });
      const prepared = JSON.parse(await readFile(path.join(backendDirectory, 'desktop-build-manifest.json'), 'utf8'));
      validateReleaseBinding(binding, prepared.release);
    } else {
      // .NET SDK 的 SourceLink 也可能探测父目录；编译输入与打包 appDir 都必须位于仓库外。
      const project = await stageBackendSource(path.join(repositoryRoot, 'backend', 'SslManager.Api'), path.join(os.tmpdir(), `ssl-manager-source-${buildId}`));
      await mkdir(backendDirectory, { recursive: true });
      await runCommand('dotnet', ['publish', project, '--configuration', 'Release', '--runtime', target.rid, '--self-contained', 'true',
        '--output', backendDirectory, '-p:PublishSingleFile=false', '-p:PublishTrimmed=false', '-p:PublishReadyToRun=false', '-p:DebugType=None', '-p:DebugSymbols=false',
        '-p:EnableSourceControlManagerQueries=false', '-p:EnableSourceLink=false', '-p:IncludeSourceRevisionInInformationalVersion=false']);
      await writeFile(path.join(backendDirectory, 'appsettings.json'), JSON.stringify(neutralConfiguration, null, 2) + '\n', { flag: 'wx' });
      const webRoot = path.join(backendDirectory, 'wwwroot');
      await copyDirectory(path.join(repositoryRoot, 'frontend', 'dist'), webRoot);
      await writeBuildManifest(backendDirectory, target.rid, version, buildId, binding);
    }
    const manifest = JSON.parse(await readFile(path.join(backendDirectory, 'desktop-build-manifest.json'), 'utf8'));
    const webRoot = path.join(backendDirectory, 'wwwroot');
    const pointer = { schemaVersion: 1, version, rid: target.rid, buildId, backendDirectory, webRoot,
      backendBuildId, manifest: path.join(backendDirectory, 'desktop-build-manifest.json'), outputDirectory: path.join(directory, 'release') };
    await writeFile(path.join(desktopRoot, '.artifacts', `current-${target.rid}.json`), JSON.stringify(pointer, null, 2) + '\n');
    console.log(`已准备 ${target.rid} 自包含后端，共 ${manifest.files.length} 个经过校验的文件：${backendDirectory}`);
    if (options.prepareOnly) continue;
    if (process.platform !== target.platform && target.platform === 'darwin') {
      const message = `${target.rid} 已准备完成。当前系统不能进行该平台的完整安装包验收；请使用目标系统或 container-package.mjs，macOS 签名必须在 macOS 完成。`;
      if (options.all) { incomplete.push(message); continue; }
      throw new Error(message);
    }
    const appDirectory = await createDetachedApplication(desktopRoot, metadata);
    const toolEnvironment = await (await import('./prepare-tools.mjs')).prepareTools(target.platform);
    const electron = JSON.parse(await readFile(path.join(desktopRoot, 'node_modules', 'electron', 'package.json'), 'utf8'));
    const builder = path.join(desktopRoot, 'node_modules', 'electron-builder', 'out', 'cli', 'cli.js');
    const guard = path.join(desktopRoot, 'scripts', 'no-git.cjs');
    const env = { ...process.env, ...toolEnvironment, DESKTOP_BACKEND_DIR: backendDirectory, DESKTOP_TARGET_RID: target.rid,
      DESKTOP_OUTPUT_DIR: pointer.outputDirectory, DESKTOP_BUILD_VERSION: version,
      DESKTOP_ENTITLEMENTS: path.join(desktopRoot, 'build', 'entitlements.mac.plist'),
      DESKTOP_ICON_MAC: icons.icns, DESKTOP_ICON_WIN: icons.ico, DESKTOP_ICON_LINUX: icons.png,
      CSC_IDENTITY_AUTO_DISCOVERY: 'false',
      NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --require=${JSON.stringify(guard)}`.trim() };
    // 测试包只使用无私钥的 ad-hoc 签名，不自动读取开发机已有签名或 Apple 账户凭据。
    for (const key of Object.keys(env)) if ((key.startsWith('CSC_') && key !== 'CSC_IDENTITY_AUTO_DISCOVERY') || key.startsWith('WIN_CSC_') || key.startsWith('APPLE_')) delete env[key];
    const configuration = path.join(appDirectory, 'electron-builder.resolved.yml');
    await writeFile(configuration, renderBuilderConfiguration(await readFile(path.join(desktopRoot, 'electron-builder.yml'), 'utf8'), env), { flag: 'wx' });
    // 在脱离仓库的 appDir 运行，不携带 repository/publish 配置；防护器阻止任何隐藏 Git 调用。
    const builderArguments = [builder, '--projectDir', appDirectory, '--config', configuration,
      `--${target.builder}`, ...(target.platform === 'darwin' ? ['zip'] : []), `--${target.arch}`, '--publish', 'never', `--config.electronVersion=${electron.version}`,
      `--config.afterPack=${path.join(desktopRoot, 'scripts', 'after-pack.cjs')}`];
    let runtimeDirectory = process.env.SSL_DESKTOP_ELECTRON_DIST ||
      (target.arch === process.arch && target.platform === process.platform ? path.join(desktopRoot, 'node_modules', 'electron', 'dist') : undefined);
    if (!runtimeDirectory) {
      try {
        const runtime = JSON.parse(await readFile(path.join(desktopRoot, '.artifacts', 'electron', `current-${target.rid}.json`), 'utf8'));
        if (runtime.rid === target.rid && runtime.version === electron.version) runtimeDirectory = runtime.directory;
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    if (runtimeDirectory) {
      const runtimeExecutable = target.platform === 'darwin' ? path.join(runtimeDirectory, 'Electron.app', 'Contents', 'MacOS', 'Electron')
        : path.join(runtimeDirectory, target.platform === 'win32' ? 'electron.exe' : 'electron');
      if (executableArchitecture(await readFile(runtimeExecutable), target.platform) !== target.arch) throw new Error('Electron 可执行文件与目标安装包架构不一致。');
      builderArguments.push(`--config.electronDist=${path.resolve(runtimeDirectory)}`);
    }
    try {
      await runCommand(process.execPath, builderArguments, { cwd: appDirectory, env });
      if (target.platform === 'darwin') await (await import('./create-dmg.mjs')).createDmg({ outputDirectory: pointer.outputDirectory,
        productName: 'SSL证书管理', version, target, buildId });
    }
    catch (error) {
      // 当前外壳无原生 Node 扩展，优先使用 builder 自带跨平台工具；失败再由隔离容器补齐。
      if (options.all && target.platform !== process.platform && target.platform !== 'darwin') {
        try { await (await import('./container-package.mjs')).packageInContainer(['--target', target.rid]); }
        catch (containerError) { incomplete.push(`${target.rid}: ${error.message}；容器补充构建：${containerError.message}`); }
      } else throw error;
    }
  }
  if (incomplete.length > 0) throw new Error(`以下目标已准备后端，但安装包尚未完成：\n${incomplete.join('\n')}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
  await build().catch(error => { console.error(error.message); process.exitCode = 1; });
