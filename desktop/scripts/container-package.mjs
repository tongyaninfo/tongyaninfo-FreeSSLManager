import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildIdentifier, copyDirectory, createDetachedApplication, renderBuilderConfiguration, targets,
  validateReleaseBinding, validateReleasePointer, verifyPreparedBackend } from './build-utils.mjs';
import { runCommand } from './process-utils.mjs';
import { checkRelease } from '../../scripts/release.mjs';

const desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = path.resolve(desktopRoot, '..');

/** 容器只挂载已校验发布物、编译外壳和独立缓存，不挂仓库或业务用户数据。 */
export function containerPlan(rid, inputDirectory, cacheDirectory, image, engine = 'podman') {
  const target = targets[rid];
  if (!target || target.platform === 'darwin') throw new Error('容器打包只支持 Windows/Linux；macOS 安装包及签名必须使用 macOS 构建环境。');
  if (!['podman', 'docker'].includes(engine)) throw new Error('容器引擎只能是 podman 或 docker。');
  // 官方 Wine 构建镜像为 amd64；这里只运行构建工具，不运行目标安装包中的 ARM 应用。
  const platform = image.startsWith('electronuserland/builder') ? 'linux/amd64' : target.arch === 'arm64' ? 'linux/arm64' : 'linux/amd64';
  const command = [
    'cd /work/tooling',
    'npm install --ignore-scripts --no-audit --no-fund',
    'cd /work/app',
    `node /work/tooling/node_modules/electron-builder/out/cli/cli.js --projectDir /work/app --config /work/tooling/electron-builder.yml --${target.builder} --${target.arch} --publish never --config.afterPack=/work/tooling/scripts/after-pack.cjs`,
  ].join(' && ');
  return { command: engine, args: ['run', '--name', `ssl-manager-${rid}-${buildIdentifier().toLowerCase()}`, '--platform', platform,
    '--volume', `${inputDirectory}:/work:rw`, '--volume', `${cacheDirectory}:/root/.cache:rw`,
    '--env', 'ELECTRON_SKIP_BINARY_DOWNLOAD=1', '--env', 'DESKTOP_BACKEND_DIR=/work/backend', '--env', `DESKTOP_TARGET_RID=${rid}`,
    '--env', 'DESKTOP_OUTPUT_DIR=/work/output', '--env', 'DESKTOP_ENTITLEMENTS=/work/tooling/build/entitlements.mac.plist',
    '--env', 'CSC_IDENTITY_AUTO_DISCOVERY=false',
    '--env', 'NODE_OPTIONS=--require=/work/tooling/scripts/no-git.cjs', image, 'bash', '-lc', command] };
}

export async function packageInContainer(args = process.argv.slice(2)) {
  let rid, engine = 'podman', image, prepareOnly = false;
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (flag === '--target') rid = args[++index];
    else if (flag === '--engine') engine = args[++index];
    else if (flag === '--image') image = args[++index];
    else if (flag === '--prepare-only') prepareOnly = true;
    else throw new Error(`未知容器打包参数：${flag}。`);
  }
  const target = targets[rid];
  if (!target || target.platform === 'darwin') throw new Error('请明确选择 win-x64、win-arm64、linux-x64 或 linux-arm64。');
  // 宿主机先校验版本；隔离容器继续仅执行已准备的打包工具。
  const { binding, version } = await checkRelease(repositoryRoot);
  image ??= target.platform === 'win32' ? 'electronuserland/builder:wine' : 'electronuserland/builder:latest';
  const pointer = JSON.parse(await readFile(path.join(desktopRoot, '.artifacts', `current-${rid}.json`), 'utf8'));
  validateReleasePointer(pointer, rid, version);
  await verifyPreparedBackend(pointer.backendDirectory, rid, { verifyHashes: true });
  const backendManifest = JSON.parse(await readFile(path.join(pointer.backendDirectory, 'desktop-build-manifest.json'), 'utf8'));
  validateReleaseBinding(binding, backendManifest.release);
  const metadata = JSON.parse(await readFile(path.join(desktopRoot, 'package.json'), 'utf8'));
  const inputDirectory = path.join(desktopRoot, '.artifacts', metadata.version, rid, buildIdentifier(), 'container');
  const tooling = path.join(inputDirectory, 'tooling');
  await mkdir(tooling, { recursive: true });
  const application = await createDetachedApplication(desktopRoot, metadata);
  await copyDirectory(application, path.join(inputDirectory, 'app'));
  await copyDirectory(pointer.backendDirectory, path.join(inputDirectory, 'backend'));
  await copyDirectory(path.join(desktopRoot, 'scripts'), path.join(tooling, 'scripts'));
  await copyDirectory(path.join(desktopRoot, 'build'), path.join(tooling, 'build'));
  const config = await readFile(path.join(desktopRoot, 'electron-builder.yml'), 'utf8');
  const electron = JSON.parse(await readFile(path.join(desktopRoot, 'node_modules', 'electron', 'package.json'), 'utf8'));
  // 工具包元数据与版本全部明确传入，且只有构建依赖，不能携带源仓库 repository。
  await writeFile(path.join(tooling, 'package.json'), JSON.stringify({ name: 'ssl-manager-packaging-tools', private: true, version: metadata.version,
    devDependencies: { electron: electron.version, 'electron-builder': metadata.devDependencies['electron-builder'] } }, null, 2) + '\n', { flag: 'wx' });
  const resolvedConfig = renderBuilderConfiguration(config, { DESKTOP_BACKEND_DIR: '/work/backend', DESKTOP_OUTPUT_DIR: '/work/output',
    DESKTOP_BUILD_VERSION: metadata.version, DESKTOP_ICON_MAC: '/work/app/resources/icon.png', DESKTOP_ICON_WIN: '/work/app/resources/icon.png',
    DESKTOP_ICON_LINUX: '/work/app/resources/icon.png', DESKTOP_ENTITLEMENTS: '/work/tooling/build/entitlements.mac.plist' });
  await writeFile(path.join(tooling, 'electron-builder.yml'), resolvedConfig + `\nelectronVersion: ${electron.version}\n`, { flag: 'wx' });
  const cacheDirectory = path.join(desktopRoot, '.artifacts', 'container-cache', target.arch);
  await mkdir(cacheDirectory, { recursive: true });
  const plan = containerPlan(rid, inputDirectory, cacheDirectory, image, engine);
  const versionPosition = plan.args.indexOf('DESKTOP_OUTPUT_DIR=/work/output');
  plan.args.splice(versionPosition + 1, 0, '--env', `DESKTOP_BUILD_VERSION=${metadata.version}`);
  const manifest = { schemaVersion: 1, rid, applicationVersion: metadata.version, release: binding, inputDirectory,
    outputDirectory: path.join(inputDirectory, 'output'), engine, image, containerName: plan.args[plan.args.indexOf('--name') + 1],
    retainsContainer: true, includesBusinessData: false };
  await writeFile(path.join(inputDirectory, 'container-build.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
  console.log(`已准备隔离容器构建：${inputDirectory}`);
  if (!prepareOnly) {
    await runCommand(plan.command, plan.args, { cwd: inputDirectory });
    // 容器回退产物有独立输出目录；仅成功后切换指针，不能误指向此前失败的本机安装包。
    const updated = { ...pointer, outputDirectory: manifest.outputDirectory, containerBuild: path.join(inputDirectory, 'container-build.json') };
    await writeFile(path.join(desktopRoot, '.artifacts', `current-${rid}.json`), JSON.stringify(updated, null, 2) + '\n');
  }
  console.log(`安装包输出：${manifest.outputDirectory}；构建现场和已停止容器保留，不执行自动删除。`);
  return manifest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
  await packageInContainer().catch(error => { console.error(error.message); process.exitCode = 1; });
