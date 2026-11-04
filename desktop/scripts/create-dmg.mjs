import { cp, mkdir, symlink } from 'node:fs/promises';
import path from 'node:path';
import { runCommand } from './process-utils.mjs';

/** 使用系统原生磁盘工具，避免 DMG 美化工具暗中引入额外 Python 环境。 */
export async function createDmg({ outputDirectory, productName, version, target, buildId }) {
  if (process.platform !== 'darwin' || target.platform !== 'darwin') throw new Error('DMG 必须在 macOS 构建。');
  const application = path.join(outputDirectory, target.arch === 'arm64' ? 'mac-arm64' : 'mac', `${productName}.app`);
  await runCommand('codesign', ['--verify', '--deep', '--strict', application]);
  // 每次复制到独立目录，历史应用、磁盘镜像和临时现场均保留。
  const source = path.join(outputDirectory, '..', 'dmg-source');
  await mkdir(source, { recursive: false });
  await cp(application, path.join(source, `${productName}.app`), { recursive: true, force: false, errorOnExist: true, verbatimSymlinks: true });
  await runCommand('codesign', ['--verify', '--deep', '--strict', path.join(source, `${productName}.app`)]);
  await symlink('/Applications', path.join(source, 'Applications'));
  const artifact = path.join(outputDirectory, `${productName}-${version}-mac-${target.arch}.dmg`);
  const volume = `SSLManager-${version}-${target.arch}-${buildId.slice(-8)}`;
  await runCommand('hdiutil', ['create', '-srcfolder', source, '-volname', volume, '-fs', 'HFS+', '-format', 'UDZO', artifact]);
  await runCommand('hdiutil', ['verify', artifact]);
  return artifact;
}
