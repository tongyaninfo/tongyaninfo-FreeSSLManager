import { mkdir, readFile, writeFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildIdentifier } from './build-utils.mjs';
import { runCommand } from './process-utils.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** 使用系统图标工具生成项目图标，不安装全局依赖，也不让打包器为图标访问外部下载。 */
export async function generateIcons() {
  const pointer = path.join(root, 'build', 'current-icons.json');
  const png = path.join(root, 'resources', 'icon.png');
  if (process.platform !== 'darwin') {
    try {
      const cached = JSON.parse(await readFile(pointer, 'utf8'));
      for (const file of [cached.png, cached.icns, cached.ico]) if (!(await stat(file)).isFile()) throw new Error('图标暂存不存在。');
      return cached;
    }
    catch { return { png, icns: png, ico: png }; }
  }
  const directory = path.join(root, 'build', 'generated-icons', buildIdentifier());
  const iconset = path.join(directory, 'icon.iconset'); await mkdir(iconset, { recursive: true });
  for (const size of [16, 32, 128, 256, 512]) {
    await runCommand('sips', ['-z', String(size), String(size), png, '--out', path.join(iconset, `icon_${size}x${size}.png`)]);
    await runCommand('sips', ['-z', String(size * 2), String(size * 2), png, '--out', path.join(iconset, `icon_${size}x${size}@2x.png`)]);
  }
  const icns = path.join(directory, 'icon.icns'); const ico = path.join(directory, 'icon.ico');
  await runCommand('iconutil', ['-c', 'icns', iconset, '-o', icns]);
  const small = await readFile(path.join(iconset, 'icon_256x256.png'));
  // Windows Vista+ 支持 PNG 内嵌 ICO；0 宽高表示 256px，不需要额外图像运行库。
  const header = Buffer.alloc(22); header.writeUInt16LE(1, 2); header.writeUInt16LE(1, 4);
  header.writeUInt16LE(1, 10); header.writeUInt16LE(32, 12); header.writeUInt32LE(small.length, 14); header.writeUInt32LE(22, 18);
  await writeFile(ico, Buffer.concat([header, small]), { flag: 'wx' });
  const result = { png, icns, ico }; await writeFile(pointer, JSON.stringify(result, null, 2) + '\n');
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) await generateIcons();
