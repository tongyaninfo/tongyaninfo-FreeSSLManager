import { mkdir, readFile, writeFile, lstat } from 'node:fs/promises';
import path from 'node:path';
import { applicationId } from '../../Common/Paths';

const marker = '# Managed by ' + applicationId;

/** Linux 使用用户级桌面自启项；关闭时写 Hidden=true，保留原文件而不删除。 */
export function linuxAutoStartEntry(executable: string, enabled: boolean): string {
  if (!path.isAbsolute(executable) || /[\r\n\0]/.test(executable)) throw new Error('客户端可执行路径不合法。');
  const quoted = '"' + executable.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('`', '\\`').replaceAll('$', '\\$').replaceAll('%', '%%') + '"';
  return `${marker}\n[Desktop Entry]\nType=Application\nName=SSL Certificate Manager\nExec=${quoted} --hidden\nTerminal=false\nHidden=${!enabled}\nX-GNOME-Autostart-enabled=${enabled}\n`;
}

export async function setLinuxAutoStart(configHome: string, executable: string, enabled: boolean): Promise<void> {
  const directory = path.join(configHome, 'autostart'); const file = path.join(directory, applicationId + '.desktop');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  try {
    const info = await lstat(file);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 16_384 || !(await readFile(file, 'utf8')).startsWith(marker + '\n'))
      throw new Error('自启位置已有其他程序内容，未覆盖。');
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  await writeFile(file, linuxAutoStartEntry(executable, enabled), { mode: 0o600 });
}
