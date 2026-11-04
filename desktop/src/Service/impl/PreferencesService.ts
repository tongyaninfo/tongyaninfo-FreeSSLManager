import { readFile, writeFile, rename, lstat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import type { DesktopPreferences } from '../../Models/DesktopModels';

export const defaultPreferences: DesktopPreferences = { closeToTray: true, launchAtLogin: false };

export function validatePreferences(value: unknown): DesktopPreferences {
  if (!value || typeof value !== 'object' || typeof (value as DesktopPreferences).closeToTray !== 'boolean' || typeof (value as DesktopPreferences).launchAtLogin !== 'boolean')
    throw new Error('桌面设置格式不正确。');
  return { closeToTray: (value as DesktopPreferences).closeToTray, launchAtLogin: (value as DesktopPreferences).launchAtLogin };
}

/** 桌面配置仅包含显示与自启偏好，账户凭据继续由原后端加密管理。 */
export class PreferencesService {
  private current: DesktopPreferences = { ...defaultPreferences };
  constructor(private readonly file: string) {}
  get value(): DesktopPreferences { return { ...this.current }; }
  async load(): Promise<void> {
    try {
      const info = await lstat(this.file);
      if (!info.isFile() || info.isSymbolicLink() || info.size > 16_384) throw new Error('桌面设置不是普通小型配置文件。');
      this.current = validatePreferences(JSON.parse(await readFile(this.file, 'utf8')));
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('桌面设置无法读取，保留原文件等待处理。'); }
  }
  async save(value: DesktopPreferences): Promise<void> {
    const validated = validatePreferences(value); const temporary = this.file + '.pending-' + randomUUID();
    await writeFile(temporary, JSON.stringify(validated, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    await rename(temporary, this.file); this.current = validated;
  }
}
