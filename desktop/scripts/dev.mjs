import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { hostRid, verifyPreparedBackend } from './build-utils.mjs';

const desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rid = hostRid();
try {
  const pointer = JSON.parse(await readFile(path.join(desktopRoot, '.artifacts', `current-${rid}.json`), 'utf8'));
  await verifyPreparedBackend(pointer.backendDirectory, rid, { verifyHashes: true });
  const electronPath = path.join(desktopRoot, 'node_modules', 'electron', 'cli.js');
  const child = spawn(process.execPath, [electronPath, desktopRoot], { cwd: desktopRoot, stdio: 'inherit', shell: false,
    env: { ...process.env, SSL_DESKTOP_BACKEND_DIR: pointer.backendDirectory } });
  child.once('error', error => { console.error(error.message); process.exitCode = 1; });
  child.once('exit', code => { process.exitCode = code ?? 1; });
} catch (error) {
  console.error(`桌面开发启动失败：${error.message}\n请先运行 npm run build:backend -- --skip-frontend。`);
  process.exitCode = 1;
}
