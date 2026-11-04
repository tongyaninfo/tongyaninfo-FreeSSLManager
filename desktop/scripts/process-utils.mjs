import { spawn } from 'node:child_process';
import path from 'node:path';

/** 命令始终以参数数组启动，不经 shell 拼接；调用者仅传递已审查的构建输入。 */
export async function runCommand(command, args, { cwd = process.cwd(), env = process.env } = {}) {
  await new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: 'inherit', shell: false });
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0 ? resolve() : reject(new Error(`${path.basename(command)} 执行失败（${signal ?? code}）。`)));
  });
}
