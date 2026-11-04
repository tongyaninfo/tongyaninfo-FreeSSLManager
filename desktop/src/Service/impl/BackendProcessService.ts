import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { appendFile } from 'node:fs/promises';
import path from 'node:path';
import { desktopTokenHeader, validateBackendOrigin } from '../../Common/Paths';
import type { BackendStatus, DesktopResult, SnapshotResult } from '../../Models/DesktopModels';
import type { IBackendProcessService } from '../IBackendProcessService';

export interface BackendProcessOptions {
  executable: string;
  dataDirectory: string;
  logsFile: string;
  webRoot?: string;
  arguments?: string[];
  environment?: NodeJS.ProcessEnv;
  startupTimeoutMs?: number;
  shutdownTimeoutMs?: number;
  restartBaseMs?: number;
}

/** 只管理自己创建的后端进程；业务恢复由既有持久任务 Worker 负责。 */
export class BackendProcessService extends EventEmitter implements IBackendProcessService {
  private child?: ChildProcessWithoutNullStreams;
  private starting?: Promise<void>;
  private stopping?: Promise<void>;
  private restartTimer?: NodeJS.Timeout;
  private stableTimer?: NodeJS.Timeout;
  private wanted = false;
  private failures = 0;
  private token = '';
  private currentOrigin?: string;
  private currentStatus: BackendStatus = { phase: 'stopped', message: '本地服务尚未启动。' };
  private requests = new Map<string, { resolve(value: DesktopResult): void; reject(reason: Error): void; timer: NodeJS.Timeout }>();

  constructor(private readonly options: BackendProcessOptions) { super(); }
  get status(): BackendStatus { return { ...this.currentStatus }; }
  get origin(): string | undefined { return this.currentOrigin; }

  async start(): Promise<void> {
    if (this.stopping) await this.stopping;
    this.wanted = true;
    if (this.child && this.currentStatus.phase === 'ready') return;
    if (this.starting) return this.starting;
    if (this.restartTimer) clearTimeout(this.restartTimer);
    this.starting = this.launch().finally(() => { this.starting = undefined; });
    return this.starting;
  }

  private setStatus(phase: BackendStatus['phase'], message: string, code?: string): void {
    this.currentStatus = { phase, message, ...(code ? { code } : {}) }; this.emit('status', this.status);
  }

  private launch(): Promise<void> {
    if (this.child) return Promise.reject(new Error('上一个本地服务尚未退出。'));
    this.setStatus('starting', '正在启动本地服务。');
    this.currentOrigin = undefined; this.token = randomBytes(32).toString('hex');
    const instanceId = randomUUID();
    const child = spawn(this.options.executable, this.options.arguments ?? ['--desktop'], {
      cwd: path.dirname(this.options.executable), windowsHide: true, shell: false,
      stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, ...this.options.environment },
    });
    this.child = child;
    let buffer = ''; let settled = false; let startupFailure = '';
    return new Promise<void>((resolve, reject) => {
      const fail = (message: string) => {
        if (settled) return;
        settled = true; clearTimeout(timeout); reject(new Error(message));
      };
      const timeout = setTimeout(() => {
        fail('本地服务启动超时，请查看日志。');
        child.kill();
      }, this.options.startupTimeoutMs ?? 90_000);
      child.on('error', (error) => { void this.log('后端进程无法启动：' + error.name); fail('无法启动内置本地服务，请查看日志。'); });
      child.stderr.on('data', (chunk: Buffer) => { void this.log(chunk.toString('utf8')); });
      child.stdout.on('data', (chunk: Buffer) => {
        if (this.child !== child) return;
        buffer += chunk.toString('utf8');
        if (buffer.length > 4 * 1024 * 1024) { fail('本地服务返回了无效控制消息。'); child.kill(); return; }
        let newline: number;
        while ((newline = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, newline).trim(); buffer = buffer.slice(newline + 1);
          if (!line) continue;
          try {
            const message = JSON.parse(line) as Record<string, unknown>;
            if (message.type === 'ready' && !settled) {
              if (message.protocol !== 1 || message.instanceId !== instanceId || message.pid !== child.pid) throw new Error('就绪实例不匹配。');
              this.currentOrigin = validateBackendOrigin(message.origin);
              settled = true; clearTimeout(timeout);
              this.setStatus('ready', '本地服务运行中，计划任务会持续执行。');
              this.stableTimer = setTimeout(() => { this.failures = 0; }, 60_000); this.stableTimer.unref();
              this.emit('ready', this.currentOrigin); resolve();
            } else if (message.type === 'response' && typeof message.requestId === 'string') {
              const request = this.requests.get(message.requestId);
              if (request) {
                clearTimeout(request.timer); this.requests.delete(message.requestId);
                request.resolve(message as unknown as DesktopResult);
              }
            } else if (message.type === 'fatal' || message.type === 'error') {
              const code = typeof message.code === 'string' && /^[A-Z0-9_]{1,100}$/.test(message.code) ? message.code : 'DESKTOP_START_FAILED';
              startupFailure = (typeof message.message === 'string' ? this.redact(message.message).slice(0, 1024) : '本地服务初始化失败。') + `（${code}）`;
              void this.log(startupFailure);
              // 数据格式、密钥和升级策略冲突需要明确处理，不能反复创建替代库或替代密钥。
              if (code.startsWith('DESKTOP_') && code !== 'DESKTOP_DATA_BUSY' && code !== 'DESKTOP_DATABASE_FAILED') {
                this.wanted = false; this.setStatus('failed', startupFailure, code);
              }
              fail(startupFailure);
            }
          } catch { fail('本地服务控制消息校验失败。'); child.kill(); }
        }
      });
      child.once('close', () => {
        clearTimeout(timeout); if (this.stableTimer) clearTimeout(this.stableTimer);
        if (this.child !== child) return;
        this.child = undefined; this.currentOrigin = undefined; this.token = '';
        for (const request of this.requests.values()) { clearTimeout(request.timer); request.reject(new Error('本地服务已断开。')); }
        this.requests.clear(); fail('本地服务在就绪前退出，请查看日志。');
        if (this.wanted) this.scheduleRestart(startupFailure);
        else if (this.currentStatus.phase !== 'failed') this.setStatus('stopped', '本地服务已停止，重新打开后继续未完成任务。');
      });
      child.stdin.on('error', () => { /* 管道关闭由 close 事件统一处理。 */ });
      child.stdin.write(JSON.stringify({ type: 'initialize', protocol: 1, token: this.token, instanceId,
        dataDirectory: this.options.dataDirectory, ...(this.options.webRoot ? { webRoot: this.options.webRoot } : {}) }) + '\n');
    });
  }

  private scheduleRestart(reason = ''): void {
    this.failures++;
    if (this.failures > 10) { this.setStatus('failed', '本地服务连续启动失败，请查看日志后从菜单重试。'); return; }
    const delay = Math.min(30_000, (this.options.restartBaseMs ?? 1_000) * 2 ** Math.min(this.failures - 1, 5));
    this.setStatus('restarting', reason ? `${reason} 正在等待自动重试。` : '本地服务意外退出，正在等待自动恢复。');
    this.restartTimer = setTimeout(() => { void this.start().catch(() => { /* 后续 close 继续退避。 */ }); }, delay);
  }

  async stop(): Promise<void> {
    this.wanted = false;
    if (this.restartTimer) clearTimeout(this.restartTimer);
    if (this.stopping) return this.stopping;
    this.stopping = this.stopChild().finally(() => { this.stopping = undefined; });
    return this.stopping;
  }

  private async stopChild(): Promise<void> {
    const child = this.child;
    if (!child) { this.setStatus('stopped', '本地服务已停止。'); return; }
    this.setStatus('stopping', '正在保存任务进度并停止本地服务。');
    const exit = new Promise<void>((resolve) => child.once('close', () => resolve()));
    try { await this.request('shutdown', {}, Math.min(10_000, this.options.shutdownTimeoutMs ?? 30_000)); } catch { /* 仍须确认该进程退出。 */ }
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([exit, new Promise<void>((resolve) => { timer = setTimeout(resolve, this.options.shutdownTimeoutMs ?? 30_000); })]);
    if (timer) clearTimeout(timer);
    if (this.child === child) {
      child.kill();
      await Promise.race([exit, new Promise<void>((resolve) => setTimeout(resolve, 5_000))]);
      if (this.child === child) child.kill('SIGKILL');
      await Promise.race([exit, new Promise<void>((_, reject) => setTimeout(() => reject(new Error('本地服务未确认退出，已停止后续数据操作。')), 5_000))]);
    }
    if (this.child === child) throw new Error('本地服务尚未退出。');
  }

  private request(type: string, values: Record<string, unknown>, timeoutMs = 120_000): Promise<DesktopResult> {
    const child = this.child;
    if (!child || child.stdin.destroyed) return Promise.reject(new Error('本地服务未运行。'));
    const requestId = randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.requests.delete(requestId); reject(new Error('本地服务操作超时。')); }, timeoutMs);
      this.requests.set(requestId, { resolve, reject, timer });
      child.stdin.write(JSON.stringify({ type, requestId, ...values }) + '\n', (error) => {
        if (error) { clearTimeout(timer); this.requests.delete(requestId); reject(new Error('本地控制管道已关闭。')); }
      });
    });
  }

  async snapshot(destination: string): Promise<SnapshotResult> {
    if (this.currentStatus.phase !== 'ready') throw new Error('请等待本地服务就绪后再备份。');
    const response = await this.request('backup', { destination });
    if (!response.success || !response.data || typeof response.data !== 'object') throw new Error(response.message || '创建一致备份失败。');
    const data = response.data as SnapshotResult;
    if (data.snapshotDirectory !== destination || data.databasePath !== path.join(destination, 'data', 'ssl-manager.db') || data.keysDirectory !== path.join(destination, 'keys'))
      throw new Error('本地快照返回了不一致的位置。');
    return data;
  }

  /** 每次重启只向当前实例注入内存令牌；跨端口、重定向和外部链接均不携带。 */
  authorize(url: string, headers: Record<string, string>): Record<string, string> {
    const result: Record<string, string> = {};
    for (const [name, value] of Object.entries(headers)) if (name.toLowerCase() !== desktopTokenHeader.toLowerCase()) result[name] = value;
    try { if (this.token && this.currentOrigin && new URL(url).origin === this.currentOrigin) result[desktopTokenHeader] = this.token; } catch { /* 无效 URL 不授予本地凭证。 */ }
    return result;
  }

  private redact(value: string): string { return this.token ? value.replaceAll(this.token, '[desktop-token]') : value; }
  private async log(value: string): Promise<void> {
    try { await appendFile(this.options.logsFile, `[${new Date().toISOString()}] ${this.redact(value).slice(0, 16_384)}\n`, { mode: 0o600 }); }
    catch { /* 日志失败不输出原始异常和秘密。 */ }
  }
}
