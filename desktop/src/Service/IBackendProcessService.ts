import type { BackendStatus, SnapshotResult } from '../Models/DesktopModels';

export interface IBackendProcessService {
  readonly status: BackendStatus;
  readonly origin: string | undefined;
  start(): Promise<void>;
  stop(): Promise<void>;
  snapshot(destination: string): Promise<SnapshotResult>;
  authorize(url: string, headers: Record<string, string>): Record<string, string>;
}
