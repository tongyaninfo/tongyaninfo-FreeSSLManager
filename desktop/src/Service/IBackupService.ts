export interface IBackupService {
  export(snapshotDirectory: string, destination: string, password: string): Promise<void>;
  read(source: string, password: string): Promise<BackupManifest>;
  stage(manifest: BackupManifest, businessParent: string): Promise<string>;
}

export interface BackupFile { path: string; length: number; sha256: string; content: string }
export interface BackupManifest {
  version: 1;
  createdAtUtc: string;
  applicationVersion: string;
  files: BackupFile[];
}
