import {
  ArrowUpOutlined,
  FileOutlined,
  FolderOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import {
  Alert,
  Button,
  Input,
  Modal,
  Space,
  Table,
  Tree,
  Typography,
} from 'antd';
import type { DataNode } from 'antd/es/tree';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import type {
  RemoteDirectoryEntry,
  RemoteDirectoryListing,
} from '@/services/ssl-manager/deploymentTypes';
import type { ApiResult } from '@/services/ssl-manager/types';

export interface RemoteFileSelection {
  directory: string;
  fileName: string;
  path: string;
}

interface Props {
  open: boolean;
  mode?: 'directory' | 'file';
  initialDirectory?: string;
  initialFileName?: string;
  loadDirectory: (path: string) => Promise<ApiResult<RemoteDirectoryListing>>;
  onTrustHost?: (fingerprint: string) => void;
  onSelect: (selection: RemoteFileSelection) => void;
  onCancel: () => void;
}

function parents(path: string): string[] {
  const result = ['/'];
  let current = '';
  for (const segment of path.split('/').filter(Boolean)) {
    current += `/${segment}`;
    result.push(current);
  }
  return result;
}

function directoryTree(paths: string[]): DataNode[] {
  const nodes = new Map<string, DataNode>();
  const all = new Set(paths.flatMap(parents));
  for (const path of [...all].sort((a, b) => a.localeCompare(b))) {
    const node: DataNode = {
      key: path,
      title: path === '/' ? '/' : path.slice(path.lastIndexOf('/') + 1),
      icon: <FolderOutlined />,
      children: [],
    };
    nodes.set(path, node);
    if (path !== '/') {
      const parent = path.slice(0, path.lastIndexOf('/')) || '/';
      nodes.get(parent)?.children?.push(node);
    }
  }
  const root = nodes.get('/');
  return root ? [root] : [];
}

function hasControlCharacters(value: string): boolean {
  return [...value].some(
    (character) =>
      character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
  );
}

function sizeText(entry: RemoteDirectoryEntry): string {
  if (!entry.isRegularFile) return '—';
  if (entry.size < 1024) return `${entry.size} B`;
  if (entry.size < 1024 * 1024) return `${(entry.size / 1024).toFixed(1)} KB`;
  return `${(entry.size / 1024 / 1024).toFixed(1)} MB`;
}

/** 只浏览目录和选择目标路径；连接凭据始终由父表单管理，不传入此组件。 */
export default function RemoteFileBrowser({
  open,
  mode = 'file',
  initialDirectory = '/',
  initialFileName = '',
  loadDirectory,
  onTrustHost,
  onSelect,
  onCancel,
}: Props) {
  const [listing, setListing] = useState<RemoteDirectoryListing>();
  const [address, setAddress] = useState('/');
  const [fileName, setFileName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [challenge, setChallenge] = useState<{
    code: string;
    fingerprint: string;
  }>();
  const [knownDirectories, setKnownDirectories] = useState<string[]>(['/']);
  const [expandedKeys, setExpandedKeys] = useState<React.Key[]>(['/']);
  const requestId = useRef(0);

  const navigate = useCallback(
    async (path: string) => {
      const currentRequest = ++requestId.current;
      setAddress(path);
      setListing(undefined);
      setError('');
      setChallenge(undefined);
      if (!path.startsWith('/') || hasControlCharacters(path)) {
        setError('请输入以 / 开始的有效目录路径。');
        setLoading(false);
        return;
      }
      setLoading(true);
      try {
        const result = await loadDirectory(path);
        // 快速切换目录或关闭弹窗后，过期请求不得覆盖当前选择。
        if (requestId.current !== currentRequest) return;
        if (!result.success || !result.data) {
          setError(result.message || '无法读取远程目录。');
          if (
            ['HOST_IDENTITY_REQUIRED', 'HOST_IDENTITY_CHANGED'].includes(
              result.code,
            ) &&
            result.data?.observedFingerprint
          ) {
            setChallenge({
              code: result.code,
              fingerprint: result.data.observedFingerprint,
            });
          }
          return;
        }
        const next = result.data;
        setListing(next);
        setAddress(next.path);
        setKnownDirectories((previous) => [
          ...new Set([
            ...previous,
            next.path,
            ...next.entries
              .filter((entry) => entry.isDirectory && entry.canSelect)
              .map((entry) => entry.path),
          ]),
        ]);
        setExpandedKeys((previous) => [
          ...new Set([...previous, ...parents(next.path)]),
        ]);
      } catch {
        if (requestId.current === currentRequest)
          setError('目录读取失败，请重试。');
      } finally {
        if (requestId.current === currentRequest) setLoading(false);
      }
    },
    [loadDirectory],
  );

  useEffect(() => {
    ++requestId.current;
    setListing(undefined);
    setKnownDirectories(['/']);
    setExpandedKeys(['/']);
    setChallenge(undefined);
    setError('');
    setFileName(initialFileName);
    if (open) {
      const initial =
        initialDirectory.startsWith('/') && !initialDirectory.includes('{')
          ? initialDirectory
          : '/';
      void navigate(initial);
    }
    return () => {
      ++requestId.current;
    };
  }, [open, initialDirectory, initialFileName, navigate]);

  const choose = () => {
    if (!listing || loading || error) return;
    if (mode === 'directory') {
      onSelect({ directory: listing.path, fileName: '', path: listing.path });
      return;
    }
    if (
      !fileName.trim() ||
      /[/\\]/.test(fileName) ||
      hasControlCharacters(fileName) ||
      ['.', '..'].includes(fileName)
    ) {
      setError('请输入不含目录分隔符的有效文件名。');
      return;
    }
    const existing = listing.entries.find((entry) => entry.name === fileName);
    if (existing && (!existing.canSelect || !existing.isRegularFile)) {
      setError('该名称属于目录、符号链接或不可选择的项目，请使用其他文件名。');
      return;
    }
    onSelect({
      directory: listing.path,
      fileName,
      path: `${listing.path.replace(/\/$/, '')}/${fileName}`,
    });
  };

  return (
    <Modal
      title={mode === 'directory' ? '选择远程目录' : '选择远程目标文件'}
      open={open}
      width={1040}
      // 低高度视口仅滚动内容区，确认按钮始终保留在弹窗底部。
      style={{ top: 24, paddingBottom: 24, maxWidth: 'calc(100vw - 32px)' }}
      styles={{
        body: {
          maxHeight: 'calc(100dvh - 176px)',
          overflowY: 'auto',
          overflowX: 'hidden',
        },
      }}
      onCancel={() => {
        ++requestId.current;
        onCancel();
      }}
      onOk={choose}
      okText={mode === 'directory' ? '选择此目录' : '使用此目标文件'}
      cancelText="取消"
      okButtonProps={{ disabled: loading || !listing || !!error }}
    >
      {error && (
        <Alert
          type="error"
          title={error}
          showIcon
          style={{ marginBottom: 12 }}
        />
      )}
      {challenge && (
        <Alert
          type="warning"
          showIcon
          title={
            challenge.code === 'HOST_IDENTITY_CHANGED'
              ? 'SSH 主机指纹已变化'
              : '首次连接，请核对 SSH 主机指纹'
          }
          description={
            <Space orientation="vertical">
              <Typography.Text code>{challenge.fingerprint}</Typography.Text>
              {challenge.code === 'HOST_IDENTITY_REQUIRED' && onTrustHost ? (
                <Button
                  onClick={() => {
                    onTrustHost(challenge.fingerprint);
                    void navigate(address);
                  }}
                >
                  确认信任并继续
                </Button>
              ) : (
                <span>请核对服务器身份后在连接配置中更新指纹。</span>
              )}
            </Space>
          }
          style={{ marginBottom: 12 }}
        />
      )}
      <Space.Compact style={{ width: '100%', marginBottom: 12 }}>
        <Button
          aria-label="上一级目录"
          icon={<ArrowUpOutlined />}
          disabled={!listing || listing.path === '/'}
          onClick={() => {
            if (listing) void navigate(listing.parentPath);
          }}
        />
        <Input
          aria-label="远程目录路径"
          value={address}
          onChange={(event) => setAddress(event.target.value)}
          onPressEnter={() => void navigate(address)}
        />
        <Button aria-label="前往" onClick={() => void navigate(address)}>
          前往
        </Button>
        <Button
          aria-label="刷新远程目录"
          icon={<ReloadOutlined />}
          onClick={() => void navigate(listing?.path || address)}
          loading={loading}
        />
      </Space.Compact>
      <div style={{ display: 'flex', gap: 16, minHeight: 0 }}>
        <div
          style={{
            width: 210,
            flexShrink: 0,
            maxHeight: 'clamp(160px, calc(100dvh - 320px), 390px)',
            overflow: 'auto',
            borderRight: '1px solid #f0f0f0',
          }}
        >
          <Tree
            aria-label="远程目录树"
            style={{
              width: 'max-content',
              minWidth: '100%',
              whiteSpace: 'nowrap',
            }}
            showIcon
            treeData={directoryTree(knownDirectories)}
            selectedKeys={listing ? [listing.path] : []}
            expandedKeys={expandedKeys}
            onExpand={(keys) => setExpandedKeys(keys)}
            onSelect={(keys) => {
              if (keys[0]) void navigate(String(keys[0]));
            }}
          />
        </div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <Table<RemoteDirectoryEntry>
            rowKey="path"
            tableLayout="fixed"
            size="small"
            loading={loading}
            dataSource={listing?.entries || []}
            pagination={false}
            scroll={{ y: 'clamp(140px, calc(100dvh - 380px), 340px)' }}
            locale={{ emptyText: '此目录为空或尚未读取' }}
            onRow={(entry) => ({
              onClick: () => {
                if (mode === 'file' && entry.isRegularFile && entry.canSelect) {
                  setFileName(entry.name);
                  setError('');
                }
              },
            })}
            columns={[
              {
                title: '名称',
                dataIndex: 'name',
                ellipsis: { showTitle: false },
                render: (_, entry) => (
                  <Button
                    aria-label={entry.name}
                    title={entry.name}
                    type="link"
                    style={{
                      paddingInline: 0,
                      width: '100%',
                      maxWidth: '100%',
                      minWidth: 0,
                      overflow: 'hidden',
                      justifyContent: 'flex-start',
                    }}
                    disabled={
                      !entry.canSelect ||
                      (mode === 'directory' && !entry.isDirectory)
                    }
                    icon={
                      entry.isDirectory ? <FolderOutlined /> : <FileOutlined />
                    }
                    onClick={() => {
                      if (entry.isDirectory) void navigate(entry.path);
                      else {
                        setFileName(entry.name);
                        setError('');
                      }
                    }}
                  >
                    <span
                      style={{
                        minWidth: 0,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {entry.name}
                    </span>
                  </Button>
                ),
              },
              {
                title: '大小',
                width: 90,
                render: (_, entry) => sizeText(entry),
              },
              {
                title: '类型',
                width: 110,
                render: (_, entry) =>
                  entry.isSymbolicLink
                    ? '符号链接'
                    : entry.isDirectory
                      ? '文件夹'
                      : entry.isRegularFile
                        ? '文件'
                        : '其他',
              },
              {
                title: '修改时间',
                width: 165,
                render: (_, entry) =>
                  entry.modifiedAtUtc
                    ? new Date(entry.modifiedAtUtc).toLocaleString()
                    : '—',
              },
            ]}
          />
        </div>
      </div>
      {listing?.truncated && (
        <Alert
          type="warning"
          title="目录内容较多，列表已截断；可直接输入路径定位。"
          style={{ marginTop: 12 }}
        />
      )}
      {mode === 'file' && (
        <div style={{ marginTop: 16 }}>
          <label htmlFor="remote-target-file-name">目标文件名</label>
          <Input
            id="remote-target-file-name"
            value={fileName}
            onChange={(event) => {
              setFileName(event.target.value);
              setError('');
            }}
            placeholder="选择已有文件，或输入新文件名"
            style={{ marginTop: 6 }}
          />
          <div style={{ color: '#666', marginTop: 6 }}>
            选择仅回填部署路径；文件将在提交部署后写入。
          </div>
        </div>
      )}
    </Modal>
  );
}
