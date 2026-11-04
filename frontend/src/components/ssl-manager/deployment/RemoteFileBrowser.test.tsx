import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import type {
  RemoteDirectoryEntry,
  RemoteDirectoryListing,
} from '@/services/ssl-manager/deploymentTypes';
import type { ApiResult } from '@/services/ssl-manager/types';
import RemoteFileBrowser from './RemoteFileBrowser';

const entry = (path: string, directory = false): RemoteDirectoryEntry => ({
  name: path.split('/').pop() || '/',
  path,
  isDirectory: directory,
  isSymbolicLink: false,
  isRegularFile: !directory,
  size: directory ? 0 : 1024,
  modifiedAtUtc: '2026-11-01T06:00:00Z',
  canSelect: true,
});
const listing = (
  path: string,
  entries: RemoteDirectoryEntry[] = [],
): ApiResult<RemoteDirectoryListing> => ({
  success: true,
  code: 'OK',
  message: '',
  data: {
    path,
    parentPath: path.slice(0, path.lastIndexOf('/')) || '/',
    entries,
    truncated: false,
    observedFingerprint: 'SHA256:test',
  },
});

describe('远程文件浏览器', () => {
  it('可导航目录并选择已有文件，路径由当前目录和文件名组成', async () => {
    const loadDirectory = vi
      .fn()
      .mockResolvedValueOnce(listing('/', [entry('/conf', true)]))
      .mockResolvedValueOnce(listing('/conf', [entry('/conf/vpn.crt')]));
    const onSelect = vi.fn();
    render(
      <RemoteFileBrowser
        open
        loadDirectory={loadDirectory}
        onSelect={onSelect}
        onCancel={vi.fn()}
      />,
    );
    fireEvent.click(await screen.findByRole('button', { name: 'conf' }));
    fireEvent.click(await screen.findByRole('button', { name: 'vpn.crt' }));
    fireEvent.click(screen.getByRole('button', { name: '使用此目标文件' }));
    expect(onSelect).toHaveBeenCalledWith({
      directory: '/conf',
      fileName: 'vpn.crt',
      path: '/conf/vpn.crt',
    });
    expect(loadDirectory.mock.calls.map((call) => call[0])).toEqual([
      '/',
      '/conf',
    ]);
  });

  it('可在空目录输入新文件名，选择不会写入远端', async () => {
    const loadDirectory = vi.fn().mockResolvedValue(listing('/conf'));
    const onSelect = vi.fn();
    render(
      <RemoteFileBrowser
        open
        initialDirectory="/conf"
        loadDirectory={loadDirectory}
        onSelect={onSelect}
        onCancel={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: '使用此目标文件' }),
      ).not.toBeDisabled(),
    );
    fireEvent.change(screen.getByLabelText('目标文件名'), {
      target: { value: 'vpn.key' },
    });
    fireEvent.click(screen.getByRole('button', { name: '使用此目标文件' }));
    expect(onSelect).toHaveBeenCalledWith({
      directory: '/conf',
      fileName: 'vpn.key',
      path: '/conf/vpn.key',
    });
    expect(loadDirectory).toHaveBeenCalledTimes(1);
  });

  it('首次指纹必须点击确认才重试，已变化指纹没有自动信任入口', async () => {
    const identity = {
      ...listing('/'),
      success: false,
      code: 'HOST_IDENTITY_REQUIRED',
      message: '请核对主机指纹',
    };
    const loadDirectory = vi
      .fn()
      .mockResolvedValueOnce(identity)
      .mockResolvedValueOnce(listing('/'));
    const onTrustHost = vi.fn();
    const view = render(
      <RemoteFileBrowser
        open
        loadDirectory={loadDirectory}
        onTrustHost={onTrustHost}
        onSelect={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    await screen.findByText('首次连接，请核对 SSH 主机指纹');
    expect(onTrustHost).not.toHaveBeenCalled();
    expect(loadDirectory).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: '确认信任并继续' }));
    await waitFor(() => expect(loadDirectory).toHaveBeenCalledTimes(2));
    expect(onTrustHost).toHaveBeenCalledWith('SHA256:test');
    const changed = vi
      .fn()
      .mockResolvedValue({ ...identity, code: 'HOST_IDENTITY_CHANGED' });
    view.rerender(
      <RemoteFileBrowser
        open
        loadDirectory={changed}
        onTrustHost={onTrustHost}
        onSelect={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    await screen.findByText('SSH 主机指纹已变化');
    expect(
      screen.queryByRole('button', { name: '确认信任并继续' }),
    ).not.toBeInTheDocument();
    expect(onTrustHost).toHaveBeenCalledTimes(1);
  });

  it('后到的旧目录响应不会覆盖新目录', async () => {
    let resolveOld: (result: ApiResult<RemoteDirectoryListing>) => void =
      () => {};
    const loadDirectory = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveOld = resolve;
          }),
      )
      .mockResolvedValueOnce(listing('/new', [entry('/new/new.crt')]));
    render(
      <RemoteFileBrowser
        open
        loadDirectory={loadDirectory}
        onSelect={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    fireEvent.change(screen.getByLabelText('远程目录路径'), {
      target: { value: '/new' },
    });
    fireEvent.click(screen.getByRole('button', { name: '前往' }));
    await screen.findByRole('button', { name: 'new.crt' });
    await act(async () => resolveOld(listing('/', [entry('/old.crt')])));
    expect(screen.getByLabelText('远程目录路径')).toHaveValue('/new');
    expect(
      screen.queryByRole('button', { name: 'old.crt' }),
    ).not.toBeInTheDocument();
  });

  it('无权限目录不能复用上次成功目录提交，符号链接不能选择', async () => {
    const link = {
      ...entry('/linked.key'),
      isSymbolicLink: true,
      canSelect: false,
    };
    const loadDirectory = vi
      .fn()
      .mockResolvedValueOnce(listing('/', [link]))
      .mockResolvedValueOnce({
        success: false,
        code: 'PERMISSION_DENIED',
        message: '没有权限读取此目录',
      });
    render(
      <RemoteFileBrowser
        open
        loadDirectory={loadDirectory}
        onSelect={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(
      await screen.findByRole('button', { name: 'linked.key' }),
    ).toBeDisabled();
    fireEvent.change(screen.getByLabelText('远程目录路径'), {
      target: { value: '/denied' },
    });
    fireEvent.click(screen.getByRole('button', { name: '前往' }));
    await screen.findByText('没有权限读取此目录');
    fireEvent.change(screen.getByLabelText('目标文件名'), {
      target: { value: 'new.key' },
    });
    expect(
      screen.getByRole('button', { name: '使用此目标文件' }),
    ).toBeDisabled();
  });

  it('目录模式支持上一级和刷新，并返回当前目录', async () => {
    const loadDirectory = vi
      .fn()
      .mockResolvedValueOnce(listing('/conf'))
      .mockResolvedValue(listing('/'));
    const onSelect = vi.fn();
    render(
      <RemoteFileBrowser
        open
        mode="directory"
        initialDirectory="/conf"
        loadDirectory={loadDirectory}
        onSelect={onSelect}
        onCancel={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: '上一级目录' }),
      ).not.toBeDisabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '上一级目录' }));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: '选择此目录' }),
      ).not.toBeDisabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '刷新远程目录' }));
    await waitFor(() => expect(loadDirectory).toHaveBeenCalledTimes(3));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: '选择此目录' }),
      ).not.toBeDisabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '选择此目录' }));
    expect(onSelect).toHaveBeenCalledWith({
      directory: '/',
      fileName: '',
      path: '/',
    });
  });
});
