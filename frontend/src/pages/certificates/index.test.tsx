import { act, fireEvent, render, screen, within } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { certificateApi } from '@/services/ssl-manager/api';
import Certificates from './index';

const mocks = vi.hoisted(() => ({
  confirm: vi.fn(),
  showResult: vi.fn((result: { success: boolean }) => result.success),
  reload: vi.fn(),
}));

vi.mock('@umijs/max', () => ({
  history: { push: vi.fn() },
  useAccess: () => ({ canAdmin: true }),
  useIntl: () => ({
    formatMessage: ({ defaultMessage }: any) => defaultMessage,
  }),
}));
vi.mock('@/services/ssl-manager/api', () => ({
  certificateApi: { list: vi.fn(), detail: vi.fn(), delete: vi.fn() },
  downloadCertificate: vi.fn(),
}));
vi.mock('@/components/ssl-manager', () => ({
  dateText: (value: string) => value || '—',
  providerNames: { Aliyun: '阿里云' },
  ReadonlyNotice: () => null,
  StatusTag: ({ value }: any) => <span>{value}</span>,
  statusNames: {},
  tableResult: (result: any) => ({ data: result.data?.items || [] }),
  useTableKeyboardPagination: () => vi.fn(),
  useTablePreferences: () => ({}),
  useCloudAccounts: () => ({ accounts: [] }),
  useResultMessage: () => mocks.showResult,
}));
vi.mock('@/components/ssl-manager/deployment/DeployModal', () => ({
  default: () => null,
}));
vi.mock('antd', () => ({
  App: { useApp: () => ({ modal: { confirm: mocks.confirm } }) },
  Alert: () => null,
  Button: ({ children, onClick, disabled }: any) => (
    <button type="button" onClick={onClick} disabled={disabled}>
      {children}
    </button>
  ),
  Descriptions: () => null,
  Dropdown: ({ children }: any) => <div>{children}</div>,
  Modal: ({ open, title, children, footer }: any) =>
    open ? (
      <div role="dialog" aria-label={title}>
        {children}
        {footer}
      </div>
    ) : null,
  Select: () => null,
  Space: ({ children }: any) => <div>{children}</div>,
  Table: () => null,
}));
vi.mock('@ant-design/pro-components', async () => {
  const ReactModule = await import('react');
  return {
    PageContainer: ({ children }: any) => <div>{children}</div>,
    ProTable: ({
      request,
      columns,
      toolBarRender,
      rowSelection,
      actionRef,
    }: any) => {
      const [rows, setRows] = ReactModule.useState<any[]>([]);
      actionRef.current = { reload: mocks.reload };
      ReactModule.useEffect(() => {
        request({ current: 1, pageSize: 20 }).then((result: any) =>
          setRows(result.data),
        );
      }, []);
      return (
        <div>
          {toolBarRender?.()}
          {rows.map((row) => (
            <div key={row.id} data-testid={row.id}>
              <input
                type="checkbox"
                aria-label={`选择 ${row.domain}`}
                checked={rowSelection.selectedRowKeys.includes(row.id)}
                onChange={(event) =>
                  rowSelection.onChange(
                    event.currentTarget.checked
                      ? [...rowSelection.selectedRowKeys, row.id]
                      : rowSelection.selectedRowKeys.filter(
                          (id: string) => id !== row.id,
                        ),
                  )
                }
              />
              {columns.map((column: any, index: number) => (
                <div key={column.dataIndex || index}>
                  {column.render
                    ? column.render(null, row)
                    : row[column.dataIndex]}
                </div>
              ))}
            </div>
          ))}
        </div>
      );
    },
  };
});

const certificates = [
  {
    id: 'certificate-1',
    domain: 'first.example.com',
    status: 'Revoked',
    provider: 'Aliyun',
  },
  {
    id: 'certificate-2',
    domain: 'second.example.com',
    status: 'Revoked',
    provider: 'Aliyun',
  },
];
const success = <T,>(data: T, message = '') => ({
  success: true,
  code: 'OK',
  message,
  data,
});
const failedItem = {
  id: 'certificate-1',
  success: false,
  code: 'Aliyun.Forbidden',
  message: '阿里云拒绝删除，请检查权限',
};

async function confirmDeletion() {
  await act(async () => {
    await mocks.confirm.mock.lastCall?.[0].onOk();
  });
}

describe('证书删除逐项结果', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(certificateApi.list).mockResolvedValue(
      success({ items: certificates, total: 2, page: 1, pageSize: 20 }) as any,
    );
    vi.mocked(certificateApi.detail).mockResolvedValue(
      success({
        certificate: certificates[0],
        validations: [],
        tasks: [],
      }) as any,
    );
  });

  it('公网 ACME 证书缺少私钥材料时关闭下载和部署', async () => {
    vi.mocked(certificateApi.list).mockResolvedValue(
      success({
        items: [
          {
            id: 'no-material',
            domain: 'test.example.com',
            provider: 'Acme',
            status: 'Issued',
            hasPrivateKey: false,
            canDownload: false,
            canDeploy: false,
          },
        ],
        total: 1,
        page: 1,
        pageSize: 20,
      }) as any,
    );
    render(<Certificates />);
    const row = await screen.findByTestId('no-material');
    expect(within(row).getByRole('button', { name: '下载' })).toBeDisabled();
    expect(within(row).getByRole('button', { name: '部署' })).toBeDisabled();
  });

  it('Staging 证书显示测试来源并禁用部署，保留后端允许的下载', async () => {
    vi.mocked(certificateApi.list).mockResolvedValue(
      success({
        items: [
          {
            id: 'staging',
            domain: 'staging.example.com',
            provider: 'Acme',
            status: 'Issued',
            isStaging: true,
            canDownload: true,
            canDeploy: true,
          },
        ],
        total: 1,
        page: 1,
        pageSize: 20,
      }) as any,
    );
    render(<Certificates />);
    const row = await screen.findByTestId('staging');
    expect(within(row).getByText(/Staging/)).toBeInTheDocument();
    expect(within(row).getByRole('button', { name: '下载' })).toBeEnabled();
    expect(within(row).getByRole('button', { name: '部署' })).toBeDisabled();
  });

  it('单张删除的批量回包即使外层成功，也展示实际失败原因', async () => {
    vi.mocked(certificateApi.delete).mockResolvedValue(success([failedItem]));
    render(<Certificates />);
    const row = await screen.findByTestId('certificate-1');
    fireEvent.click(within(row).getByRole('button', { name: '删除' }));
    await confirmDeletion();
    expect(certificateApi.delete).toHaveBeenCalledExactlyOnceWith([
      'certificate-1',
    ]);
    expect(mocks.showResult).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        message: expect.stringContaining(failedItem.message),
      }),
    );
  });

  it('详情中的逐项删除失败保留详情弹窗，方便继续核对', async () => {
    vi.mocked(certificateApi.delete).mockResolvedValue(success([failedItem]));
    render(<Certificates />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'first.example.com' }),
    );
    const dialog = await screen.findByRole('dialog', {
      name: '证书详情 · first.example.com',
    });
    fireEvent.click(within(dialog).getByRole('button', { name: '删除' }));
    await confirmDeletion();
    expect(dialog).toBeInTheDocument();
    expect(mocks.showResult).toHaveBeenCalledWith(
      expect.objectContaining({ success: false }),
    );
  });

  it('批量删除部分失败时仅保留失败项选中，并展示失败详情', async () => {
    vi.mocked(certificateApi.delete).mockResolvedValue(
      success([
        failedItem,
        {
          id: 'certificate-2',
          success: true,
          code: 'OK',
          message: '云端已删除',
        },
      ]),
    );
    render(<Certificates />);
    const first = await screen.findByRole('checkbox', {
      name: '选择 first.example.com',
    });
    const second = screen.getByRole('checkbox', {
      name: '选择 second.example.com',
    });
    fireEvent.click(first);
    fireEvent.click(second);
    fireEvent.click(screen.getByRole('button', { name: '删除已选证书' }));
    await confirmDeletion();
    expect(certificateApi.delete).toHaveBeenCalledExactlyOnceWith([
      'certificate-1',
      'certificate-2',
    ]);
    expect(first).toBeChecked();
    expect(second).not.toBeChecked();
    expect(mocks.showResult).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        message: expect.stringContaining(failedItem.message),
      }),
    );
  });

  it('删除任务已受理时显示逐项等待文案，不误报为已经删除', async () => {
    const message = '删除请求已提交，等待云端确认';
    vi.mocked(certificateApi.delete).mockResolvedValue(
      success(
        [{ id: 'certificate-1', success: true, code: 'OK', message }],
        '已删除所选证书',
      ),
    );
    render(<Certificates />);
    const row = await screen.findByTestId('certificate-1');
    fireEvent.click(within(row).getByRole('button', { name: '删除' }));
    await confirmDeletion();
    expect(mocks.showResult).toHaveBeenCalledWith(
      expect.objectContaining({ success: true }),
      message,
    );
  });

  it('缺少逐项结果时保留详情并提示核对，不将外层成功视为删除完成', async () => {
    vi.mocked(certificateApi.delete).mockResolvedValue(success([]));
    render(<Certificates />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'first.example.com' }),
    );
    const dialog = await screen.findByRole('dialog', {
      name: '证书详情 · first.example.com',
    });
    fireEvent.click(within(dialog).getByRole('button', { name: '删除' }));
    await confirmDeletion();
    expect(dialog).toBeInTheDocument();
    expect(mocks.showResult).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        message: expect.stringContaining('服务器未返回该证书的删除结果'),
      }),
    );
  });
});
