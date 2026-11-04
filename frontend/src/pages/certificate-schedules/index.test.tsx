import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { Modal } from 'antd';
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type CertificateSchedule,
  certificateScheduleApi,
} from '@/services/ssl-manager/certificateSchedule';
import CertificateSchedules from './index';

vi.mock('@/components/ssl-manager', () => ({
  tableResult: (result: any) => ({
    data: result.data?.items || [],
    total: result.data?.total || 0,
    success: result.success,
  }),
  useResultMessage: () => (result: any) => result.success,
  useTablePreferences: () => ({}),
}));
vi.mock('@/services/ssl-manager/certificateSchedule', () => ({
  certificateScheduleApi: {
    list: vi.fn(),
    get: vi.fn(),
    status: vi.fn(),
    run: vi.fn(),
  },
}));
vi.mock('./ScheduleForm', () => ({
  default: ({ open, schedule }: any) =>
    open ? <div>计划表单：{schedule?.name || '新计划'}</div> : null,
}));
vi.mock('./RunHistory', () => ({
  default: ({ schedule }: any) =>
    schedule ? <div>运行历史：{schedule.name}</div> : null,
  ScheduleStateTag: ({ state }: any) => <span>{state}</span>,
}));
vi.mock('@ant-design/pro-components', async () => {
  const ReactModule = await import('react');
  return {
    PageContainer: ({ children }: any) => <div>{children}</div>,
    ProTable: ({ request, columns, toolBarRender }: any) => {
      const [rows, setRows] = ReactModule.useState<any[]>([]);
      ReactModule.useEffect(() => {
        request({ current: 1, pageSize: 20 }).then((result: any) =>
          setRows(result.data),
        );
      }, []);
      return (
        <div>
          {toolBarRender?.()}
          {rows.map((row) => (
            <div key={row.id}>
              {columns.map((column: any, index: number) => (
                <div key={column.title || index}>
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
const success = <T,>(data: T) => ({
  success: true,
  code: 'OK',
  message: '',
  data,
});
const schedule = {
  id: 'schedule',
  name: 'VPN续签',
  domain: 'vpn.example.com',
  accountId: 'account',
  accountName: '测试账号',
  targetIds: ['target'],
  enabled: true,
  intervalValue: 1,
  intervalUnit: 'month',
  revokeOldCertificates: true,
  nextRunAtUtc: '2026-12-01T18:00:00Z',
} as CertificateSchedule;

describe('计划列表与实际执行授权', () => {
  let confirmation: any;
  beforeEach(() => {
    vi.clearAllMocks();
    confirmation = undefined;
    vi.spyOn(Modal, 'confirm').mockImplementation((options) => {
      confirmation = options;
      return { destroy: vi.fn(), update: vi.fn() };
    });
    vi.mocked(certificateScheduleApi.list).mockResolvedValue(
      success({ items: [schedule], total: 1, page: 1, pageSize: 20 }),
    );
    vi.mocked(certificateScheduleApi.get).mockResolvedValue(success(schedule));
    vi.mocked(certificateScheduleApi.status).mockResolvedValue(
      success(schedule),
    );
    vi.mocked(certificateScheduleApi.run).mockResolvedValue(
      success({ id: 'run' }) as any,
    );
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('新建与编辑读取计划表单，不触发证书申请或立即运行', async () => {
    render(<CertificateSchedules />);
    fireEvent.click(
      await screen.findByRole('button', { name: /新建计划任务/ }),
    );
    expect(screen.getByText('计划表单：新计划')).toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: '编辑' }));
    await screen.findByText('计划表单：VPN续签');
    expect(certificateScheduleApi.get).toHaveBeenCalledWith(schedule.id);
    expect(certificateScheduleApi.run).not.toHaveBeenCalled();
  });
  it('立即执行先展示具体计划确认，确认后仅提交一次原计划并打开历史', async () => {
    render(<CertificateSchedules />);
    fireEvent.click(await screen.findByRole('button', { name: '立即执行' }));
    expect(confirmation.title).toBe('立即执行一次 · VPN续签');
    expect(certificateScheduleApi.run).not.toHaveBeenCalled();
    await act(async () => {
      await confirmation.onOk();
    });
    expect(certificateScheduleApi.run).toHaveBeenCalledExactlyOnceWith(
      schedule.id,
    );
    expect(screen.getByText('运行历史：VPN续签')).toBeInTheDocument();
  });
  it('停用立即调用状态接口，重新启用需明确确认自动申请部署范围', async () => {
    vi.mocked(certificateScheduleApi.list).mockResolvedValue(
      success({
        items: [{ ...schedule, enabled: false }],
        total: 1,
        page: 1,
        pageSize: 20,
      }),
    );
    render(<CertificateSchedules />);
    fireEvent.click(await screen.findByRole('button', { name: '启用' }));
    expect(confirmation.title).toBe('启用计划 · VPN续签');
    expect(certificateScheduleApi.status).not.toHaveBeenCalled();
    await act(async () => {
      await confirmation.onOk();
    });
    expect(certificateScheduleApi.status).toHaveBeenCalledExactlyOnceWith(
      schedule.id,
      true,
    );
  });
  it('已有活跃轮次时禁用立即执行，防止从页面重复启动', async () => {
    vi.mocked(certificateScheduleApi.list).mockResolvedValue(
      success({
        items: [
          {
            ...schedule,
            latestRun: {
              active: true,
              status: 'NeedsAttention',
              cleanupStatus: 'Pending',
              message: '结果待核对',
            } as any,
          },
        ],
        total: 1,
        page: 1,
        pageSize: 20,
      }),
    );
    render(<CertificateSchedules />);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '立即执行' })).toBeDisabled(),
    );
    expect(certificateScheduleApi.run).not.toHaveBeenCalled();
  });
});
