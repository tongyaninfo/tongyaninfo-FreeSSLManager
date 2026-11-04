import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type CertificateSchedule,
  type CertificateScheduleRun,
  certificateScheduleApi,
} from '@/services/ssl-manager/certificateSchedule';
import RunHistory, { RunDetail } from './RunHistory';

vi.mock('@umijs/max', () => ({ history: { push: vi.fn() } }));
vi.mock('@/components/ssl-manager', () => ({
  tableResult: (result: any) => ({
    data: result.data?.items || [],
    total: result.data?.total || 0,
    success: result.success,
  }),
  useResultMessage: () => (result: any) => result.success,
}));
vi.mock('@/services/ssl-manager/certificateSchedule', () => ({
  certificateScheduleApi: { runs: vi.fn(), resume: vi.fn(), resolve: vi.fn() },
}));
vi.mock('@ant-design/pro-components', async () => {
  const ReactModule = await import('react');
  return {
    ProTable: ({ request, columns }: any) => {
      const [rows, setRows] = ReactModule.useState<any[]>([]);
      ReactModule.useEffect(() => {
        request({ current: 1, pageSize: 10 }).then((result: any) =>
          setRows(result.data),
        );
      }, []);
      return (
        <div>
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
const run: CertificateScheduleRun = {
  id: 'run',
  scheduleId: 'schedule',
  certificateId: 'certificate',
  status: 'NeedsAttention',
  code: 'SUBMISSION_UNKNOWN',
  message: '云端申请结果需要人工核对',
  cleanupStatus: 'NeedsAttention',
  active: true,
  scheduledForUtc: '2026-12-01T18:00:00Z',
  createdAtUtc: '2026-12-01T18:00:00Z',
  nextCheckAtUtc: '2026-12-01T18:00:00Z',
  targets: [
    {
      targetId: 'target',
      targetName: 'VPN服务器',
      batchId: 'batch',
      status: 'Succeeded',
      code: 'OK',
      message: '文件已读回核对',
    },
  ],
  oldCertificates: [
    {
      certificateId: 'old-certificate',
      domain: 'vpn.example.com',
      status: 'Revoking',
      code: '',
      message: '等待云端确认吊销',
    },
  ],
};
const schedule = { id: 'schedule', name: 'VPN续签' } as CertificateSchedule;

describe('计划运行历史和独立旧证书清理结果', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(certificateScheduleApi.runs).mockResolvedValue(
      success({ items: [run], total: 1, page: 1, pageSize: 10 }),
    );
    vi.mocked(certificateScheduleApi.resume).mockResolvedValue(success(run));
    vi.mocked(certificateScheduleApi.resolve).mockResolvedValue(
      success({ ...run, active: false }),
    );
  });
  it('独立展示部署成功、旧证书等待吊销及清理需处理信息', () => {
    render(
      <RunDetail
        run={{
          ...run,
          status: 'Succeeded',
          applicationCleanupStatus: 'Running',
        }}
      />,
    );
    expect(screen.getByText('申请验证 DNS 清理')).toBeInTheDocument();
    expect(screen.getByText('清理中')).toBeInTheDocument();
    expect(screen.getAllByText('已完成').length).toBeGreaterThan(0);
    expect(screen.getByText('清理需处理')).toBeInTheDocument();
    expect(screen.getByText('等待吊销确认')).toBeInTheDocument();
    expect(screen.getByText('文件已读回核对')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: '查看部署记录' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: '查看证书' }),
    ).toBeInTheDocument();
  });
  it('重新核对只调用原轮次恢复接口', async () => {
    render(
      <RunHistory schedule={schedule} onClose={vi.fn()} onChanged={vi.fn()} />,
    );
    fireEvent.click(await screen.findByRole('button', { name: '重新核对' }));
    await waitFor(() =>
      expect(certificateScheduleApi.resume).toHaveBeenCalledWith(run.id),
    );
    expect(certificateScheduleApi.resolve).not.toHaveBeenCalled();
  });
  it('结束本轮要求明确人工处理说明，空说明不会提交', async () => {
    render(
      <RunHistory schedule={schedule} onClose={vi.fn()} onChanged={vi.fn()} />,
    );
    fireEvent.click(await screen.findByRole('button', { name: '结束本轮' }));
    fireEvent.click(screen.getByRole('button', { name: '确认结束本轮' }));
    await screen.findByText('请填写人工核对结果和结束原因');
    expect(certificateScheduleApi.resolve).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('处理说明'), {
      target: { value: '已核对云端证书和设备，没有重复提交；人工结束。' },
    });
    fireEvent.click(screen.getByRole('button', { name: '确认结束本轮' }));
    await waitFor(() =>
      expect(certificateScheduleApi.resolve).toHaveBeenCalledWith(
        run.id,
        '已核对云端证书和设备，没有重复提交；人工结束。',
      ),
    );
  });
});
