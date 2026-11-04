import { describe, expect, it } from 'vitest';
import {
  formatCertificateExpiry,
  getExpiringCertificates,
} from './certificateSummary';

const NOW = Date.parse('2026-11-02T00:00:00Z');
const DAY = 24 * 60 * 60 * 1000;

describe('首页证书到期统计', () => {
  it('超过 8 条时仍统计所有到期证书，展示列表可独立限制条数', () => {
    const certificates = Array.from({ length: 12 }, (_, index) => ({
      id: String(index),
      notAfterUtc: new Date(NOW + (12 - index) * DAY).toISOString(),
    }));
    const expiring = getExpiringCertificates(certificates, NOW);
    expect(expiring).toHaveLength(12);
    expect(expiring.slice(0, 8)).toHaveLength(8);
    expect(expiring[0].id).toBe('11');
    expect(certificates[0].id).toBe('0');
  });

  it('包含时间窗两端，排除已过期、30 天外及缺失或非法时间', () => {
    const certificates = [
      { id: 'now', notAfterUtc: new Date(NOW).toISOString() },
      { id: 'deadline', notAfterUtc: new Date(NOW + 30 * DAY).toISOString() },
      { id: 'expired', notAfterUtc: new Date(NOW - 1).toISOString() },
      { id: 'later', notAfterUtc: new Date(NOW + 30 * DAY + 1).toISOString() },
      { id: 'invalid', notAfterUtc: 'invalid' },
      { id: 'missing', notAfterUtc: undefined },
    ];
    expect(
      getExpiringCertificates(certificates, NOW).map((item) => item.id),
    ).toEqual(['now', 'deadline']);
  });
});

describe('首页证书到期时间格式', () => {
  it('固定上海时区和标准格式，UTC 零点跨日后保持双位日期时间', () => {
    expect(formatCertificateExpiry('2026-11-02T16:00:00Z')).toBe(
      '2026-11-03 00:00:00',
    );
    expect(formatCertificateExpiry('2026-11-03T00:00:00+08:00')).toBe(
      '2026-11-03 00:00:00',
    );
    expect(formatCertificateExpiry('2026-11-02T16:00:00')).toBe(
      '2026-11-03 00:00:00',
    );
  });

  it('空白、缺失或非法时间均显示占位符', () => {
    for (const value of [undefined, '', '   ', 'invalid']) {
      expect(formatCertificateExpiry(value)).toBe('—');
    }
  });
});
