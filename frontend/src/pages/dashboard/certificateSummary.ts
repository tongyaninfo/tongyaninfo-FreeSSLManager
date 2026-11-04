/** 使用完整到期集合统计；展示列表的条数限制由调用方单独处理。 */
export function getExpiringCertificates<T extends { notAfterUtc?: string }>(
  certificates: T[],
  now: number,
): T[] {
  const deadline = now + 30 * 24 * 60 * 60 * 1000;
  return certificates
    .filter((item) => {
      const timestamp = item.notAfterUtc ? Date.parse(item.notAfterUtc) : NaN;
      return (
        Number.isFinite(timestamp) && timestamp >= now && timestamp <= deadline
      );
    })
    .sort(
      (left, right) =>
        Date.parse(left.notAfterUtc ?? '') -
        Date.parse(right.notAfterUtc ?? ''),
    );
}

const expiryFormatter = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'Asia/Shanghai',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

/** Utc 字段缺少时区时按 UTC 解释；只转换一次，再拼接固定展示格式。 */
export function formatCertificateExpiry(value?: string): string {
  if (!value?.trim()) return '—';
  const text = value.trim().replace(' ', 'T');
  const date = new Date(
    /(?:Z|[+-]\d{2}:?\d{2})$/i.test(text) ? text : `${text}Z`,
  );
  if (!Number.isFinite(date.getTime())) return '—';
  const parts = Object.fromEntries(
    expiryFormatter.formatToParts(date).map((part) => [part.type, part.value]),
  );
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
}
