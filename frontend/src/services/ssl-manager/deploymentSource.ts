import type { Certificate } from './types';

/** 与后端主域名规则保持一致；不把通配域名扩展为其他业务域名。 */
export function normalizeDeploymentDomain(value?: string): string {
  const normalize = (domain: string) => domain.trim().replace(/\.+$/, '').toLowerCase();
  const domains = (value || '')
    .split(/[,;\s]+/)
    .map(normalize)
    .filter((domain) => {
      const labels = domain.split('.');
      const isIpv4 = labels.length === 4 && labels.every((label) => /^\d+$/.test(label) && Number(label) <= 255);
      return domain.length <= 253 && labels.length > 1 && !isIpv4 && labels.every((label) =>
        label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
    });
  return domains.find((domain) => !domain.startsWith('www.')) || domains[0] || normalize(value || '');
}

/** 每个域名仅保留最新已签发证书，证书 ID 仅用于本次读取源文件。 */
export function latestDeploymentCertificates(certificates: Certificate[]) {
  const time = (value?: string) => {
    const timestamp = value ? Date.parse(value) : 0;
    return Number.isFinite(timestamp) ? timestamp : 0;
  };
  const ordered = certificates
    .filter((certificate) => certificate.status === 'Issued')
    .toSorted(
      (left, right) =>
        time(right.notAfterUtc || right.notAfter || right.expiresAt) -
          time(left.notAfterUtc || left.notAfter || left.expiresAt) ||
        time(right.notBeforeUtc || right.notBefore || right.issuedAt) -
          time(left.notBeforeUtc || left.notBefore || left.issuedAt) ||
        right.id.localeCompare(left.id),
    );
  const latest = new Map<string, Certificate>();
  for (const certificate of ordered) {
    const domain = normalizeDeploymentDomain(certificate.domain);
    if (domain && !latest.has(domain)) latest.set(domain, certificate);
  }
  return latest;
}
