import type { Certificate, CloudAccount, DnsZone } from './types';

export const acmeDirectories = {
  production: 'https://acme-v02.api.letsencrypt.org/directory',
  staging: 'https://acme-staging-v02.api.letsencrypt.org/directory',
};

export function certificateEnvironmentName(certificate: Pick<Certificate, 'isStaging'>) {
  return certificate.isStaging ? 'Staging 测试环境' : '生产环境';
}

export function certificateUsage(certificate: Certificate) {
  if (certificate.isStaging) return 'Let’s Encrypt 测试环境证书不受公网客户端信任，不能用于正式部署。';
  if (certificate.hasPrivateKey === false && certificate.provider === 'Acme') return '当前实例未保存匹配的私钥，不能下载或部署。';
  return '用于公网客户端与服务器之间的 TLS。';
}

/** 后端能力为准；旧版腾讯/阿里接口缺少字段时保留原行为，新平台缺字段时关闭写操作。 */
export function certificateCapabilities(certificate?: Certificate) {
  if (!certificate) return { download: false, deploy: false, revoke: false, cancel: false, remove: false };
  const legacy = certificate.provider === 'TencentCloud' || certificate.provider === 'Aliyun';
  const issued = certificate.status === 'Issued';
  const mutable = certificate.provider !== 'Cloudflare';
  return {
    download: mutable && issued && (certificate.canDownload ?? legacy),
    deploy: mutable && issued && !certificate.isStaging && (certificate.canDeploy ?? legacy),
    revoke: mutable && issued && (certificate.canRevoke ?? legacy),
    cancel: mutable && ['PendingValidation', 'Processing'].includes(certificate.status) && (certificate.canCancel ?? legacy),
    remove: mutable && ['Expired', 'Revoked', 'Cancelled'].includes(certificate.status) && (certificate.canDelete ?? true),
  };
}

export function certificateDownloadFormats(certificate: Certificate) {
  const legacy = certificate.provider === 'TencentCloud' || certificate.provider === 'Aliyun';
  const formats = certificate.downloadFormats ?? (legacy ? ['nginx', 'apache', 'iis', ...(certificate.provider === 'Aliyun' ? ['pem', 'pfx'] : ['tomcat'])] : []);
  const names: Record<string, string> = { nginx: 'Nginx', apache: 'Apache', iis: 'IIS', tomcat: 'Tomcat', pem: 'PEM', pfx: 'PFX' };
  return formats.filter((format) => format in names).map((key) => ({ key, label: names[key] }));
}

/** 托管 DNS 可以来自独立账号，只展示已启用账号中覆盖目标域名的区域。 */
export function matchingDnsZones(zones: DnsZone[], accounts: CloudAccount[], domain: string) {
  const name = domain.trim().toLowerCase().replace(/\.+$/, '');
  return zones.filter((zone) => {
    const suffix = (zone.name || zone.domain || '').toLowerCase().replace(/\.+$/, '');
    return suffix && zone.status !== 'NotPresent' && accounts.some((account) => account.id === zone.accountId && account.enabled && account.useForDns) && (!name || name === suffix || name.endsWith(`.${suffix}`));
  }).sort((a, b) => (b.name || b.domain || '').length - (a.name || a.domain || '').length);
}

export function dnsZoneLabel(zone: DnsZone, accounts: CloudAccount[]) {
  const account = accounts.find((item) => item.id === zone.accountId);
  return `${zone.name || zone.domain} · ${account?.name || zone.accountName || zone.accountId} / ${zone.provider}`;
}
