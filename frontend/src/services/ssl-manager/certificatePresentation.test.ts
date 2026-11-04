import { describe, expect, it } from 'vitest';
import { certificateCapabilities, certificateDownloadFormats, certificateEnvironmentName, matchingDnsZones } from './certificatePresentation';
import type { Certificate, CloudAccount, DnsZone } from './types';

const certificate: Certificate = { id: 'cert', accountId: 'acme', provider: 'Acme', domain: 'test.example.com', status: 'Issued' };

describe('证书用途和可操作能力', () => {
  it('Cloudflare 账号只用于 DNS，即使带证书能力也不开放证书操作', () => {
    expect(certificateCapabilities({ ...certificate, provider: 'Cloudflare', canDownload: true, canDeploy: true, canRevoke: true })).toEqual({ download: false, deploy: false, revoke: false, cancel: false, remove: false });
  });

  it('缺少私钥的新平台不会根据已签发状态自动显示下载/部署能力', () => {
    expect(certificateCapabilities(certificate)).toMatchObject({ download: false, deploy: false, revoke: false });
    expect(certificateDownloadFormats(certificate)).toEqual([]);
  });

  it('Staging 允许按能力下载检查，但不能部署；新平台不冒出Tomcat格式', () => {
    const staging = { ...certificate, provider: 'Acme', isStaging: true, canDownload: true, canDeploy: true, downloadFormats: ['nginx', 'pem', 'unsupported'] } as Certificate;
    expect(certificateCapabilities(staging)).toMatchObject({ download: true, deploy: false });
    expect(certificateDownloadFormats(staging).map((item) => item.key)).toEqual(['nginx', 'pem']);
    expect(certificateEnvironmentName(staging)).toContain('Staging');
  });

  it('旧腾讯/阿里接口仍保留已有下载与部署能力', () => {
    expect(certificateCapabilities({ ...certificate, provider: 'TencentCloud' })).toMatchObject({ download: true, deploy: true, revoke: true });
  });

  it('独立 DNS 账号按域名边界匹配，排除停用、无 DNS 用途与已消失区域', () => {
    const accounts = [
      { id: 'cf', enabled: true, useForDns: true },
      { id: 'disabled', enabled: false, useForDns: true },
      { id: 'cert-only', enabled: true, useForDns: false },
    ] as CloudAccount[];
    const zones = [
      { id: 'root', accountId: 'cf', name: 'example.com' },
      { id: 'child', accountId: 'cf', name: 'sub.example.com' },
      { id: 'lookalike', accountId: 'cf', name: 'ample.com' },
      { id: 'disabled', accountId: 'disabled', name: 'example.com' },
      { id: 'cert-only', accountId: 'cert-only', name: 'example.com' },
      { id: 'missing', accountId: 'cf', name: 'example.com', status: 'NotPresent' },
    ] as DnsZone[];
    expect(matchingDnsZones(zones, accounts, 'TEST.SUB.EXAMPLE.COM.').map((item) => item.id)).toEqual(['child', 'root']);
  });
});
