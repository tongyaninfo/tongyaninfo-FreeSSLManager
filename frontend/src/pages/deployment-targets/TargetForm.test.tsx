import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { certificateApi } from '@/services/ssl-manager/api';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import type {
  DeploymentExecutorDescriptor,
  DeploymentTarget,
} from '@/services/ssl-manager/deploymentTypes';
import TargetForm from './TargetForm';

vi.mock('@/components/ssl-manager', () => ({
  useResultMessage: () => () => true,
}));
vi.mock('@/services/ssl-manager/deployment', () => ({
  deploymentApi: {
    discover: vi.fn(),
    saveTarget: vi.fn(),
    browseDirectory: vi.fn(),
    sourceFiles: vi.fn(),
  },
}));
vi.mock('@/services/ssl-manager/api', () => ({
  certificateApi: { list: vi.fn() },
}));

const executors: DeploymentExecutorDescriptor[] = [
  {
    key: 'synology.dsm.7.x',
    name: '群晖 DSM 7.x',
    targetType: 'Synology',
    operatingSystem: '',
    protocol: 'HTTPS',
    revision: '1',
    supportedProductVersions: '7.x',
    available: true,
    unavailableReason: '',
    authenticationModes: ['Password'],
    supportsRollback: false,
  },
];

const target: DeploymentTarget = {
  id: 'nas-target',
  name: '群晖测试目标',
  description: '',
  executorKey: 'synology.dsm.7.x',
  executorRevision: '1',
  endpoint: 'https://nas.example.com:5443',
  port: 0,
  username: 'deploy-admin',
  authenticationMode: 'Password',
  enabled: true,
  tlsFingerprint: '',
  configRevision: 3,
  configuration: {
    siteIds: [],
    remoteCertificateId: 'cert-1',
    certificateDescription: '',
    bindSites: false,
    operatingSystem: '',
    shell: '',
    outputDirectory: '',
    files: [],
    validationCommands: [],
    postCommands: [],
    hostKeyFingerprint: '',
    createDirectory: false,
    verificationHost: '',
    verificationPort: 443,
    verificationServerName: '',
    connectionTimeoutSeconds: 30,
    operationTimeoutSeconds: 120,
  },
  passwordConfigured: true,
  apiTokenConfigured: false,
  privateKeyConfigured: false,
  pfxPasswordConfigured: false,
  lastTestMessage: '',
  productVersion: '7.2',
  lastDeploymentStatus: '',
};

describe('群晖部署目标配置', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(deploymentApi.saveTarget).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: target,
    });
  });

  it('新增群晖目标只显示 HTTPS 和证书配置，并保留地址中的自定义端口', async () => {
    render(
      <TargetForm
        open
        executors={executors}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await screen.findByText('支持 DSM 7.x 管理员账号密码登录');
    expect(screen.queryByLabelText('SSH 主机密钥指纹')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('证书输出目录')).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText('上传后更新已有站点绑定'),
    ).not.toBeInTheDocument();
    expect(screen.queryByText('添加后置命令')).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: '读取群晖证书和服务' }),
    ).toBeDisabled();
    fireEvent.change(screen.getByLabelText('目标名称'), {
      target: { value: 'NAS 证书' },
    });
    fireEvent.change(screen.getByLabelText('管理地址'), {
      target: { value: 'https://nas.example.com:7443' },
    });
    fireEvent.change(screen.getByLabelText('用户名'), {
      target: { value: 'deploy-admin' },
    });
    fireEvent.change(screen.getByLabelText('密码'), {
      target: { value: 'test-password' },
    });
    fireEvent.change(screen.getByLabelText('证书描述'), {
      target: { value: '门户证书' },
    });
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
      undefined,
      expect.objectContaining({
        endpoint: 'https://nas.example.com:7443',
        port: 0,
        authenticationMode: 'Password',
        configuration: expect.objectContaining({
          certificateDescription: '门户证书',
          remoteCertificateId: '',
          bindSites: false,
          siteIds: [],
          files: [],
          postCommands: [],
        }),
      }),
    );
  });

  it('读取已保存目标并显示所选证书关联服务，保存时空密码保留原值', async () => {
    vi.mocked(deploymentApi.discover).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: {
        certificates: [
          {
            id: 'cert-1',
            name: 'NAS 证书',
            domains: ['nas.example.com'],
            fingerprint: '',
            relatedSiteIds: ['DSM'],
          },
        ],
        sites: [
          {
            id: 'DSM',
            name: 'DSM 管理服务',
            domains: [],
            certificateId: 'cert-1',
          },
        ],
        productVersion: '7.2',
      },
    });
    render(
      <TargetForm
        open
        target={target}
        executors={executors}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await screen.findByDisplayValue('https://nas.example.com:5443');
    expect(screen.getByLabelText('密码')).toHaveValue('');
    expect(screen.getByLabelText('证书描述')).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: '读取群晖证书和服务' }));
    await screen.findByText(/当前关联服务：DSM 管理服务/);
    expect(deploymentApi.discover).toHaveBeenCalledWith('nas-target');
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
      'nas-target',
      expect.objectContaining({
        password: '',
        configRevision: 3,
        configuration: expect.objectContaining({
          remoteCertificateId: 'cert-1',
          bindSites: false,
          siteIds: [],
        }),
      }),
    );
  });

  it('已保存的远端证书不存在时仍可设置自动匹配描述并保存', async () => {
    vi.mocked(deploymentApi.discover).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: { certificates: [], sites: [], productVersion: '7.2' },
    });
    render(
      <TargetForm
        open
        target={target}
        executors={executors}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await screen.findByDisplayValue('https://nas.example.com:5443');
    fireEvent.click(screen.getByRole('button', { name: '读取群晖证书和服务' }));
    await screen.findByText(/当前关联服务：无/);
    const description = screen.getByLabelText('证书描述');
    expect(description).toBeEnabled();
    fireEvent.change(description, { target: { value: 'nas.example.com' } });
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
        'nas-target',
        expect.objectContaining({
          configuration: expect.objectContaining({
            remoteCertificateId: 'cert-1',
            certificateDescription: 'nas.example.com',
          }),
        }),
      ),
    );
  });

  it('群晖表单扩展不会清除已有雷池目标的独立端口', async () => {
    const safeline = {
      ...target,
      executorKey: 'safeline.ce.9.x',
      endpoint: 'https://waf.example.com',
      port: 9443,
    };
    render(
      <TargetForm
        open
        target={safeline}
        executors={[
          {
            ...executors[0],
            key: 'safeline.ce.9.x',
            name: '雷池社区版 9.x.x',
            targetType: 'SafeLine',
          },
        ]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await screen.findByDisplayValue('https://waf.example.com');
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
      'nas-target',
      expect.objectContaining({
        endpoint: 'https://waf.example.com',
        port: 9443,
      }),
    );
  });

  it.each([
    'synology.dsm.7.x',
    'safeline.ce.9.x',
  ])('%s 隐藏管理证书指纹并保留旧值，业务 HTTPS 验证配置独立保存', async (executorKey) => {
    const configuration = {
      ...target.configuration,
      verificationHost: '192.0.2.10',
      verificationPort: 8443,
      verificationServerName: 'nas.example.com',
    };
    render(
      <TargetForm
        open
        target={{
          ...target,
          executorKey,
          tlsFingerprint: 'A'.repeat(64),
          configuration,
        }}
        executors={[{ ...executors[0], key: executorKey }]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await screen.findByText('管理连接默认忽略对端证书校验错误');
    const platformName = executorKey.startsWith('synology.') ? '群晖' : '雷池';
    expect(
      screen.getByText(
        `${platformName}证书和证书链上传并读回一致即部署成功；业务 HTTPS 检查仅作提示，不影响部署结果。`,
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByLabelText('管理端 SHA-256 证书指纹'),
    ).not.toBeInTheDocument();
    expect(screen.getByLabelText('连接主机或 IP')).toHaveValue('192.0.2.10');
    expect(screen.getByLabelText('SNI 域名')).toHaveValue('nas.example.com');
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
      target.id,
      expect.objectContaining({
        tlsFingerprint: 'A'.repeat(64),
        configuration: expect.objectContaining({
          verificationHost: '192.0.2.10',
          verificationPort: 8443,
          verificationServerName: 'nas.example.com',
        }),
      }),
    );
  });

  it.each([
    ['SSH', 'linux.ssh', 'SSH 主机密钥指纹'],
    ['WinRM', 'windows.winrm', '管理端 SHA-256 证书指纹'],
  ])('%s 目标仍保留原有身份校验字段', async (protocol, key, label) => {
    render(
      <TargetForm
        open
        executors={[{ ...executors[0], protocol, key }]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await screen.findByLabelText(label);
    expect(
      screen.queryByText('管理连接默认忽略对端证书校验错误'),
    ).not.toBeInTheDocument();
  });

  it.each([
    ['https://nas.example.com', 7443, 'https://nas.example.com:7443'],
    ['https://nas.example.com', 443, 'https://nas.example.com:443'],
    ['https://nas.example.com:443', 5001, 'https://nas.example.com:443'],
    ['https://[2001:db8::1]/dsm', 7443, 'https://[2001:db8::1]:7443/dsm'],
  ])('编辑群晖地址 %s 时保留有效端口 %i', async (endpoint, port, expected) => {
    render(
      <TargetForm
        open
        target={{ ...target, endpoint, port }}
        executors={executors}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await screen.findByDisplayValue(expected);
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
      'nas-target',
      expect.objectContaining({
        endpoint: expected,
        port: 0,
      }),
    );
  });
});

const linuxExecutor: DeploymentExecutorDescriptor = {
  ...executors[0],
  key: 'linux.files.ssh.v1',
  name: 'Linux SSH 文件部署',
  operatingSystem: 'Linux',
  protocol: 'SSH',
  authenticationModes: ['Password', 'PrivateKey'],
};

const harborExecutor: DeploymentExecutorDescriptor = {
  ...linuxExecutor,
  key: 'harbor.compose.ssh.v1',
  name: 'Harbor 2.x Docker Compose',
  targetType: 'Harbor',
  supportedProductVersions: '2.x',
};

describe('Harbor 部署目标配置', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(deploymentApi.saveTarget).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: target,
    });
  });

  it('默认代理双文件，可成对增减源证书副本，并独立保存 SSH 和 HTTPS 端口', async () => {
    render(
      <TargetForm
        open
        executors={[harborExecutor]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await screen.findByLabelText('Harbor 安装目录');
    expect(screen.getByLabelText('Harbor 安装目录')).toHaveValue('');
    expect(screen.getByLabelText('证书输出目录')).toHaveValue('');
    expect(screen.getByLabelText('SSH 端口')).toHaveValue('22');
    expect(screen.getByLabelText('代理服务名')).toHaveValue('proxy');
    expect(screen.getAllByLabelText('材料角色')).toHaveLength(2);
    expect(screen.queryByText('添加输出文件')).not.toBeInTheDocument();
    expect(screen.queryByText('添加后置命令')).not.toBeInTheDocument();
    expect(screen.queryByText('添加配置验证命令')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('PFX 密码')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('允许创建输出目录')).not.toBeInTheDocument();
    expect(
      screen.getByText(/仅使用已存在且代理可访问的目录/),
    ).toBeInTheDocument();
    expect(screen.queryByText('读取源文件')).not.toBeInTheDocument();
    expect(screen.getByText('业务 HTTPS 生效验证（必填）')).toBeInTheDocument();
    for (const [label, value] of [
      ['目标名称', 'Harbor'],
      ['SSH 主机或 IP', '192.0.2.65'],
      ['SSH 用户名', 'root'],
      ['密码', 'test-password'],
      ['SSH 主机密钥指纹', 'SHA256:test-fingerprint'],
      ['Harbor 绑定域名', 'HARBOR.EXAMPLE.COM.'],
      ['Harbor 安装目录', '/opt/harbor'],
      ['证书输出目录', '/data/cert'],
      ['连接主机或 IP', '192.0.2.65'],
    ])
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    fireEvent.change(screen.getByLabelText('HTTPS 端口'), {
      target: { value: '8443' },
    });
    expect(screen.getByLabelText('SNI 域名')).toHaveValue(
      'harbor.example.com',
    );
    expect(screen.getByText('代理实际挂载证书（第一对）')).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', { name: '同步 Harbor 源证书副本' }),
    );
    await waitFor(() =>
      expect(screen.getAllByLabelText('材料角色')).toHaveLength(4),
    );
    expect(screen.getByText('Harbor 源证书副本（第二对）')).toBeInTheDocument();
    expect(screen.getByLabelText('文件 3 的目标目录')).toHaveValue('');
    fireEvent.click(
      screen.getByRole('button', { name: '取消同步 Harbor 源证书副本' }),
    );
    await waitFor(() =>
      expect(screen.getAllByLabelText('材料角色')).toHaveLength(2),
    );
    expect(screen.getByLabelText('文件 1 的目标文件名')).toHaveValue(
      'fullchain.pem',
    );
    expect(screen.getByLabelText('文件 2 的目标文件名')).toHaveValue(
      'privkey.pem',
    );
    fireEvent.click(
      screen.getByRole('button', { name: '同步 Harbor 源证书副本' }),
    );
    for (const [label, value] of [
      ['文件 3 的目标目录', '/data/source-certs'],
      ['文件 3 的目标文件名', 'harbor.crt'],
      ['文件 4 的目标目录', '/data/source-keys'],
      ['文件 4 的目标文件名', 'harbor.key'],
    ])
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
      undefined,
      expect.objectContaining({
        executorKey: 'harbor.compose.ssh.v1',
        port: 22,
        configuration: expect.objectContaining({
          sourceDomain: 'harbor.example.com',
          sourceFormat: '',
          createDirectory: false,
          harborInstallDirectory: '/opt/harbor',
          harborComposeCommand: 'docker compose',
          harborProxyService: 'proxy',
          verificationHost: '192.0.2.65',
          verificationPort: 8443,
          verificationServerName: 'harbor.example.com',
          files: [
            expect.objectContaining({
              role: 'FullChain',
              fileName: 'fullchain.pem',
            }),
            expect.objectContaining({
              role: 'PrivateKey',
              fileName: 'privkey.pem',
            }),
            expect.objectContaining({
              role: 'FullChain',
              directory: '/data/source-certs',
              fileName: 'harbor.crt',
            }),
            expect.objectContaining({
              role: 'PrivateKey',
              directory: '/data/source-keys',
              fileName: 'harbor.key',
            }),
          ],
          validationCommands: [],
          postCommands: [],
        }),
      }),
    );
    expect(certificateApi.list).not.toHaveBeenCalled();
  });

  it('业务 SNI 不一致时阻止保存，修正后保存并关闭历史目录创建选项', async () => {
    render(
      <TargetForm
        open
        target={{
          ...target,
          executorKey: harborExecutor.key,
          endpoint: '192.0.2.65',
          port: 22,
          configuration: {
            ...target.configuration,
            shell: 'sh',
            createDirectory: true,
            sourceDomain: 'harbor.example.com',
            harborInstallDirectory: '/opt/harbor',
            harborComposeCommand: 'docker-compose',
            harborProxyService: 'proxy',
            hostKeyFingerprint: 'SHA256:test-fingerprint',
            outputDirectory: '/data/cert',
            files: [
              { role: 'FullChain', fileName: 'server.crt' },
              { role: 'PrivateKey', fileName: 'server.key' },
            ],
            verificationHost: '192.0.2.65',
            verificationPort: 8443,
            verificationServerName: 'other.example.com',
          },
        }}
        executors={[harborExecutor]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await screen.findByDisplayValue('/opt/harbor');
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await screen.findByText('SNI 域名必须与 Harbor 绑定域名一致');
    expect(deploymentApi.saveTarget).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('SNI 域名'), {
      target: { value: 'harbor.example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
      target.id,
      expect.objectContaining({
        configuration: expect.objectContaining({ createDirectory: false }),
      }),
    );
  });
});

const sourceListing = {
  certificateId: 'source-1',
  domain: 'vpn.example.com',
  format: 'nginx',
  files: [
    {
      name: 'nginx/vpn.example.com_bundle.crt',
      role: 'FullChain',
      size: 1234,
      sha256: 'A'.repeat(64),
      containsSecrets: false,
    },
    {
      name: 'nginx/vpn.example.com.key',
      role: 'PrivateKey',
      size: 456,
      sha256: 'B'.repeat(64),
      containsSecrets: true,
    },
    {
      name: 'nginx/readme.txt',
      role: 'Auxiliary',
      size: 100,
      sha256: 'C'.repeat(64),
      containsSecrets: false,
    },
  ],
};
const linuxTarget: DeploymentTarget = {
  ...target,
  id: 'linux-target',
  name: 'Linux 服务器',
  endpoint: '192.0.2.10',
  port: 22,
  executorKey: linuxExecutor.key,
  configuration: {
    ...target.configuration,
    sourceDomain: 'vpn.example.com',
    sourceFormat: 'nginx',
    operatingSystem: 'Linux',
    shell: 'sh',
    outputDirectory: '',
    files: [],
    hostKeyFingerprint: 'SHA256:test',
  },
};

describe('Linux 来源文件和远程路径配置', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(certificateApi.list).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: {
        items: [
          {
            id: 'source-1',
            accountId: 'account',
            provider: 'TencentCloud',
            domain: 'vpn.example.com',
            status: 'Issued',
          },
        ],
        total: 1,
        page: 1,
        pageSize: 100,
      },
    });
    vi.mocked(deploymentApi.sourceFiles).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: sourceListing,
    });
    vi.mocked(deploymentApi.saveTarget).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: linuxTarget,
    });
  });

  it('读取真实源文件并保存不同目标目录、重命名和刷新命令', async () => {
    render(
      <TargetForm
        open
        target={linuxTarget}
        executors={[linuxExecutor]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '读取源文件' })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '读取源文件' }));
    await screen.findByLabelText('目标目录 1');
    expect(deploymentApi.sourceFiles).toHaveBeenCalledWith('source-1', 'nginx');
    expect(screen.getByLabelText('目标文件名 1')).toHaveValue(
      'vpn.example.com_bundle.crt',
    );
    expect(screen.getByLabelText('目标文件名 2')).toHaveValue(
      'vpn.example.com.key',
    );
    expect(screen.queryByLabelText('目标文件名 3')).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('目标目录 1'), {
      target: { value: '/etc/ssl/vpn' },
    });
    fireEvent.change(screen.getByLabelText('目标目录 2'), {
      target: { value: '/run/vpn' },
    });
    fireEvent.change(screen.getByLabelText('目标文件名 1'), {
      target: { value: 'vpn_bundle.crt' },
    });
    fireEvent.change(screen.getByLabelText('目标文件名 2'), {
      target: { value: 'vpn.key' },
    });
    fireEvent.click(screen.getByRole('button', { name: /添加后置命令/ }));
    fireEvent.change(screen.getByLabelText('命令'), {
      target: { value: 'systemctl restart anylink' },
    });
    fireEvent.change(screen.getByLabelText('完成检查命令'), {
      target: { value: 'systemctl is-active --quiet anylink' },
    });
    fireEvent.click(screen.getByRole('switch', { name: '中断后允许重试' }));
    fireEvent.click(screen.getByRole('button', { name: '读取源文件' }));
    await waitFor(() =>
      expect(deploymentApi.sourceFiles).toHaveBeenCalledTimes(2),
    );
    expect(screen.getByLabelText('目标文件名 1')).toHaveValue('vpn_bundle.crt');
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
      'linux-target',
      expect.objectContaining({
        configuration: expect.objectContaining({
          sourceDomain: 'vpn.example.com',
          sourceCertificateId: '',
          sourceFormat: 'nginx',
          outputDirectory: '',
          files: [
            {
              sourceFileName: 'nginx/vpn.example.com_bundle.crt',
              role: 'FullChain',
              directory: '/etc/ssl/vpn',
              fileName: 'vpn_bundle.crt',
            },
            {
              sourceFileName: 'nginx/vpn.example.com.key',
              role: 'PrivateKey',
              directory: '/run/vpn',
              fileName: 'vpn.key',
            },
          ],
          postCommands: [
            expect.objectContaining({
              command: 'systemctl restart anylink',
              executionMode: 'WaitForExit',
              recoveryCheckCommand: 'systemctl is-active --quiet anylink',
              retryOnInterruption: true,
            }),
          ],
        }),
      }),
    );
  });

  it('域名候选去重并跨页读取最新续签包，保留已有目标路径且保存时清空证书 ID', async () => {
    const oldCertificate = {
      id: 'source-1',
      accountId: 'account',
      provider: 'TencentCloud' as const,
      domain: 'vpn.example.com',
      status: 'Issued',
      notAfterUtc: '2027-01-11T00:00:00Z',
    };
    const renewedCertificate = {
      ...oldCertificate,
      id: 'renewed-source',
      domain: 'VPN.EXAMPLE.COM.',
      notAfterUtc: '2027-01-30T00:00:00Z',
    };
    vi.mocked(certificateApi.list)
      .mockResolvedValueOnce({
        success: true,
        code: 'OK',
        message: '',
        data: {
          items: [oldCertificate],
          total: 2,
          page: 1,
          pageSize: 100,
        },
      })
      .mockResolvedValueOnce({
        success: true,
        code: 'OK',
        message: '',
        data: {
          items: [renewedCertificate],
          total: 2,
          page: 2,
          pageSize: 100,
        },
      });
    vi.mocked(deploymentApi.sourceFiles).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: {
        ...sourceListing,
        certificateId: renewedCertificate.id,
        files: sourceListing.files.map((file) => ({
          ...file,
          name: file.name.replace('nginx/', 'renewed-package/'),
        })),
      },
    });
    const configured: DeploymentTarget = {
      ...linuxTarget,
      configuration: {
        ...linuxTarget.configuration,
        sourceCertificateId: oldCertificate.id,
        files: [
          {
            role: 'FullChain',
            sourceFileName: sourceListing.files[0].name,
            directory: '/etc/vpn',
            fileName: 'server.crt',
          },
          {
            role: 'PrivateKey',
            sourceFileName: sourceListing.files[1].name,
            directory: '/etc/vpn/keys',
            fileName: 'private.key',
          },
        ],
      },
    };
    render(
      <TargetForm
        open
        target={configured}
        executors={[linuxExecutor]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '读取源文件' })).toBeEnabled(),
    );
    expect(certificateApi.list).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ page: 2, pageSize: 100 }),
    );
    fireEvent.mouseDown(screen.getByLabelText('绑定域名'));
    expect(
      await screen.findAllByRole('option', { name: 'vpn.example.com' }),
    ).toHaveLength(1);
    const domainOption = screen.getAllByText('vpn.example.com').at(-1);
    if (!domainOption) throw new Error('未找到域名选项');
    fireEvent.click(domainOption);
    fireEvent.click(screen.getByRole('button', { name: '读取源文件' }));
    await waitFor(() =>
      expect(deploymentApi.sourceFiles).toHaveBeenCalledWith(
        renewedCertificate.id,
        'nginx',
      ),
    );
    await screen.findByText(/已读取 vpn.example.com/);
    expect(screen.getByLabelText('目标目录 1')).toHaveValue('/etc/vpn');
    expect(screen.getByLabelText('目标文件名 1')).toHaveValue('server.crt');
    expect(screen.getByLabelText('目标目录 2')).toHaveValue('/etc/vpn/keys');
    expect(screen.getByLabelText('目标文件名 2')).toHaveValue('private.key');
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
      configured.id,
      expect.objectContaining({
        configuration: expect.objectContaining({
          sourceDomain: 'vpn.example.com',
          sourceCertificateId: '',
          files: [
            expect.objectContaining({
              directory: '/etc/vpn',
              fileName: 'server.crt',
              sourceFileName: 'renewed-package/vpn.example.com_bundle.crt',
            }),
            expect.objectContaining({
              directory: '/etc/vpn/keys',
              fileName: 'private.key',
              sourceFileName: 'renewed-package/vpn.example.com.key',
            }),
          ],
        }),
      }),
    );
  });

  it('原源路径类型改变时保留配置并报错，不改选其他目录的同名文件', async () => {
    const original = {
      role: 'FullChain',
      sourceFileName: sourceListing.files[0].name,
      directory: '/etc/vpn',
      fileName: 'server.crt',
    };
    vi.mocked(deploymentApi.sourceFiles).mockResolvedValue({
      success: true,
      code: 'OK',
      message: '',
      data: {
        ...sourceListing,
        files: [
          { ...sourceListing.files[0], role: 'PrivateKey' },
          {
            ...sourceListing.files[0],
            name: 'other/vpn.example.com_bundle.crt',
          },
        ],
      },
    });
    render(
      <TargetForm
        open
        target={{
          ...linuxTarget,
          configuration: {
            ...linuxTarget.configuration,
            files: [original],
          },
        }}
        executors={[linuxExecutor]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '读取源文件' })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '读取源文件' }));
    await screen.findByText(/部分源文件已变化或存在多个同名文件/);
    expect(screen.getByLabelText('目标目录 1')).toHaveValue(original.directory);
    expect(screen.getByLabelText('目标文件名 1')).toHaveValue(
      original.fileName,
    );
    fireEvent.click(screen.getByRole('button', { name: '保存目标' }));
    await waitFor(() =>
      expect(deploymentApi.saveTarget).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.saveTarget).toHaveBeenCalledWith(
      linuxTarget.id,
      expect.objectContaining({
        configuration: expect.objectContaining({ files: [original] }),
      }),
    );
  });

  it('新建未保存目标可直接浏览，并在明确确认后回填主机指纹', async () => {
    const directory = {
      path: '/conf',
      parentPath: '/',
      entries: [],
      truncated: false,
      observedFingerprint: 'SHA256:observed',
    };
    vi.mocked(deploymentApi.browseDirectory)
      .mockResolvedValueOnce({
        success: false,
        code: 'HOST_IDENTITY_REQUIRED',
        message: '请核对主机身份',
        data: directory,
      })
      .mockResolvedValueOnce({
        success: true,
        code: 'OK',
        message: '',
        data: directory,
      });
    render(
      <TargetForm
        open
        executors={[linuxExecutor]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await screen.findByLabelText('默认输出目录');
    fireEvent.change(screen.getByLabelText('主机或 IP'), {
      target: { value: '192.0.2.10' },
    });
    fireEvent.change(screen.getByLabelText('用户名'), {
      target: { value: 'root' },
    });
    fireEvent.change(screen.getByLabelText('密码'), {
      target: { value: 'test-password' },
    });
    fireEvent.click(screen.getByRole('button', { name: '浏览远程目录' }));
    await screen.findByRole('button', { name: '确认信任并继续' });
    expect(deploymentApi.browseDirectory).toHaveBeenCalledWith(
      expect.objectContaining({
        endpoint: '192.0.2.10',
        username: 'root',
        password: 'test-password',
        hostKeyFingerprint: '',
        path: '/',
      }),
    );
    expect(deploymentApi.saveTarget).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: '确认信任并继续' }));
    await waitFor(() =>
      expect(deploymentApi.browseDirectory).toHaveBeenCalledTimes(2),
    );
    expect(
      vi.mocked(deploymentApi.browseDirectory).mock.calls[1][0]
        .hostKeyFingerprint,
    ).toBe('SHA256:observed');
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: '选择此目录' }),
      ).not.toBeDisabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '选择此目录' }));
    expect(screen.getByLabelText('默认输出目录')).toHaveValue('/conf');
    expect(screen.getByLabelText('SSH 主机密钥指纹')).toHaveValue(
      'SHA256:observed',
    );
  });

  it('切换来源格式会清除映射，并忽略旧格式迟到的读取响应', async () => {
    let complete: (value: any) => void = () => {};
    vi.mocked(deploymentApi.sourceFiles).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          complete = resolve;
        }),
    );
    render(
      <TargetForm
        open
        target={linuxTarget}
        executors={[linuxExecutor]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole('button', { name: '读取源文件' })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole('button', { name: '读取源文件' }));
    await waitFor(() =>
      expect(deploymentApi.sourceFiles).toHaveBeenCalledOnce(),
    );
    fireEvent.mouseDown(screen.getByLabelText('源证书格式'));
    fireEvent.click(await screen.findByText('IIS'));
    await act(async () =>
      complete({ success: true, code: 'OK', message: '', data: sourceListing }),
    );
    expect(screen.queryByLabelText('目标文件名 1')).not.toBeInTheDocument();
    expect(
      screen.queryByText(/已读取 vpn.example.com/),
    ).not.toBeInTheDocument();
  });

  it('逐行浏览仅回填选中行，已有目标复用凭据且支持原相对子路径', async () => {
    const configured: DeploymentTarget = {
      ...linuxTarget,
      configuration: {
        ...linuxTarget.configuration,
        files: [
          {
            sourceFileName: sourceListing.files[0].name,
            role: 'FullChain',
            directory: '/certs',
            fileName: 'existing.crt',
          },
          {
            sourceFileName: sourceListing.files[1].name,
            role: 'PrivateKey',
            directory: '/keys',
            fileName: 'nested/old.key',
          },
        ],
      },
    };
    vi.mocked(deploymentApi.browseDirectory)
      .mockResolvedValueOnce({
        success: true,
        code: 'OK',
        message: '',
        data: {
          path: '/keys/nested',
          parentPath: '/keys',
          entries: [],
          truncated: false,
          observedFingerprint: 'SHA256:test',
        },
      })
      .mockResolvedValueOnce({
        success: true,
        code: 'OK',
        message: '',
        data: {
          path: '/secure',
          parentPath: '/',
          entries: [],
          truncated: false,
          observedFingerprint: 'SHA256:test',
        },
      });
    render(
      <TargetForm
        open
        target={configured}
        executors={[linuxExecutor]}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );
    fireEvent.click(
      await screen.findByRole('button', { name: '浏览目标文件 2' }),
    );
    await waitFor(() =>
      expect(deploymentApi.browseDirectory).toHaveBeenCalledOnce(),
    );
    expect(deploymentApi.browseDirectory).toHaveBeenCalledWith(
      expect.objectContaining({
        targetId: 'linux-target',
        configRevision: 3,
        password: '',
        path: '/keys/nested',
      }),
    );
    fireEvent.change(screen.getByLabelText('远程目录路径'), {
      target: { value: '/secure' },
    });
    fireEvent.click(screen.getByRole('button', { name: '前往' }));
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: '使用此目标文件' }),
      ).not.toBeDisabled(),
    );
    fireEvent.change(screen.getByLabelText('目标文件名'), {
      target: { value: 'new.key' },
    });
    fireEvent.click(screen.getByRole('button', { name: '使用此目标文件' }));
    expect(screen.getByLabelText('目标目录 1')).toHaveValue('/certs');
    expect(screen.getByLabelText('目标文件名 1')).toHaveValue('existing.crt');
    expect(screen.getByLabelText('目标目录 2')).toHaveValue('/secure');
    expect(screen.getByLabelText('目标文件名 2')).toHaveValue('new.key');
  });
});
