import { MinusCircleOutlined, PlusOutlined } from '@ant-design/icons';
import {
  Alert,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
} from 'antd';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useResultMessage } from '@/components/ssl-manager';
import RemoteFileBrowser, {
  type RemoteFileSelection,
} from '@/components/ssl-manager/deployment/RemoteFileBrowser';
import { certificateApi } from '@/services/ssl-manager/api';
import { deploymentApi } from '@/services/ssl-manager/deployment';
import {
  latestDeploymentCertificates,
  normalizeDeploymentDomain,
} from '@/services/ssl-manager/deploymentSource';
import type {
  CertificateSourceListing,
  DeploymentDiscovery,
  DeploymentExecutorDescriptor,
  DeploymentTarget,
  DeploymentTargetConfiguration,
  DeploymentTargetInput,
} from '@/services/ssl-manager/deploymentTypes';
import type { Certificate } from '@/services/ssl-manager/types';

const authenticationNames: Record<string, string> = {
  Password: '用户名密码',
  ApiToken: 'API Token',
  PrivateKey: 'SSH 私钥',
};
const fileRoles = [
  { value: 'FullChain', label: '完整证书链' },
  { value: 'PrivateKey', label: '私钥' },
  { value: 'Leaf', label: '叶子证书' },
  { value: 'Chain', label: '中间证书链' },
  { value: 'Pfx', label: 'PFX' },
];
const sourceFormats = [
  { value: 'nginx', label: 'Nginx' },
  { value: 'apache', label: 'Apache' },
  { value: 'iis', label: 'IIS' },
  { value: 'tomcat', label: 'Tomcat' },
];
const sourceRoleNames: Record<string, string> = {
  ...Object.fromEntries(fileRoles.map((item) => [item.value, item.label])),
  Jks: 'Java 密钥库',
  Password: '密码文件',
  Auxiliary: '附加文件',
};

/** 群晖表单统一在 URL 中编辑端口，兼容通过 API 单独保存端口的目标。 */
function endpointForForm(target: DeploymentTarget): string {
  if (!target.executorKey.startsWith('synology.') || target.port <= 0)
    return target.endpoint;
  // 只补没有显式端口的地址；保留显式 443 和 IPv6，避免 URL 规范化丢弃默认端口。
  return target.endpoint.replace(
    /^(https:\/\/(?:\[[^\]]+\]|[^:/?#]+))(?=[/?#]|$)/i,
    `$1:${target.port}`,
  );
}

function defaultConfiguration(
  executor?: DeploymentExecutorDescriptor,
): DeploymentTargetConfiguration {
  const windows = executor?.operatingSystem === 'Windows';
  const httpsApi = executor?.protocol === 'HTTPS';
  const linux = executor?.key === 'linux.files.ssh.v1';
  const harbor = executor?.key === 'harbor.compose.ssh.v1';
  return {
    ...(linux ? { sourceFormat: 'nginx', sourceDomain: '' } : {}),
    ...(harbor
      ? {
          sourceDomain: '',
          sourceFormat: '',
          harborInstallDirectory: '',
          harborComposeCommand: 'docker compose' as const,
          harborProxyService: 'proxy',
        }
      : {}),
    siteIds: [],
    remoteCertificateId: '',
    certificateDescription: '',
    bindSites: false,
    operatingSystem: executor?.operatingSystem || '',
    shell: httpsApi ? '' : windows ? 'PowerShell' : 'sh',
    outputDirectory: '',
    files:
      httpsApi || linux
        ? []
        : [
            { role: 'FullChain', fileName: 'fullchain.pem' },
            { role: 'PrivateKey', fileName: 'privkey.pem' },
          ],
    validationCommands: [],
    postCommands: [],
    hostKeyFingerprint: '',
    createDirectory: false,
    verificationHost: '',
    verificationPort: 443,
    verificationServerName: '',
    connectionTimeoutSeconds: 30,
    operationTimeoutSeconds: 120,
  };
}

/** 命令由明确的工作目录、超时和断连语义组成，不把整个配置作为 JSON 交给用户编辑。 */
function CommandFields({
  name,
  title,
  post,
}: {
  name: string;
  title: string;
  post?: boolean;
}) {
  return (
    <Form.List name={['configuration', name]}>
      {(fields, { add, remove }) => (
        <>
          <div style={{ margin: '16px 0 8px', fontWeight: 600 }}>{title}</div>
          {fields.map((field) => (
            <div
              key={field.key}
              style={{
                padding: 12,
                border: '1px solid #f0f0f0',
                borderRadius: 6,
                marginBottom: 12,
              }}
            >
              <Form.Item
                name={[field.name, 'command']}
                label="命令"
                rules={[{ required: true, message: '请输入命令' }]}
              >
                <Input.TextArea
                  rows={2}
                  placeholder="例如 nginx -s reload；在目标机器执行"
                />
              </Form.Item>
              <Space align="start" wrap>
                <Form.Item
                  name={[field.name, 'workingDirectory']}
                  label="工作目录"
                >
                  <Input style={{ width: 280 }} />
                </Form.Item>
                <Form.Item
                  name={[field.name, 'timeoutSeconds']}
                  label="超时秒数"
                  rules={[{ required: true }]}
                >
                  <InputNumber min={1} max={3600} />
                </Form.Item>
                <Form.Item
                  name={[field.name, 'executionMode']}
                  label="执行模式"
                >
                  <Select
                    style={{ width: 190 }}
                    options={[
                      { value: 'WaitForExit', label: '等待命令退出' },
                      ...(post
                        ? [
                            {
                              value: 'ExpectDisconnect',
                              label: '允许重启导致断连',
                            },
                          ]
                        : []),
                    ]}
                  />
                </Form.Item>
                <Button
                  type="text"
                  aria-label={`移除${title}`}
                  icon={<MinusCircleOutlined />}
                  onClick={() => remove(field.name)}
                />
              </Space>
              <Form.Item
                name={[field.name, 'recoveryCheckCommand']}
                label="完成检查命令"
                extra="服务重启后先执行此检查；退出码为 0 表示原命令已完成。检查命令应只读取状态。"
              >
                <Input.TextArea
                  rows={2}
                  placeholder="例如核对服务状态及本轮证书指纹"
                />
              </Form.Item>
              <Form.Item
                name={[field.name, 'retryOnInterruption']}
                label="中断后允许重试"
                valuePropName="checked"
                extra="仅在命令可安全重复执行时开启；默认关闭。"
              >
                <Switch />
              </Form.Item>
            </div>
          ))}
          <Button
            type="dashed"
            icon={<PlusOutlined />}
            onClick={() =>
              add({
                command: '',
                workingDirectory: '',
                timeoutSeconds: 120,
                executionMode: 'WaitForExit',
              })
            }
          >
            添加{title}
          </Button>
        </>
      )}
    </Form.List>
  );
}

export default function TargetForm({
  open,
  target,
  executors,
  onClose,
  onSaved,
}: {
  open: boolean;
  target?: DeploymentTarget;
  executors: DeploymentExecutorDescriptor[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form] = Form.useForm<DeploymentTargetInput>();
  const showResult = useResultMessage();
  const [saving, setSaving] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [error, setError] = useState('');
  const [discovery, setDiscovery] = useState<DeploymentDiscovery>();
  const [sourceCertificates, setSourceCertificates] = useState<Certificate[]>(
    [],
  );
  const [sourceCertificatesLoading, setSourceCertificatesLoading] =
    useState(false);
  const [sourceListing, setSourceListing] =
    useState<CertificateSourceListing>();
  const [sourceLoading, setSourceLoading] = useState(false);
  const [browser, setBrowser] = useState<{
    index?: number;
    mode: 'directory' | 'file';
    directory: string;
    fileName: string;
  }>();
  const certificateRequest = useRef(0);
  const sourceRequest = useRef(0);
  const executorKey = Form.useWatch('executorKey', form);
  const authenticationMode = Form.useWatch('authenticationMode', form);
  const bindSites = Form.useWatch(['configuration', 'bindSites'], form);
  const remoteCertificateId = Form.useWatch(
    ['configuration', 'remoteCertificateId'],
    form,
  );
  const sourceDomain = Form.useWatch(['configuration', 'sourceDomain'], {
    form,
    preserve: true,
  });
  const sourceFormat = Form.useWatch(['configuration', 'sourceFormat'], {
    form,
    preserve: true,
  });
  const executor = executors.find((item) => item.key === executorKey);
  const safeline = executorKey?.startsWith('safeline.') ?? false;
  const synology = executorKey?.startsWith('synology.') ?? false;
  const linux = executorKey === 'linux.files.ssh.v1';
  const harbor = executorKey === 'harbor.compose.ssh.v1';
  const sourceMode = linux && !!sourceFormat;
  const latestSourceCertificates =
    latestDeploymentCertificates(sourceCertificates);
  const ignoresManagementCertificateErrors = safeline || synology;
  const httpsApi = executor?.protocol === 'HTTPS';
  const relatedServices = discovery?.sites.filter(
    (item) => item.certificateId === remoteCertificateId,
  );
  const close = () => {
    // 编辑会话关闭即丢弃未保存的明文凭据，不留待下次打开表单。
    form.resetFields();
    setDiscovery(undefined);
    setError('');
    setBrowser(undefined);
    setSourceListing(undefined);
    setSourceLoading(false);
    setSourceCertificatesLoading(false);
    ++sourceRequest.current;
    ++certificateRequest.current;
    onClose();
  };

  useEffect(() => {
    if (!open) return;
    setError('');
    setDiscovery(undefined);
    setSourceListing(undefined);
    setSourceLoading(false);
    setBrowser(undefined);
    ++sourceRequest.current;
    form.resetFields();
    const first = executors.find((item) => item.available);
    form.setFieldsValue(
      target
        ? {
            ...target,
            endpoint: endpointForForm(target),
            configuration: {
              ...structuredClone(target.configuration),
              sourceDomain: normalizeDeploymentDomain(
                target.configuration.sourceDomain,
              ),
            },
            password: '',
            apiToken: '',
            privateKey: '',
            privateKeyPassphrase: '',
            pfxPassword: '',
          }
        : {
            name: '',
            description: '',
            executorKey: first?.key || '',
            endpoint: '',
            port: first?.protocol === 'SSH' ? 22 : 0,
            username: '',
            authenticationMode: first?.authenticationModes?.[0] || 'Password',
            enabled: true,
            tlsFingerprint: '',
            configuration: defaultConfiguration(first),
          },
    );
  }, [open, target, executors, form]);

  const loadSourceCertificates = useCallback(async () => {
    const sequence = ++certificateRequest.current;
    setSourceCertificatesLoading(true);
    const certificates: Certificate[] = [];
    // 完整读取后按域名去重，避免最新续签证书位于后续分页时仍读取旧包。
    for (let page = 1; ; page += 1) {
      const result = await certificateApi.list({
        status: 'Issued',
        page,
        pageSize: 100,
      });
      if (certificateRequest.current !== sequence) return;
      if (!result.success || !result.data) {
        setSourceCertificatesLoading(false);
        setError(result.message);
        return;
      }
      certificates.push(...result.data.items);
      if (!result.data.items.length || certificates.length >= result.data.total)
        break;
    }
    setSourceCertificatesLoading(false);
    setSourceCertificates(
      certificates.filter((item) => item.status === 'Issued'),
    );
  }, []);

  useEffect(() => {
    if (open && linux) void loadSourceCertificates();
    return () => {
      ++certificateRequest.current;
    };
  }, [open, linux, loadSourceCertificates]);

  useEffect(() => {
    if (
      !open ||
      !linux ||
      form.getFieldValue(['configuration', 'sourceDomain'])
    )
      return;
    // 兼容升级前已打开的表单；持久配置的域名回填由后端负责。
    const legacyId = form.getFieldValue([
      'configuration',
      'sourceCertificateId',
    ]);
    const legacy = sourceCertificates.find((item) => item.id === legacyId);
    if (legacy)
      form.setFieldValue(
        ['configuration', 'sourceDomain'],
        normalizeDeploymentDomain(legacy.domain),
      );
  }, [open, linux, sourceCertificates, form]);

  const resetSourceFiles = () => {
    ++sourceRequest.current;
    setSourceLoading(false);
    setSourceListing(undefined);
    form.setFieldValue(['configuration', 'files'], []);
  };

  const readSourceFiles = async () => {
    await form.validateFields([
      ['configuration', 'sourceDomain'],
      ['configuration', 'sourceFormat'],
    ]);
    if (!sourceDomain || !sourceFormat) return;
    const certificate = latestSourceCertificates.get(
      normalizeDeploymentDomain(sourceDomain),
    );
    if (!certificate) {
      setError('绑定域名当前没有可用的已签发证书，请同步证书后重试。');
      return;
    }
    const sequence = ++sourceRequest.current;
    setSourceLoading(true);
    setError('');
    const result = await deploymentApi.sourceFiles(
      certificate.id,
      sourceFormat,
    );
    if (sourceRequest.current !== sequence) return;
    setSourceLoading(false);
    if (!result.success || !result.data) {
      setError(result.message);
      return;
    }
    const listing = result.data;
    setSourceListing(listing);
    const existing = form.getFieldValue([
      'configuration',
      'files',
    ]) as DeploymentTargetConfiguration['files'];
    // 续签包顶层目录可能变化；仅在文件名和角色唯一匹配时更新来源路径，保留目标路径。
    const remapped = existing.map((mapping) => {
      const exact = listing.files.filter(
        (file) => file.name === mapping.sourceFileName,
      );
      const candidates = listing.files.filter(
        (file) =>
          file.role === mapping.role &&
          file.name.split('/').pop() ===
            mapping.sourceFileName?.split('/').pop(),
      );
      const file = exact.length
        ? exact.length === 1 && exact[0].role === mapping.role
          ? exact[0]
          : undefined
        : candidates.length === 1
          ? candidates[0]
          : undefined;
      return file ? { ...mapping, sourceFileName: file.name } : undefined;
    });
    if (existing.length && remapped.some((mapping) => !mapping)) {
      setError(
        '新证书包的部分源文件已变化或存在多个同名文件，请核对并重新选择对应源文件；目标路径已保留。',
      );
      return;
    }
    // 首次读取默认选择关键材料，附加文件可手动加入。
    const files = existing.length
      ? remapped.filter((mapping) => mapping !== undefined)
      : listing.files
          .filter((file) => !['Password', 'Auxiliary'].includes(file.role))
          .map((file) => ({
            sourceFileName: file.name,
            role: file.role,
            directory: '',
            fileName: file.name.split('/').pop() || file.name,
          }));
    form.setFieldValue(['configuration', 'files'], files);
  };

  const loadDirectory = useCallback(
    (path: string) => {
      const values = form.getFieldsValue(true);
      return deploymentApi.browseDirectory({
        targetId: target?.id,
        configRevision: target?.configRevision,
        executorKey: values.executorKey,
        endpoint: values.endpoint,
        port: values.port,
        username: values.username,
        authenticationMode: values.authenticationMode,
        password: values.password,
        privateKey: values.privateKey,
        privateKeyPassphrase: values.privateKeyPassphrase,
        hostKeyFingerprint: values.configuration.hostKeyFingerprint || '',
        path,
        connectionTimeoutSeconds: Math.min(
          values.configuration.connectionTimeoutSeconds || 30,
          120,
        ),
        operationTimeoutSeconds: Math.min(
          values.configuration.operationTimeoutSeconds || 30,
          120,
        ),
      });
    },
    [form, target],
  );

  const openBrowser = async (index?: number) => {
    try {
      // 首次连接允许尚未填写主机指纹，由浏览结果展示并明确确认信任。
      await form.validateFields([
        'endpoint',
        'port',
        'username',
        'authenticationMode',
        authenticationMode === 'PrivateKey' ? 'privateKey' : 'password',
      ]);
      const directory =
        form.getFieldValue(['configuration', 'outputDirectory']) || '/';
      const mapping =
        index === undefined
          ? undefined
          : form.getFieldValue(['configuration', 'files', index]);
      const relativeFile = (mapping?.fileName || '').replace(/\\/g, '/');
      const separator = relativeFile.lastIndexOf('/');
      const baseDirectory = mapping?.directory || directory;
      setBrowser({
        index,
        mode: index === undefined ? 'directory' : 'file',
        directory:
          separator < 0
            ? baseDirectory
            : `${baseDirectory.replace(/\/$/, '')}/${relativeFile.slice(0, separator)}`,
        fileName: relativeFile.slice(separator + 1),
      });
    } catch {
      setError('请先填写服务器地址和 SSH 登录信息。');
    }
  };

  const selectRemoteFile = (selection: RemoteFileSelection) => {
    if (browser?.index === undefined)
      form.setFieldValue(
        ['configuration', 'outputDirectory'],
        selection.directory,
      );
    else {
      form.setFieldValue(
        ['configuration', 'files', browser.index, 'directory'],
        selection.directory,
      );
      form.setFieldValue(
        ['configuration', 'files', browser.index, 'fileName'],
        selection.fileName,
      );
    }
    setBrowser(undefined);
  };

  const discover = async () => {
    if (!target) return;
    setDiscovering(true);
    setError('');
    try {
      const result = await deploymentApi.discover(target.id);
      if (result.success && result.data) setDiscovery(result.data);
      else setError(result.message);
    } finally {
      setDiscovering(false);
    }
  };
  const save = async () => {
    let values: DeploymentTargetInput;
    try {
      values = await form.validateFields();
    } catch {
      // 表单已展示字段错误，等待修正；不把正常校验失败当成未处理异常。
      return;
    }
    setSaving(true);
    setError('');
    try {
      const result = await deploymentApi.saveTarget(target?.id, {
        ...values,
        // 两类管理 API 已默认忽略证书错误，隐藏历史指纹输入但保留旧值，兼容既有目标数据。
        tlsFingerprint: ignoresManagementCertificateErrors
          ? target?.tlsFingerprint || ''
          : values.tlsFingerprint,
        // 群晖端口由管理地址指定；其他已有目标仍保留其独立端口配置。
        port: synology ? 0 : httpsApi ? target?.port || 0 : values.port,
        configuration: synology
          ? {
              ...defaultConfiguration(executor),
              ...values.configuration,
              remoteCertificateId:
                values.configuration.remoteCertificateId || '',
              bindSites: false,
              siteIds: [],
              files: [],
              validationCommands: [],
              postCommands: [],
            }
          : harbor
            ? {
                ...values.configuration,
                sourceDomain: normalizeDeploymentDomain(
                  values.configuration.sourceDomain,
                ),
                sourceCertificateId: '',
                sourceFormat: '',
                createDirectory: false,
                verificationServerName: normalizeDeploymentDomain(
                  values.configuration.verificationServerName,
                ),
                // Harbor 的代理激活由执行器生成，不接受隐藏的旧命令。
                validationCommands: [],
                postCommands: [],
              }
            : sourceMode
              ? {
                  ...values.configuration,
                  sourceDomain: normalizeDeploymentDomain(
                    values.configuration.sourceDomain,
                  ),
                  sourceCertificateId: '',
                }
              : values.configuration,
        configRevision: target?.configRevision,
      });
      if (showResult(result, '部署目标已保存')) {
        onSaved();
        close();
      } else setError(result.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <Modal
        title={target ? '编辑部署目标' : '新建部署目标'}
        open={open}
        width={900}
        onCancel={close}
        onOk={save}
        confirmLoading={saving}
        okText="保存目标"
        cancelText="取消"
      >
        {error && (
          <Alert
            type="error"
            title={error}
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}
        <Form name="deployment-target" form={form} layout="vertical" preserve>
          <Space align="start" wrap style={{ width: '100%' }}>
            <Form.Item
              name="name"
              label="目标名称"
              rules={[{ required: true, message: '请输入目标名称' }]}
            >
              <Input maxLength={100} style={{ width: 320 }} />
            </Form.Item>
            <Form.Item name="enabled" label="启用" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
          <Form.Item name="description" label="说明">
            <Input maxLength={500} />
          </Form.Item>
          <Form.Item
            name="executorKey"
            label="目标执行器"
            rules={[{ required: true }]}
          >
            <Select
              disabled={!!target}
              options={executors.map((item) => ({
                value: item.key,
                label: `${item.name}${item.available ? '' : `（${item.unavailableReason || '暂不可用'}）`}`,
                disabled: !item.available,
              }))}
              onChange={(key) => {
                const selected = executors.find((item) => item.key === key);
                setDiscovery(undefined);
                resetSourceFiles();
                setBrowser(undefined);
                form.setFieldsValue({
                  authenticationMode:
                    selected?.authenticationModes?.[0] || 'Password',
                  port: selected?.protocol === 'SSH' ? 22 : 0,
                  configuration: defaultConfiguration(selected),
                  password: '',
                  apiToken: '',
                  privateKey: '',
                  privateKeyPassphrase: '',
                  pfxPassword: '',
                });
              }}
            />
          </Form.Item>
          {executor && (
            <Alert
              type={executor.available ? 'info' : 'warning'}
              title={
                executor.available
                  ? `${executor.protocol} · ${executor.supportedProductVersions || executor.operatingSystem}`
                  : executor.unavailableReason
              }
              style={{ marginBottom: 16 }}
            />
          )}
          <Space align="start" wrap>
            <Form.Item
              name="endpoint"
              label={
                httpsApi ? '管理地址' : harbor ? 'SSH 主机或 IP' : '主机或 IP'
              }
              rules={[{ required: true, message: '请输入连接地址' }]}
              extra={
                synology
                  ? '请输入 DSM 的 HTTPS 地址；省略端口时使用 5001，自定义端口请写入地址。'
                  : undefined
              }
            >
              <Input
                style={{ width: 470 }}
                placeholder={
                  synology
                    ? 'https://nas.example.com:5001'
                    : safeline
                      ? 'https://192.0.2.1:9443'
                      : '192.0.2.10'
                }
              />
            </Form.Item>
            {!httpsApi && (
              <Form.Item
                name="port"
                label={harbor ? 'SSH 端口' : '端口'}
                rules={[{ required: true }]}
              >
                <InputNumber min={1} max={65535} />
              </Form.Item>
            )}
          </Space>
          <Space align="start" wrap>
            <Form.Item name="authenticationMode" label="认证方式">
              <Select
                style={{ width: 200 }}
                options={(executor?.authenticationModes || ['Password']).map(
                  (value) => ({
                    value,
                    label: authenticationNames[value] || value,
                  }),
                )}
              />
            </Form.Item>
            {authenticationMode !== 'ApiToken' && (
              <Form.Item
                name="username"
                label={harbor ? 'SSH 用户名' : '用户名'}
                rules={[{ required: true, message: '请输入用户名' }]}
              >
                <Input autoComplete="off" style={{ width: 300 }} />
              </Form.Item>
            )}
          </Space>
          {authenticationMode === 'Password' && (
            <Form.Item
              name="password"
              label="密码"
              rules={[
                {
                  required: !target?.passwordConfigured,
                  message: '请输入密码',
                },
              ]}
            >
              <Input.Password
                autoComplete="new-password"
                placeholder={
                  target?.passwordConfigured
                    ? '已配置；留空保留原密码'
                    : '请输入密码'
                }
              />
            </Form.Item>
          )}
          {authenticationMode === 'ApiToken' && (
            <Form.Item
              name="apiToken"
              label="API Token"
              rules={[
                {
                  required: !target?.apiTokenConfigured,
                  message: '请输入 API Token',
                },
              ]}
            >
              <Input.Password
                autoComplete="new-password"
                placeholder={
                  target?.apiTokenConfigured
                    ? '已配置；留空保留原 Token'
                    : '请输入 API Token'
                }
              />
            </Form.Item>
          )}
          {authenticationMode === 'PrivateKey' && (
            <>
              <Form.Item
                name="privateKey"
                label="SSH 私钥"
                rules={[
                  {
                    required: !target?.privateKeyConfigured,
                    message: '请输入私钥',
                  },
                ]}
              >
                <Input.TextArea
                  rows={4}
                  autoComplete="off"
                  placeholder={
                    target?.privateKeyConfigured
                      ? '已配置；留空保留原私钥'
                      : '粘贴 PEM 或 OpenSSH 私钥'
                  }
                />
              </Form.Item>
              <Form.Item name="privateKeyPassphrase" label="私钥口令">
                <Input.Password
                  autoComplete="new-password"
                  placeholder="有口令时填写；编辑留空保留"
                />
              </Form.Item>
            </>
          )}
          {ignoresManagementCertificateErrors ? (
            <Alert
              type="info"
              showIcon
              title="管理连接默认忽略对端证书校验错误"
              description="自签名、证书过期或域名不匹配不会阻止连接和更新证书，无需配置管理端证书指纹。"
              style={{ marginBottom: 16 }}
            />
          ) : httpsApi || executor?.protocol === 'WinRM' ? (
            <Form.Item
              name="tlsFingerprint"
              label="管理端 SHA-256 证书指纹"
              extra="留空使用系统证书信任；自签名管理端请配置确认过的指纹。仅用于管理连接。"
            >
              <Input autoComplete="off" />
            </Form.Item>
          ) : (
            <Form.Item
              name={['configuration', 'hostKeyFingerprint']}
              label="SSH 主机密钥指纹"
              extra={
                linux
                  ? '首次连接可先点击“浏览远程目录”，核对指纹后确认信任。'
                  : undefined
              }
              rules={[
                { required: true, message: '请输入已核对的 SSH 主机密钥指纹' },
              ]}
            >
              <Input placeholder="SHA256:…" />
            </Form.Item>
          )}
          {safeline || synology ? (
            <>
              <Space style={{ marginBottom: 16 }}>
                <Button
                  onClick={discover}
                  loading={discovering}
                  disabled={!target}
                >
                  {synology ? '读取群晖证书和服务' : '读取雷池证书和站点'}
                </Button>
                <span style={{ color: '#888' }}>
                  {target
                    ? '读取已保存目标，不提交当前尚未保存的配置。'
                    : '保存目标后可读取远端资源。'}
                </span>
              </Space>
              <Form.Item
                name={['configuration', 'remoteCertificateId']}
                label="指定替换的证书资源"
                extra={
                  synology
                    ? '优先更新所选证书；未选择或已不存在时按描述匹配，存在则更新，不存在则新增。多个同描述证书需明确选择。'
                    : '留空时由计划按证书域名发现；存在多个候选时不会随意替换。'
                }
              >
                <Select
                  allowClear
                  showSearch={{ optionFilterProp: 'label' }}
                  options={
                    discovery?.certificates.map((item) => ({
                      value: item.id,
                      label: `${item.name || item.id} · ${item.domains.join('、')}`,
                    })) ||
                    (remoteCertificateId
                      ? [
                          {
                            value: remoteCertificateId,
                            label: `证书 ID：${remoteCertificateId}`,
                          },
                        ]
                      : [])
                  }
                />
              </Form.Item>
              {synology && (
                <>
                  <Form.Item
                    name={['configuration', 'certificateDescription']}
                    label="证书描述"
                    extra="留空使用部署证书域名；用于自动匹配及新增，更新时保留群晖原有描述、服务关联和默认状态。"
                  >
                    <Input maxLength={200} />
                  </Form.Item>
                  <Alert
                    type="info"
                    showIcon
                    title="支持 DSM 7.x 管理员账号密码登录"
                    description={
                      <>
                        <div>
                          当前版本不支持两步验证。新增证书仅导入，服务分配可在
                          DSM 中设置。
                        </div>
                        {!!remoteCertificateId && discovery && (
                          <div>
                            当前关联服务：
                            {relatedServices?.length
                              ? relatedServices
                                  .map((item) => item.name || item.id)
                                  .join('、')
                              : '无'}
                            。部署前将再次核对关联范围。
                          </div>
                        )}
                      </>
                    }
                    style={{ marginBottom: 16 }}
                  />
                </>
              )}
              {safeline && (
                <>
                  <Form.Item
                    name={['configuration', 'bindSites']}
                    label="上传后更新已有站点绑定"
                    valuePropName="checked"
                  >
                    <Switch />
                  </Form.Item>
                  {bindSites && (
                    <Form.Item
                      name={['configuration', 'siteIds']}
                      label="允许修改的已有站点"
                      rules={[{ required: true, message: '请选择站点范围' }]}
                    >
                      <Select
                        mode="multiple"
                        showSearch={{ optionFilterProp: 'label' }}
                        options={
                          discovery?.sites.map((item) => ({
                            value: item.id,
                            label: `${item.name || item.id} · ${item.domains.join('、')}`,
                          })) || []
                        }
                      />
                    </Form.Item>
                  )}
                </>
              )}
            </>
          ) : (
            <>
              {harbor && (
                <>
                  <Alert
                    type="info"
                    showIcon
                    title="Harbor 2.x Docker Compose 证书部署"
                    description="仅使用已存在且代理可访问的目录。第一对文件填写代理实际挂载的证书路径；如果 harbor.yml 的 https.certificate / private_key 使用其他源路径，请同步配置第二对，避免以后运行 prepare 时恢复旧证书。部署保留全部文件备份，仅重建代理并检查 Nginx 和业务 TLS；文件恢复后需重新激活代理。SSH 与业务 HTTPS 端口分别配置。"
                    style={{ marginBottom: 16 }}
                  />
                  <Form.Item
                    name={['configuration', 'sourceDomain']}
                    label="Harbor 绑定域名"
                    rules={[
                      { required: true, message: '请输入 Harbor 访问域名' },
                    ]}
                    extra="目标仅接受此域名的证书，同域名续签可复用；访问域名须已在 Harbor 中配置。"
                  >
                    <Input
                      placeholder="harbor.example.com"
                      onChange={(event) =>
                        form.setFieldValue(
                          ['configuration', 'verificationServerName'],
                          normalizeDeploymentDomain(event.target.value),
                        )
                      }
                    />
                  </Form.Item>
                  <Form.Item
                    name={['configuration', 'harborInstallDirectory']}
                    label="Harbor 安装目录"
                    rules={[
                      { required: true, message: '请输入 Harbor 安装目录' },
                      { pattern: /^\//, message: '请输入 Linux 绝对目录' },
                    ]}
                    extra="已有 docker-compose.yml 所在的绝对目录。"
                  >
                    <Input placeholder="填写服务器实际安装目录" />
                  </Form.Item>
                  <Space align="start" wrap>
                    <Form.Item
                      name={['configuration', 'harborComposeCommand']}
                      label="Compose 命令"
                      rules={[{ required: true }]}
                    >
                      <Select
                        style={{ width: 220 }}
                        options={[
                          {
                            value: 'docker compose',
                            label: 'docker compose（V2）',
                          },
                          {
                            value: 'docker-compose',
                            label: 'docker-compose（V1）',
                          },
                        ]}
                      />
                    </Form.Item>
                    <Form.Item
                      name={['configuration', 'harborProxyService']}
                      label="代理服务名"
                      rules={[
                        { required: true, message: '请输入代理服务名' },
                        {
                          pattern: /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/,
                          message: '请输入有效的 Compose 服务名',
                        },
                      ]}
                    >
                      <Input style={{ width: 220 }} />
                    </Form.Item>
                  </Space>
                </>
              )}
              {linux &&
                (sourceMode ? (
                  <>
                    <Form.Item
                      name={['configuration', 'sourceDomain']}
                      label="绑定域名"
                      rules={[
                        { required: true, message: '请选择已签发证书的域名' },
                      ]}
                      extra="同域名续签后的新证书可复用此目标和文件映射；切换域名或格式后需重新读取并配置源文件。"
                    >
                      <Select
                        placeholder="搜索并选择证书域名"
                        loading={sourceCertificatesLoading}
                        showSearch={{ optionFilterProp: 'label' }}
                        options={[
                          ...Array.from(latestSourceCertificates.keys()).map(
                            (domain) => ({
                              value: domain,
                              label: domain,
                            }),
                          ),
                          ...(sourceDomain &&
                          !latestSourceCertificates.has(
                            normalizeDeploymentDomain(sourceDomain),
                          )
                            ? [
                                {
                                  value: sourceDomain,
                                  label: sourceDomain,
                                },
                              ]
                            : []),
                        ]}
                        onChange={resetSourceFiles}
                      />
                    </Form.Item>
                    <Space align="start" wrap>
                      <Form.Item
                        name={['configuration', 'sourceFormat']}
                        label="源证书格式"
                        rules={[{ required: true }]}
                      >
                        <Select
                          style={{ width: 200 }}
                          options={sourceFormats}
                          onChange={resetSourceFiles}
                        />
                      </Form.Item>
                      <Button
                        style={{ marginTop: 30 }}
                        loading={sourceLoading}
                        disabled={
                          !sourceDomain ||
                          !sourceFormat ||
                          sourceCertificatesLoading
                        }
                        onClick={readSourceFiles}
                      >
                        读取源文件
                      </Button>
                    </Space>
                    {sourceListing && (
                      <Alert
                        type="info"
                        title={`已读取 ${sourceListing.domain} 的 ${sourceListing.format.toUpperCase()} 文件包，共 ${sourceListing.files.length} 个源文件。`}
                        description="仅展示文件名称和类型，不展示证书私钥或密码文件内容。"
                        style={{ marginBottom: 16 }}
                      />
                    )}
                  </>
                ) : (
                  <Alert
                    type="info"
                    title="当前目标沿用材料角色映射"
                    description={
                      <Button
                        type="link"
                        onClick={() => {
                          form.setFieldValue(
                            ['configuration', 'sourceFormat'],
                            'nginx',
                          );
                          resetSourceFiles();
                        }}
                      >
                        改用绑定域名和格式配置
                      </Button>
                    }
                    style={{ marginBottom: 16 }}
                  />
                ))}
              <Space align="start" wrap>
                <Form.Item
                  name={['configuration', 'shell']}
                  label="远程命令环境"
                  rules={[{ required: true }]}
                >
                  <Select
                    style={{ width: 200 }}
                    options={
                      executor?.operatingSystem === 'Windows'
                        ? [
                            { value: 'PowerShell', label: 'PowerShell' },
                            { value: 'cmd', label: 'cmd.exe' },
                          ]
                        : [
                            { value: 'sh', label: 'sh' },
                            { value: 'bash', label: 'bash' },
                          ]
                    }
                  />
                </Form.Item>
                {!harbor && (
                  <Form.Item
                    name={['configuration', 'createDirectory']}
                    label="允许创建输出目录"
                    valuePropName="checked"
                  >
                    <Switch />
                  </Form.Item>
                )}
              </Space>
              <Form.Item
                name={['configuration', 'outputDirectory']}
                label={sourceMode ? '默认输出目录' : '证书输出目录'}
                rules={[{ required: !sourceMode, message: '请输入输出目录' }]}
                extra={
                  harbor
                    ? '请按 Harbor 现有代理挂载填写；证书链和私钥可分别指定目录。'
                    : sourceMode
                      ? '文件可以分别指定目录；未单独填写时使用此目录。可浏览选择任意有权限访问的目录。'
                      : '可使用 {domain}、{certificateId}、{fingerprintShort}，计划会显示最终路径。'
                }
              >
                <Input
                  placeholder={
                    executor?.operatingSystem === 'Windows'
                      ? 'D:\nginxconfssl{domain}'
                      : '/etc/nginx/ssl/{domain}'
                  }
                />
              </Form.Item>
              {linux && (
                <Button
                  onClick={() => void openBrowser()}
                  style={{ marginBottom: 16 }}
                >
                  浏览远程目录
                </Button>
              )}
              <Form.List
                name={['configuration', 'files']}
                rules={[
                  {
                    validator: async (_, values) => {
                      if (!values?.length)
                        throw new Error('至少配置一个输出文件');
                      if (
                        harbor &&
                        (![2, 4].includes(values.length) ||
                          values.filter(
                            (file: { role: string }) =>
                              file.role === 'FullChain',
                          ).length !==
                            values.length / 2 ||
                          values.filter(
                            (file: { role: string }) =>
                              file.role === 'PrivateKey',
                          ).length !==
                            values.length / 2)
                      )
                        throw new Error(
                          'Harbor 必须配置代理证书链与私钥，可再同步一对源证书副本',
                        );
                    },
                  },
                ]}
              >
                {(fields, { add, remove }, { errors }) => (
                  <>
                    <div style={{ fontWeight: 600, marginBottom: 8 }}>
                      证书文件映射
                    </div>
                    {fields.map((field) =>
                      sourceMode ? (
                        <div
                          key={field.key}
                          style={{
                            padding: 12,
                            border: '1px solid #f0f0f0',
                            borderRadius: 6,
                            marginBottom: 12,
                          }}
                        >
                          <Form.Item
                            name={[field.name, 'sourceFileName']}
                            label={`源文件 ${field.name + 1}`}
                            rules={[
                              {
                                required: true,
                                message: '请选择文件包中的源文件',
                              },
                            ]}
                          >
                            <Select
                              showSearch={{ optionFilterProp: 'label' }}
                              options={
                                sourceListing?.files.map((file) => ({
                                  value: file.name,
                                  label: `${file.name} · ${sourceRoleNames[file.role] || file.role}`,
                                })) ||
                                (
                                  form.getFieldValue([
                                    'configuration',
                                    'files',
                                  ]) as DeploymentTargetConfiguration['files']
                                )
                                  .filter((mapping) => mapping.sourceFileName)
                                  .map((mapping) => ({
                                    value: mapping.sourceFileName || '',
                                    label: `${mapping.sourceFileName} · ${sourceRoleNames[mapping.role] || mapping.role}`,
                                  }))
                              }
                              onChange={(name) => {
                                const file = sourceListing?.files.find(
                                  (item) => item.name === name,
                                );
                                if (!file) return;
                                form.setFieldValue(
                                  [
                                    'configuration',
                                    'files',
                                    field.name,
                                    'role',
                                  ],
                                  file.role,
                                );
                                form.setFieldValue(
                                  [
                                    'configuration',
                                    'files',
                                    field.name,
                                    'fileName',
                                  ],
                                  file.name.split('/').pop(),
                                );
                              }}
                            />
                          </Form.Item>
                          <Form.Item
                            name={[field.name, 'role']}
                            hidden
                            rules={[{ required: true }]}
                          >
                            <Input />
                          </Form.Item>
                          <Space align="start" wrap>
                            <Form.Item
                              name={[field.name, 'directory']}
                              label={`目标目录 ${field.name + 1}`}
                              rules={[
                                {
                                  validator: async (_, value) => {
                                    if (
                                      !value &&
                                      !form.getFieldValue([
                                        'configuration',
                                        'outputDirectory',
                                      ])
                                    )
                                      throw new Error(
                                        '请填写目标目录或默认输出目录',
                                      );
                                  },
                                },
                              ]}
                            >
                              <Input
                                style={{ width: 360 }}
                                placeholder="留空使用默认输出目录"
                              />
                            </Form.Item>
                            <Form.Item
                              name={[field.name, 'fileName']}
                              label={`目标文件名 ${field.name + 1}`}
                              rules={[
                                { required: true, message: '请输入目标文件名' },
                              ]}
                            >
                              <Input
                                style={{ width: 300 }}
                                placeholder="可选择现有文件或输入新名称"
                              />
                            </Form.Item>
                          </Space>
                          <Space>
                            <Button
                              onClick={() => void openBrowser(field.name)}
                            >
                              浏览目标文件 {field.name + 1}
                            </Button>
                            <Button
                              type="text"
                              aria-label="移除文件映射"
                              icon={<MinusCircleOutlined />}
                              onClick={() => remove(field.name)}
                            />
                          </Space>
                        </div>
                      ) : (
                        <div key={field.key}>
                          {harbor && field.name % 2 === 0 && (
                            <div
                              style={{ fontWeight: 600, margin: '12px 0 8px' }}
                            >
                              {field.name === 0
                                ? '代理实际挂载证书（第一对）'
                                : 'Harbor 源证书副本（第二对）'}
                            </div>
                          )}
                          <Space align="start" wrap>
                            <Form.Item
                              name={[field.name, 'role']}
                              rules={[{ required: true }]}
                            >
                              <Select
                                style={{ width: 180 }}
                                options={
                                  harbor
                                    ? fileRoles.filter((item) =>
                                        ['FullChain', 'PrivateKey'].includes(
                                          item.value,
                                        ),
                                      )
                                    : fileRoles
                                }
                                disabled={harbor}
                                aria-label="材料角色"
                              />
                            </Form.Item>
                            {(linux || harbor) && (
                              <Form.Item
                                name={[field.name, 'directory']}
                                rules={
                                  harbor && field.name >= 2
                                    ? [
                                        {
                                          required: true,
                                          message:
                                            '请输入 harbor.yml 中该源文件所在目录',
                                        },
                                        {
                                          pattern: /^\//,
                                          message: '请输入 Linux 绝对目录',
                                        },
                                      ]
                                    : []
                                }
                              >
                                <Input
                                  aria-label={`文件 ${field.name + 1} 的目标目录`}
                                  style={{ width: 280 }}
                                  placeholder={
                                    harbor && field.name >= 2
                                      ? 'harbor.yml 中该源文件所在目录'
                                      : '留空使用证书输出目录'
                                  }
                                />
                              </Form.Item>
                            )}
                            <Form.Item
                              name={[field.name, 'fileName']}
                              rules={[
                                { required: true, message: '请输入文件名' },
                              ]}
                            >
                              <Input
                                aria-label={`文件 ${field.name + 1} 的目标文件名`}
                                style={{ width: 380 }}
                                placeholder="文件名，例如 fullchain.pem"
                              />
                            </Form.Item>
                            {!harbor && (
                              <Button
                                type="text"
                                aria-label="移除文件映射"
                                icon={<MinusCircleOutlined />}
                                onClick={() => remove(field.name)}
                              />
                            )}
                            {linux && (
                              <Button
                                onClick={() => void openBrowser(field.name)}
                              >
                                浏览文件
                              </Button>
                            )}
                          </Space>
                        </div>
                      ),
                    )}
                    <Form.ErrorList errors={errors} />
                    {harbor && (
                      <Button
                        type="dashed"
                        onClick={() => {
                          if (fields.length > 2) remove([2, 3]);
                          else {
                            // 源路径必须单独填写，避免误写到代理证书的同一路径。
                            const files = form.getFieldValue([
                              'configuration',
                              'files',
                            ]);
                            form.setFieldValue(
                              ['configuration', 'files'],
                              [
                                ...files,
                                {
                                  role: 'FullChain',
                                  directory: '',
                                  fileName: '',
                                },
                                {
                                  role: 'PrivateKey',
                                  directory: '',
                                  fileName: '',
                                },
                              ],
                            );
                          }
                        }}
                      >
                        {fields.length > 2
                          ? '取消同步 Harbor 源证书副本'
                          : '同步 Harbor 源证书副本'}
                      </Button>
                    )}
                    {!harbor && (
                      <Button
                        type="dashed"
                        icon={<PlusOutlined />}
                        disabled={sourceMode && !sourceListing}
                        onClick={() =>
                          add(
                            sourceMode
                              ? {
                                  sourceFileName: '',
                                  role: '',
                                  directory: '',
                                  fileName: '',
                                }
                              : { role: 'FullChain', fileName: '' },
                          )
                        }
                      >
                        添加输出文件
                      </Button>
                    )}
                  </>
                )}
              </Form.List>
              {!sourceMode && !harbor && (
                <Form.Item
                  name="pfxPassword"
                  label="PFX 密码"
                  style={{ marginTop: 16 }}
                  extra="仅输出 PFX 时使用，服务端加密保存。"
                >
                  <Input.Password
                    autoComplete="new-password"
                    placeholder={
                      target?.pfxPasswordConfigured
                        ? '已配置；留空保留原密码'
                        : '可选'
                    }
                  />
                </Form.Item>
              )}
              {!harbor && (
                <>
                  <CommandFields
                    name="validationCommands"
                    title="配置验证命令"
                  />
                  <CommandFields name="postCommands" title="后置命令" post />
                </>
              )}
            </>
          )}
          <div style={{ marginTop: 24, marginBottom: 12, fontWeight: 600 }}>
            {harbor
              ? '业务 HTTPS 生效验证（必填）'
              : '业务 HTTPS 生效验证（可选）'}
          </div>
          {ignoresManagementCertificateErrors && (
            <div style={{ marginBottom: 12, color: '#666' }}>
              {`${synology ? '群晖' : '雷池'}证书和证书链上传并读回一致即部署成功；业务 HTTPS 检查仅作提示，不影响部署结果。`}
            </div>
          )}
          <Space align="start" wrap>
            <Form.Item
              name={['configuration', 'verificationHost']}
              label="连接主机或 IP"
              rules={
                harbor
                  ? [
                      {
                        required: true,
                        message: '请输入业务 HTTPS 连接主机或 IP',
                      },
                    ]
                  : []
              }
            >
              <Input style={{ width: 240 }} placeholder="与管理地址分开配置" />
            </Form.Item>
            <Form.Item
              name={['configuration', 'verificationPort']}
              label="HTTPS 端口"
              rules={
                harbor
                  ? [{ required: true, message: '请输入业务 HTTPS 端口' }]
                  : []
              }
            >
              <InputNumber min={1} max={65535} />
            </Form.Item>
            <Form.Item
              name={['configuration', 'verificationServerName']}
              label="SNI 域名"
              dependencies={harbor ? [['configuration', 'sourceDomain']] : []}
              rules={
                harbor
                  ? [
                      { required: true, message: '请输入业务 SNI 域名' },
                      {
                        validator: async (_, value) => {
                          if (
                            normalizeDeploymentDomain(value) !==
                            normalizeDeploymentDomain(
                              form.getFieldValue([
                                'configuration',
                                'sourceDomain',
                              ]),
                            )
                          )
                            throw new Error(
                              'SNI 域名必须与 Harbor 绑定域名一致',
                            );
                        },
                      },
                    ]
                  : []
              }
            >
              <Input style={{ width: 240 }} />
            </Form.Item>
          </Space>
          <Space align="start" wrap>
            <Form.Item
              name={['configuration', 'connectionTimeoutSeconds']}
              label="连接超时秒数"
            >
              <InputNumber min={1} max={300} />
            </Form.Item>
            <Form.Item
              name={['configuration', 'operationTimeoutSeconds']}
              label="操作超时秒数"
            >
              <InputNumber min={1} max={3600} />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
      <RemoteFileBrowser
        open={open && !!browser}
        mode={browser?.mode}
        initialDirectory={browser?.directory}
        initialFileName={browser?.fileName}
        loadDirectory={loadDirectory}
        onTrustHost={(fingerprint) =>
          form.setFieldValue(
            ['configuration', 'hostKeyFingerprint'],
            fingerprint,
          )
        }
        onSelect={selectRemoteFile}
        onCancel={() => setBrowser(undefined)}
      />
    </>
  );
}
