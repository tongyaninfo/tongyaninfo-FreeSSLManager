# 通研免费 SSL 管理系统（Tongyan FreeSSL Manager）

**把证书申请、DNS 验证、部署和到期维护，放进一个工作台。**

通研免费 SSL 管理系统面向需要维护多个域名、云账号和服务的开发者与运维人员：集中管理腾讯云、阿里云、Cloudflare 的证书与 DNS 资源，自动完成 Let's Encrypt ACME 签发，预览并批量部署到自建服务，按周期自动申请与部署，并在到期前通过 SMTP 提醒。同时提供标准 MCP 接口，让支持 MCP 的 AI Agent 在授权范围内查询状态、准备证书申请和部署计划。

本仓库包含**后端 + Web 前端**完整源码，以 Apache License 2.0 开源。桌面客户端不在本仓库范围内。

**当前版本：[1.1.0](CHANGELOG.md)**（以根目录 [VERSION](VERSION) 为准）

## 能力概览

| 模块 | 能力 |
| --- | --- |
| 云账号 | 腾讯云、阿里云账号接入；按"证书管理 / DNS 管理"用途分别启用；连接检测与资源同步 |
| 域名与 DNS | 同步腾讯云 DNSPod、阿里云 DNS、Cloudflare 托管域与解析记录；签发账号与 DNS 验证账号可独立选择；签发后精确清理本轮临时记录 |
| 证书 | 申请免费公网单域证书（腾讯云、阿里云、Let's Encrypt ACME），跟踪验证与签发进度；按平台和状态提供下载、吊销、取消或清理 |
| 部署 | 保存并测试目标，预览文件、资源和执行动作，批量部署并跟踪步骤与验证结果 |
| 周期计划 | 按小时、天、月申请新证书并部署；支持立即执行、暂停、恢复与运行历史 |
| 邮件 | SMTP 设置、测试邮件、发件记录、到期前提醒与重复汇总 |
| 配置迁移 | 配置 JSON 导出、预览冲突、仅新增或按名称更新；导入后重新加密并保持停用 |
| 权限与审计 | 管理员 / 只读用户，管理操作审计；MCP 客户端独立授权与调用审计 |
| MCP | 标准 Streamable HTTP 接口：只读查询与受控操作工具；API Key + OAuth 授权码 / PKCE / 机器凭据；按工具、账号、域名、部署目标授权 |
| 界面体验 | 简体中文 / English；浅色、深色、跟随系统；表格列与密度偏好 |

### 平台与部署支持

| 类型 | 当前支持 |
| --- | --- |
| 公网证书 | 腾讯云、阿里云、Let's Encrypt ACME；当前免费申请面向单域名 |
| DNS 托管与验证 | 腾讯云 DNSPod、阿里云 DNS、Cloudflare |
| 手动部署 | Linux SSH、Windows SSH、雷池社区版 9.x、群晖 DSM 7.x、Harbor 2.x Docker Compose |
| 周期申请与部署 | 腾讯云、阿里云、ACME；目标为 Linux SSH、雷池、群晖、Harbor |
| 使用方式 | Web（本仓库后端 + 前端） |

Cloudflare 在本系统中提供 DNS 管理，不提供 Origin CA 或边缘证书签发。Windows SSH 目前仅支持手动部署。

## 技术栈与仓库结构

| 组件 | 技术栈 |
| --- | --- |
| 后端 | .NET 10、ASP.NET Core、Entity Framework Core 10、SQLite（12 个累计迁移）、OpenIddict、MailKit、SSH.NET、ModelContextProtocol.AspNetCore |
| 前端 | React 19、UmiJS Max 4、Ant Design 6、Tailwind CSS 4、TypeScript、Vitest、Biome |
| CI | GitHub Actions（后端 restore/build/test + 前端 npm ci/lint/test/build） |

```text
.
├── backend/
│   ├── SslManager.Api/          # Web 后端：Controllers、Service、Workers、Models、Data/Migrations、Resources
│   ├── SslManager.CloudProbe/   # 手动、显式执行的隔离云验证工具（默认仅输出计划）
│   ├── SslManager.Tests/        # xUnit 测试
│   └── SslManager.slnx
├── frontend/                    # React + UmiJS Max 管理界面
├── .github/workflows/ci.yml     # 持续集成
├── global.json                  # .NET SDK 版本固定
├── VERSION                      # 当前源码版本
└── README.md / LICENSE / NOTICE / CONTRIBUTING.md / SECURITY.md / CHANGELOG.md
```

## 快速开始

### 前置条件

- [.NET SDK 10.0.x](https://dotnet.microsoft.com/download)（`global.json` 固定 10.0.300，允许 10.0.x 内升级）
- [Node.js](https://nodejs.org/) >= 22 与 npm（前端使用 `package-lock.json`，请使用 npm，勿混用其他包管理器）
- 一个可用的云厂商账号（申请证书、创建 DNS 记录会产生对应平台的真实操作）

### 1. 启动后端

```sh
dotnet restore backend/SslManager.slnx
dotnet build backend/SslManager.slnx
dotnet run --project backend/SslManager.Api/SslManager.Api.csproj
```

默认监听 `http://localhost:5000`。首次启动时后端会自动创建 SQLite 数据库并应用全新数据库的全部迁移，具体数据库位置由 `ConnectionStrings:Default` 决定。启动后通过前端页面完成初始化：首次打开系统时创建管理员账号，**系统没有预置默认密码**。

如需指定监听地址或使用 HTTPS，设置以下环境变量（示例见 [.env.example](.env.example)）：

```sh
ASPNETCORE_URLS=https://localhost:5001 dotnet run --project backend/SslManager.Api/SslManager.Api.csproj
```

已有数据库的后续迁移不会在启动时静默执行：如果数据库落后于当前源码的迁移基线，启动会明确报错并停止，需先成套备份数据库与密钥，再按目标迁移显式升级。

### 2. 启动前端

```sh
cd frontend
npm ci
npm run dev
```

开发服务器默认把 `/api` 代理到 `https://localhost:5001`。如果后端使用其他地址（如上面的默认 `http://localhost:5000`），通过环境变量指定：

```sh
SSL_API_PROXY=http://localhost:5000 npm run dev
```

生产构建：

```sh
cd frontend
npm run build        # 产物输出到 frontend/dist/
```

将 `frontend/dist/` 交由静态文件服务器托管，并把 `/api` 反向代理到后端即可。公网部署时请启用 HTTPS 并限制管理入口访问来源。

## 配置说明

### 后端配置

后端默认读取 `backend/SslManager.Api/appsettings.json`（相对路径、localhost，不含任何真实凭据）：

```json
{
  "ConnectionStrings": { "Default": "Data Source=App_Data/ssl-manager.db" },
  "Storage": { "KeyDirectory": "App_Data/keys" },
  "Worker": { "PollSeconds": 15 },
  "Logging": { "LogLevel": { "Default": "Information", "Microsoft.AspNetCore": "Warning" } },
  "AllowedHosts": "localhost;127.0.0.1"
}
```

完整的可配置键与占位符见 [`backend/SslManager.Api/appsettings.Example.json`](backend/SslManager.Api/appsettings.Example.json)，环境变量覆盖方式见 [`.env.example`](.env.example)。常用键：

| 配置键 | 说明 |
| --- | --- |
| `ConnectionStrings:Default` | SQLite 连接串，默认 `App_Data/ssl-manager.db` |
| `Storage:KeyDirectory` | DataProtection 密钥目录，默认 `App_Data/keys` |
| `Worker:PollSeconds` | 后台任务轮询间隔（秒），默认 15 |
| `AllowedHosts` | 允许的 Host 头；生产环境改为实际域名 |
| `Mcp:OAuth:Issuer` | MCP OAuth 的 HTTPS issuer，例如 `https://freessl.example.com` |
| `Mcp:OAuth:CertificatePath` / `CertificatePassword` | MCP OAuth 签名证书（RSA >= 2048）的 PFX 路径与密码占位符 |
| `Mcp:OAuth:CertificatePemPath` / `PrivateKeyPemPath` | 或使用 PEM 证书 + 私钥，二者必须同时配置 |
| `Mcp:TrustedProxyAddresses` / `TrustedProxyNetworks` | 反向代理后需要真实来源地址时配置的可信代理 |
| `Mail:AllowedPrivateHosts` | 需要连接内网 SMTP 主机时精确配置的主机名 |

**真实凭据一律不写入配置文件与源码**，而是在界面中录入、由后端加密保存；配置文件中只保留路径、localhost 与 `CHANGE_ME` 类占位符。

### 云厂商凭据配置指引

在系统"配置管理"中新增账号，按用途启用"用于证书管理"和/或"用于 DNS 管理"，保存前先测试连接：

| 平台 | 所需凭据 | 建议权限 |
| --- | --- | --- |
| 腾讯云 | SecretId、SecretKey | 仅授权 SSL 证书与 DNSPod 所需接口的最小权限子账号；如使用其他来源账号可只读 |
| 阿里云 | AccessKey ID、AccessKey Secret | 仅授权 SSL 证书与云解析 DNS 所需接口的最小权限 RAM 用户 |
| Cloudflare | API Token | 仅授予对应 Zone 的 DNS 编辑权限；不要使用全局 API Key |
| Let's Encrypt ACME | 用户既有 ACME 账号 JSON（`directoryUrl`、`accountUrl`、`accountPrivateKeyPem`） | 工具只导入既有账号，不注册、生成或维护外部账号 |

上述凭据在保存后使用实例的 DataProtection 密钥加密，界面默认只显示掩码。请使用最小权限凭据、定期轮换，并避免在截图、日志、工单或 Issue 中出现真实值。

### SMTP 与 MCP OAuth

- SMTP：在"邮件管理"中填写主机、端口、加密方式、账号与授权码并发送测试邮件；授权码属于敏感凭据，只通过界面录入。
- MCP：默认关闭。启用 OAuth 需要配置有效的 HTTPS issuer 与 RSA 证书（见上表）；也可使用 API Key 直连。MCP 是外部 AI 客户端访问证书业务的边界，启用后需按工具、账号、域名与部署目标逐项授权。

## 数据、SQLite 与密钥备份

- 所有业务数据保存在 SQLite 数据库（默认 `App_Data/ssl-manager.db`）；云凭据、证书私钥、ACME 材料等敏感字段使用 DataProtection 密钥（默认 `App_Data/keys/`）加密。
- **备份时必须同时保留数据库与密钥目录，二者成套才有恢复价值**：只有数据库没有密钥无法解密凭据与证书材料；只有密钥没有数据库没有业务数据。
- 备份文件包含敏感数据，请按敏感资料管理：不进入版本库、不放入公开网盘链接、不通过聊天工具明文传输。恢复前先在隔离环境验证。
- 从 `1.1.0` 起数据库包含 12 个累计 EF Core 迁移；升级源码到包含新迁移的版本时，需先成套备份，再按明确目标迁移显式升级，启动过程不会对既有数据库静默升级。
- 配置导出 JSON 含明文连接凭据，不等同于完整备份，也不包含 MCP API Key；跨实例迁移时先预览、后导入，导入项保持停用。

## 隐私与安全边界

- 本项目**不包含遥测上报**，不会向项目维护者发送使用数据、域名或证书信息。
- 仓库源码、测试与示例中不包含真实凭据、真实内网地址或真实测试域名：示例域名统一为 `example.com`（RFC 2606），示例 IP 统一为 `192.0.2.0/24`（RFC 5737）。
- 云厂商凭据、SMTP 授权码、ACME 账号私钥、证书私钥均不写入前端包或仓库，运行时加密保存；日志与 MCP 审计记录对敏感字段做有界脱敏。
- 请只在获得授权的域名、账号与主机上执行真实证书申请、DNS 操作与部署；误操作会产生真实云平台操作与费用。
- 安全漏洞报告方式见 [SECURITY.md](SECURITY.md)。

## 开发与测试

```sh
# 后端构建与测试
dotnet build backend/SslManager.slnx
dotnet test backend/SslManager.Tests/SslManager.Tests.csproj

# 前端（在 frontend/ 下）
npm ci
npm run tsc
npm run biome:lint
npm test
npm run build
```

隔离云验证工具 `backend/SslManager.CloudProbe/` 默认只输出计划、不读取凭据、不创建文件；确认目标后显式加 `--execute` 才会发起真实云请求，使用说明见 [`backend/SslManager.CloudProbe/README.md`](backend/SslManager.CloudProbe/README.md)。

更多约定见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 文档

| 文档 | 内容 |
| --- | --- |
| [CHANGELOG.md](CHANGELOG.md) | 版本变更记录 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献流程、代码风格、本地验证 |
| [SECURITY.md](SECURITY.md) | 安全策略、漏洞报告、安全边界 |
| [NOTICE](NOTICE) | 第三方组件许可声明 |
| [LICENSE](LICENSE) | Apache License 2.0 全文 |
| [frontend/docs/cheatsheet.zh-CN.md](frontend/docs/cheatsheet.zh-CN.md) | 使用文档（前端欢迎页内置中文版） |
| [frontend/docs/cheatsheet.en-US.md](frontend/docs/cheatsheet.en-US.md) | User guide (English) |

## 参与贡献

欢迎提交 Issue 与 Pull Request。提交前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，并在 PR 中如实说明验证范围；不要附带真实凭据、真实域名解析记录或生产数据。

## 许可证

本项目以 [Apache License 2.0](LICENSE) 发布。第三方组件仍遵循各自许可证，主要声明见 [NOTICE](NOTICE)。

## 免责声明

本项目按"现状"提供，不提供任何明示或暗示的担保。证书申请、DNS 修改与远程部署都是对真实基础设施的写操作：使用者应自行确认云平台授权、配额与费用，并为生产环境配置备份、监控与回滚方案。因使用本软件造成的任何直接或间接损失，由使用者自行承担。
