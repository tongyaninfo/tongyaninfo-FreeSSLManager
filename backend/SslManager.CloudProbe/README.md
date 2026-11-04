# 手动隔离云验证

本工具只验证腾讯云公网证书和 Let's Encrypt 公网 ACME 证书，DNS 验证记录统一写入 Cloudflare。ACME 只能导入用户已有外部账号，工具不注册、生成或维护外部账号。

工具**不内置任何真实测试域名**：默认使用 RFC 2606 保留域名 `example.com`，真实执行时必须用 `--domain` 指定操作者自己持有、并已接入对应 DNS 平台（如 Cloudflare）的域名，例如 `--domain your-test.example.com`。`--domain` 只接受普通 ASCII 域名（字母、数字、点和连字符），不接受 URL、路径或通配符。

默认只输出计划，不读取凭据、业务库或密钥，不创建输出目录。只有显式指定 `--execute` 后才执行真实云请求。

```sh
dotnet run --project backend/SslManager.CloudProbe/SslManager.CloudProbe.csproj -- --run tencent
```

真实验证需要提供以下路径，所有秘密都从文件或原密文读取，不能作为命令行参数传入：

```sh
dotnet run --project backend/SslManager.CloudProbe/SslManager.CloudProbe.csproj -- \
  --run tencent \
  --domain your-test.example.com \
  --credentials-file /absolute/path/cloudflare-api-token.md \
  --source-db /absolute/path/ssl-manager.db \
  --source-keys /absolute/path/keys \
  --output-directory /absolute/path/cloud-probe \
  --execute
```

后续共用该目录运行 `acme-staging` 或 `acme-production` 时必须加 `--resume`，也可用它继续等待同一申请。ACME 每次真实执行必须显式提供 `--acme-account-file /absolute/path/existing-acme-account.json`；缺少文件参数会在读取其他路径、创建输出目录或调用云服务前停止。工具只读取此明确指定文件，不搜索其他账号或秘密路径。可选 `--email` 仅作本地联系备注，不用于注册或修改外部账户，也不从腾讯或 SSO 身份推导账号资料。可选 `--tencent-account-id` 固定腾讯来源账号，否则按账号 ID 升序选择第一个已启用证书账号，不再按任何特定域名筛选账号。默认等待 30 分钟，`--timeout-minutes` 允许 1～120 分钟。

既有 ACME 账号文件包含且仅包含以下字段；示例中的 URL 和私钥必须替换为用户自己已有的匹配账号资料：

```json
{
  "directoryUrl": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "accountUrl": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345",
  "accountPrivateKeyPem": "<用户已有的 PEM 账号私钥>"
}
```

支持 RSA 2048/3072/4096 或 EC P-256/P-384 私钥。目录必须与运行目标相符，账号 URL 必须属于该 CA；公钥、错误主机、未知 JSON 字段和不受支持密钥均被拒绝。恢复时核对文件与原本地配置的账号 URL、目录及公钥身份相同，拒绝替换已有申请所属外部账号。没有现有账号材料时暂停 ACME 测试，不能以自动注册或生成账户密钥代替用户提供。

`--auto-cleanup`（或 `--auto-cleanup true`）在本次新申请中启用现有 Worker 的自动清理，只有本轮创建且 ID、名称、类型、值、所有权仍精确匹配的临时 DNS 记录具备清理资格；复用、共享、代理已变化或内容被改动的记录保持保护。工具会等到申请与清理均完成后才报告 `VERIFIED`。默认 `false`，`--auto-cleanup false` 可显式保留。恢复时沿用原申请配置，显式指定与原值不同会停止，不会改写旧申请的删除授权。

原库使用 SQLite `Mode=ReadOnly` 和基线字段的原始 SELECT，只接受 10 条迁移、终点 `20261102133402_AddMcpServices`。原 DataProtection 配置禁用自动生成密钥，仅用于解密选定腾讯账号。新输出库独立迁移并使用新密钥环重新保护凭据。恢复时要求输出库结构与当前源码一致，不自动升级已有探测库。

Cloudflare 凭据仅解析 `[API 令牌]` 段内完整的 `Token=` 行，允许 35～256 个 ASCII 字母、数字、下划线或连字符，支持成对反引号；遇到后续段立即停止，因此不会误取 R2 凭证。`--self-test-credentials-parser` 仅使用内存合成文本验证 53 字符令牌、长度边界、CRLF、跨段与错误字段拒绝，并验证合成 ACME 既有账号文件及 EC/RSA 算法、目录与账号 URL 的匹配；不读取真实文件或调用云端。

申请前、执行中和未知结果均保留持久台账。恢复时优先查找原申请，不重复创建订单或生成配套私钥。验证记录默认保留；显式启用后只由既有 Worker 精确清理本轮拥有的临时 DNS。工具不删除或吊销证书、不执行部署。成功后在内存下载 Nginx 包，检查域名、有效期和私钥匹配，输出 `summary.json` 中的状态、清理状态、有效期和证书指纹；下载包及私钥不会明文落盘。输出库和 `keys` 必须成套保留，未经用户确认不要清理。

`--execute` 代表真实证书申请和 DNS 创建，仅在获得对应域名和平台操作授权后由操作者运行。ACME 必须使用已导入的既有账号，工具不创建、注册、更新或注销外部账户。工具不会注册后台任务，也不会自行触发其他平台测试。
