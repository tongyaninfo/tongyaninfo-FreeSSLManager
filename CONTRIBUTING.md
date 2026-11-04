# 参与贡献

感谢关注「通研免费 SSL 管理系统」。本文说明如何报告问题、提交改动与本地验证要求。参与本项目即表示同意遵守基本的开源协作礼仪，并对不同经验背景的参与者保持尊重。

## 报告问题

- 使用 GitHub Issues 提交缺陷或功能建议，优先使用仓库提供的 Issue 模板。
- 提交前先搜索是否已有相同问题。
- 描述中只包含**合成示例**：不要粘贴真实云厂商密钥、SMTP 授权码、ACME 账号私钥、证书内容、数据库文件、内网地址或真实域名解析记录。
- 安全漏洞不要开公开 Issue，按 [SECURITY.md](SECURITY.md) 的渠道报告。

## 开发环境

| 组件 | 版本要求 |
| --- | --- |
| .NET SDK | 10.0.x（`global.json` 固定 10.0.300，允许 10.0.x 内升级） |
| Node.js | >= 22（推荐使用当前 LTS 或更高版本） |
| npm | 随 Node.js 提供，使用 `package-lock.json` |

## 分支与提交

- 从 `main` 切出分支，命名 `feature/<短主题>`、`fix/<短主题>`、`docs/<短主题>`、`chore/<短主题>`。
- 提交信息采用 `type(scope): 描述` 格式，`type` 取 `feat`、`fix`、`docs`、`style`、`refactor`、`perf`、`test`、`chore`、`ci`、`revert`、`merge` 之一，冒号后一个空格，描述使用中文且不超过 50 字。
- 一个提交只做一件事；不要把格式化、依赖升级与功能改动混在一起。
- 不要提交 `App_Data/`、数据库、密钥、日志、`node_modules/`、`bin/`、`obj/`、`dist/` 或任何真实凭据。

## 代码风格

- C#：4 空格缩进，启用可空引用类型，保持现有文件组织与中文注释风格；改动 EF 迁移后必须同步更新模型快照，历史迁移不得删改或改名。
- 前端：2 空格缩进，遵守 `frontend/biome.json`；提交前运行 `npm run tsc` 与 `npm run biome:lint`。
- 文档：中文标点、简洁明确；命令、路径、字段名使用反引号；不写个人绝对路径与内网地址。

## 本地验证

提交 PR 前至少运行以下检查，并在 PR 中如实填写结果（未运行的项要说明原因）：

```sh
# 后端
dotnet build backend/SslManager.slnx
dotnet test backend/SslManager.Tests/SslManager.Tests.csproj

# 前端（在 frontend/ 下）
npm ci
npm run tsc
npm run biome:lint
npm test
npm run build
```

涉及证书申请、DNS 操作、云厂商账号或部署执行器的改动，必须在**隔离的测试账号**中验证，并在 PR 中说明验证范围与未覆盖的边界；不得把生产凭据或真实业务数据用于测试。

## Pull Request

- 使用仓库的 PR 模板，说明改动目的、影响范围、验证方式与回滚方式。
- PR 中"本人亲自验证""已审阅改动"等确认项必须由提交者本人如实填写，不得代填或由自动化工具代填。
- 涉及数据库迁移、凭据处理、认证授权、MCP 权限边界、部署命令执行的改动，需要更详细的说明与回归测试。
- 维护者可能要求拆分过大的 PR，或补充测试与文档后再合并。

## 许可证

提交代码即表示你同意以本项目的 [Apache License 2.0](LICENSE) 授权你的贡献，并保证你有权提交该内容。
