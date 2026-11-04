# 通研免费 SSL 管理系统 · 前端

本目录是「通研免费 SSL 管理系统」的 Web 管理界面：云账号与 DNS 托管、证书申请与到期提醒、部署目标与批量部署、周期计划、邮件提醒、MCP 接入和调用审计等页面。

技术栈：React 19、UmiJS Max 4、Ant Design 6、Tailwind CSS 4、TypeScript、Vitest、Biome。

## 本地开发

前置条件：Node.js >= 22，npm（使用 `package-lock.json`，请勿混用其他包管理器）。

```sh
npm ci                 # 按锁文件安装依赖
npm run dev            # 启动开发服务器；默认代理到 https://localhost:5001
npm run tsc            # TypeScript 类型检查
npm run biome:lint     # Biome 静态检查
npm test               # Vitest 单元测试
npm run build          # 生产构建，产物输出到 dist/
```

开发代理默认连接本机后端；如后端地址不同，设置环境变量 `SSL_API_PROXY`，见 `config/proxy.ts`。生产环境由同源反向代理转发 `/api`。

首次打开系统时创建管理员账号，没有预置通用密码。云厂商凭据、SMTP 授权码、ACME 账号私钥等敏感配置通过界面录入，由后端加密保存，不要写进前端代码或仓库。

## 目录结构

| 目录 | 内容 |
| --- | --- |
| `src/pages/` | 业务页面（证书、域名、账号配置、部署、计划、邮件、MCP、用户等） |
| `src/services/` | 后端接口封装 |
| `src/locales/` | 中英文文案 |
| `config/` | Umi 配置、路由与开发代理 |
| `docs/` | 内置使用文档（欢迎页渲染的 Markdown） |
| `mock/` | 本地演示数据 |
| `public/` | 静态资源与品牌 Logo |
| `tests/` | Vitest 测试环境与 mock |
| `tools/` | 构建期本地替代包（MIT，见根目录 NOTICE） |

## 构建工具依赖

本项目保留 Ant Design CLI 的诊断能力，终端横幅使用 `tools/cli-banner/` 的原创 MIT 纯文本实现；Umi 的 Stagewise 开发工具栏固定关闭，并使用 `tools/toolbar-disabled/` 的原创 MIT 包替代。替代包不包含原工具代码或字体，误调用工具栏会明确报错。

`package.json` 通过直接本地依赖与 npm `overrides` 同时覆盖两条依赖链。同名依赖键只用于兼容上游解析，实际包身份分别为 `@tongyan/build-toolbar-disabled`、`@tongyan/build-cli-banner`。请使用 npm 和锁文件安装，勿仅关闭工具栏配置或手工修改 `node_modules`。

```sh
npm run check:build-dependencies
npm run test:build-dependencies
node scripts/check-build-dependencies.mjs --lock-only
node scripts/check-build-dependencies.mjs --artifact dist
```

安装准备与所有构建入口先检查锁文件及实际解析路径；构建完成后检查静态产物，拒绝原始工具代码进入分发目录。检查只针对这两项依赖，不代表整仓库已完成所有许可证审核。

## 相关文档

- 仓库根 [README](../README.md)：完整能力、后端配置、云厂商凭据与安全说明
- [CONTRIBUTING](../CONTRIBUTING.md)、[SECURITY](../SECURITY.md)、[CHANGELOG](../CHANGELOG.md)
