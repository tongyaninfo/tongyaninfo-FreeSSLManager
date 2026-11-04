# SSL 证书管理桌面客户端

Electron 外壳直接启动安装包中的 .NET 10 自包含后端，后端托管前端静态文件并使用 SQLite。
终端用户不需要安装 Node.js、.NET、数据库或部署服务器；业务代码与 Web / 容器部署共用仓库中的
`frontend` 与 `backend/SslManager.Api`。

## 使用与后台任务

- 首次打开创建管理员，随后使用证书、DNS、部署和计划任务页面。
- 关闭主窗口默认隐藏托盘并保留本地服务；没有可见托盘的 Linux 桌面保留最小化入口。
- “完全退出”先停止后端、保存已提交状态。后端崩溃会退避重启，复用原轮次及证书恢复机制。
- 关机、注销、睡眠和完全退出期间不会执行计划；重新启动或唤醒后继续未完成阶段，并按原周期规则补跑一轮。
- “桌面设置与备份”提供关闭行为、用户级登录自启、日志位置及加密备份恢复。默认不写系统登录启动项。

## 程序和数据分离

稳定数据根为系统应用数据目录下的 `tongyaninfo/FreeSslManager`：

| 系统 | 默认数据根 |
| --- | --- |
| Windows | `%APPDATA%\tongyaninfo\FreeSslManager` |
| macOS | `~/Library/Application Support/tongyaninfo/FreeSslManager` |
| Linux | `$XDG_CONFIG_HOME/tongyaninfo/FreeSslManager`，默认 `~/.config/tongyaninfo/FreeSslManager` |

`business/data/ssl-manager.db` 保存业务数据，`business/keys` 保存 DataProtection 密钥；
`logs`、`backups` 和 `settings.json` 位于数据根。安装包升级只替换程序资源，不覆盖用户数据。

桌面首次安装仅在独立新目录使用既有 EF 迁移初始化数据库。存量业务库缺少待应用迁移时，
新后端明确停止启动，不会把结构升级夹带在启动流程中。缺失原数据库、原密钥或目录被其他实例
占用时明确拒绝不安全启动。

## 备份与恢复

导出的 `.sslbak` 文件使用 scrypt 派生密钥和 AES-256-GCM 加密，包含 SQLite 在线一致快照、
完整密钥、归属标记和逐文件 SHA256。恢复先验证密码、完整性与固定路径白名单，再经原生确认
停止后端并切换业务目录；原目录以 `business-before-restore-*` 保留。备份是历史快照，
恢复前应确保客户端已退出并核对备份生成后的云端变更。

## 开发与测试

开发机需要 Node.js 22.12+、.NET 10 SDK；这些仅用于构建，终端用户无需安装。

```bash
cd desktop
npm ci
npm run install:electron
npm run build:backend
npm run dev
```

Electron 的 npm 包使用显式二进制安装命令。官方源下载较慢时可临时指定公共镜像，安装仍使用
npm 包内的官方 SHA256 清单验证：

```bash
ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/ npm run install:electron
```

```bash
npm test
npm run typecheck
```

## 三平台打包

以下命令在相应系统的构建环境运行，按目标携带匹配架构的 .NET、ASP.NET Core 和 SQLite 原生文件：

```bash
npm run package -- --target win-x64
npm run package -- --target win-arm64
npm run package -- --target linux-x64
npm run package -- --target linux-arm64
npm run package -- --target osx-x64
npm run package -- --target osx-arm64
```

Windows 生成 NSIS EXE，macOS 生成 DMG 和 ZIP，Linux 生成 DEB 和 AppImage。单纯准备全部运行
资源可用 `npm run build:backend -- --all`；`--skip-frontend` 复用已经构建的前端。每次构建产生
独立 `.artifacts/<version>/<RID>/<build-id>` 目录，`current-<RID>.json` 指向当前资源。

安装包必须通过架构、文件摘要、内置 .NET/SQLite、前端资源与无运行数据/秘密配置校验。
自包含不等于无操作系统基础库要求：Linux 以 Ubuntu/Debian 桌面环境为基线，DEB 声明 Electron
与 .NET 的系统库依赖，不安装 .NET 或数据库服务。

当前开源构建禁用签名身份自动发现：macOS 使用无私钥 ad-hoc 签名，Windows 未签名。正式公开
分发的 Windows 签名及 macOS Developer ID/公证需单独配置；未公证测试包不代表已完成
Gatekeeper 分发验收。

## 版本与升级

版本以仓库根目录 [`VERSION`](../VERSION) 为准。打包前运行 `node scripts/release.mjs check`
（在仓库根执行）校验版本镜像、迁移链与版本台账。升级前应停止写入、成套备份 SQLite 数据库与
`keys` 目录，并按 `docs/releases/` 中的版本说明显式升级；普通启动不会自动建库或迁库。
