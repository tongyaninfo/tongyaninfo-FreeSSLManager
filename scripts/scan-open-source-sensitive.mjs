#!/usr/bin/env node
// 开源移植敏感信息扫描器：只读扫描目标目录，按"阻断/复核/豁免"分级输出打码证据。
// 独立实现、零依赖，可随规范复制到任意开源仓库的 scripts/ 目录使用。
//
// 用法：
//   node scripts/scan-open-source-sensitive.mjs [--root <目录>] [--denylist <词1,词2>] [--max-size <MB>] [--format text|json]
//
// 退出码：0 无阻断命中；1 存在阻断命中；2 参数或目录错误。
//
// 说明：
// - 只读，不写入任何文件；不访问网络。
// - 命中值只输出打码后的片段，不打印完整敏感值。
// - 组织内部名称、真实设备名等无法通用识别的项，通过 --denylist 传入（逗号分隔），仅在私有侧移植流程使用；
//   公开仓库 CI 使用默认通用规则即可，不要将内部名称写进公开的 CI 配置。

import fs from 'node:fs';
import path from 'node:path';

const EXIT_OK = 0;
const EXIT_BLOCK = 1;
const EXIT_USAGE = 2;

// 遍历时跳过的目录：依赖、构建产物、版本库对象与缓存。运行数据目录不跳过，由规则单独提示。
const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'bin',
  'obj',
  'dist',
  'dist-ssr',
  '.umi',
  '.umi-production',
  '.umi-test',
  '.next',
  '.nuxt',
  '.cache',
  '.vite',
  '.vite-temp',
  '.next',
  '.turbo',
  '.artifacts',
  'releases',
  'TestResults',
  'coverage',
  '.nyc_output',
  '.venv',
  'venv',
  '__pycache__',
  '.tools',
  '.idea',
  '.vs',
  '.vscode',
]);

// 运行数据目录：开源仓库中不应出现，命中后提示复核（不阻断，便于发现误放的示例数据）。
const RUN_DATA_DIRS = new Set([
  'App_Data',
  'backups',
  'local-run',
  '.local',
  'logs',
  'uploads',
]);

const TEXT_EXTENSIONS = new Set([
  '.cs', '.csproj', '.props', '.slnx', '.sln', '.json', '.jsonc', '.xml', '.config', '.ini', '.env', '.example',
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.vue', '.html', '.css', '.scss', '.less',
  '.md', '.markdown', '.txt', '.yml', '.yaml', '.toml', '.sql', '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
  '.conf', '.service', '.template', '.dockerignore', '.gitignore', '.gitattributes', '.editorconfig',
  '.properties', '.gradle', '.java', '.kt', '.go', '.py', '.rb', '.php', '.rs', '.swift', '.plist',
]);

// 明确允许的占位值与公开常量（按字符串包含判断）。
const ALLOW_SUBSTRINGS = [
  // 回环与通配
  '127.0.0.1', '::1', '0.0.0.0', 'localhost',
  // RFC 5737 / 3849 文档网段与约定的示例内网网段
  '192.0.2.', '198.51.100.', '203.0.113.', '2001:db8', '10.20.30.',
  // 文档占位路径
  '/Users/developer', '/home/developer', 'C:\\\\Users\\\\developer',
  '/Users/example', '/home/example', '/Users/username', '/home/username',
  '/Users/user', '/home/user', '/Users/you', '/Users/demo', '/home/demo',
  // 保留域名与邮箱
  'example.com', 'example.org', 'example.net', 'example.test',
  'dev@example.com', 'test@example.com', 'user@example.com',
  // 占位值
  'CHANGE_ME', 'CHANGE_TO', 'YOUR_ACCESS_KEY', 'YOUR_SECRET', '<', '>',
  // 测试固定值
  'FAKE_', 'fixture-', 'controlled-', 'synthetic-', 'test-', 'demo-', 'mock-',
  // 公开官方域名与依赖站点
  'github.com', 'githubusercontent.com', 'npmjs.org', 'npmjs.com', 'nuget.org',
  'microsoft.com', 'mcr.microsoft.com', 'dotnet.microsoft.com', 'learn.microsoft.com',
  'packagecloud.io', 'public.ecr.aws', 'docker.io', 'gcr.io', 'quay.io',
  'ant.design', 'alipay.com', 'opensource.org', 'apache.org', 'nodejs.org',
  'maxmind.com', 'db-ip.com', 'ip2location.com', 'ipinfo.io', 'ip2region',
  'cz88.net', 'qq.com', 'w3.org', 'schema.org', 'creativecommons.org',
];

const RULES = [
  {
    id: 'S1-private-key-header',
    level: 'review',
    description: '私钥头（占位提示或真实私钥均需人工判定）',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    id: 'S1-aliyun-ak',
    level: 'block',
    description: '疑似阿里云 AccessKey',
    pattern: /\bLTAI[A-Za-z0-9]{12,}\b/g,
  },
  {
    id: 'S1-tencent-ak',
    level: 'block',
    description: '疑似腾讯云 SecretId',
    pattern: /\bAKID[A-Za-z0-9]{13,}\b/g,
  },
  {
    id: 'S1-aws-ak',
    level: 'block',
    description: '疑似 AWS AccessKey',
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: 'S1-jwt',
    level: 'block',
    description: '疑似 JWT 令牌',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  {
    id: 'S1-password-literal',
    level: 'review',
    description: '疑似口令字面量',
    pattern: /(?:password|passwd|pwd|secret|apikey|api_key|token)["']?\s*[:=]\s*["'][^"'\s]{6,}["']/gi,
  },
  {
    id: 'S2-email',
    level: 'review',
    description: '邮箱地址',
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  },
  {
    id: 'S4-private-ipv4',
    level: 'review',
    description: '内网或可疑 IPv4',
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
  },
  {
    id: 'S4-internal-domain',
    level: 'review',
    description: '疑似内部域名',
    pattern: /\b(?:[A-Za-z0-9-]+\.)+(?:local|internal|lan|corp|intra|home)\b/gi,
  },
  {
    id: 'S4-ipv6',
    level: 'review',
    description: '非文档 IPv6',
    // 要求至少 4 组冒号分隔的十六进制段，避免误报 HH:MM:SS 时间格式。
    pattern: /\b(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{0,4}\b/gi,
  },
  {
    id: 'S5-home-path',
    level: 'review',
    description: '疑似个人家目录或用户名路径',
    pattern: /(?:\/Users\/[A-Za-z0-9._-]+|\/home\/[A-Za-z0-9._-]+|[A-Za-z]:\\\\Users\\\\[A-Za-z0-9._ -]+)/g,
  },
  {
    id: 'S3-hostname',
    level: 'review',
    description: '疑似个人设备或主机名',
    pattern: /\b(?:[A-Za-z0-9-]+-(?:MacBook|MacBOOK|ThinkPad|Surface|PC|Laptop)|[A-Za-z0-9-]+\u7684MacBook[A-Za-z0-9-]*)\b/gi,
  },
];

// 跨行规则：仅在文件全文层面匹配，用于识别"私钥头 + 多行 base64 材料"这类真实私钥特征。
const MULTILINE_RULES = [
  {
    id: 'S1-private-key-material',
    level: 'block',
    description: '疑似真实私钥材料',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\r\n]+(?:[A-Za-z0-9+/=]{60,}[\r\n]+){2,}/g,
  },
];

// 文件名规则：出现在开源仓库中即需复核。
const FILE_NAME_RULES = [
  { id: 'S6-database-file', level: 'block', pattern: /\.(?:db|db-shm|db-wal|sqlite|sqlite3|dump|bak)$/i, description: '数据库或备份文件' },
  { id: 'S1-certificate-file', level: 'block', pattern: /\.(?:pfx|p12|key|pem|jks|keystore)$/i, description: '证书或私钥文件' },
  { id: 'S6-log-file', level: 'review', pattern: /\.log$/i, description: '日志文件' },
  { id: 'S6-archive-file', level: 'review', pattern: /\.(?:zip|7z|rar|tar|gz|tgz)$/i, description: '压缩包' },
];

function parseArgs(argv) {
  const options = { root: process.cwd(), denylist: [], maxSizeMb: 2, format: 'text' };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--root') {
      options.root = argv[index + 1];
      index += 1;
    } else if (arg === '--denylist') {
      options.denylist = String(argv[index + 1] ?? '')
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
      index += 1;
    } else if (arg === '--max-size') {
      options.maxSizeMb = Number(argv[index + 1]);
      index += 1;
    } else if (arg === '--format') {
      options.format = argv[index + 1];
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else {
      throw new Error(`未知参数：${arg}`);
    }
  }
  return options;
}

function isAllowed(text) {
  return ALLOW_SUBSTRINGS.some((allowed) => text.includes(allowed));
}

// 只保留首段或首尾少量字符，避免输出完整敏感值。
function mask(value) {
  const text = String(value);
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) {
    return `${text.split('.')[0]}.***.***.***`;
  }
  if (text.length <= 6) return `${text.slice(0, 2)}***`;
  return `${text.slice(0, 4)}***${text.slice(-2)}`;
}

function isBinary(buffer) {
  const sample = buffer.subarray(0, 8192);
  return sample.includes(0);
}

function walk(root, options, state) {
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      if (RUN_DATA_DIRS.has(entry.name)) {
        state.findings.push({
          level: 'review',
          rule: 'S6-run-data-dir',
          file: path.relative(options.root, fullPath),
          line: 0,
          snippet: `${entry.name}/`,
          note: '运行数据目录不应出现在开源仓库',
        });
        // 运行数据目录只需提示存在，不递归扫描其内部，避免验证缓存等产生大量误报。
        continue;
      }
      walk(fullPath, options, state);
    } else if (entry.isFile()) {
      checkFileName(fullPath, options, state);
      checkFileContent(fullPath, options, state);
    }
  }
}

function checkFileName(fullPath, options, state) {
  const name = path.basename(fullPath);
  for (const rule of FILE_NAME_RULES) {
    if (rule.pattern.test(name)) {
      state.findings.push({
        level: rule.level,
        rule: rule.id,
        file: path.relative(options.root, fullPath),
        line: 0,
        snippet: mask(name),
        note: rule.description,
      });
    }
  }
}

function checkFileContent(fullPath, options, state) {
  const extension = path.extname(fullPath).toLowerCase();
  const baseName = path.basename(fullPath);
  const isNamedConfig = baseName.startsWith('.env') || baseName === '.gitignore' || baseName === '.gitattributes';
  if (!TEXT_EXTENSIONS.has(extension) && !isNamedConfig) return;

  let stat;
  try {
    stat = fs.statSync(fullPath);
  } catch {
    return;
  }
  if (stat.size > options.maxSizeMb * 1024 * 1024) return;

  let buffer;
  try {
    buffer = fs.readFileSync(fullPath);
  } catch {
    return;
  }
  if (isBinary(buffer)) return;

  const text = buffer.toString('utf8');
  if (!text) return;
  const lines = text.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line) continue;
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(line)) !== null) {
        const value = match[0];
        if (isAllowed(value)) continue;
        if (isAllowed(line)) continue;
        state.findings.push({
          level: rule.level,
          rule: rule.id,
          file: path.relative(options.root, fullPath),
          line: index + 1,
          snippet: mask(value),
          note: rule.description,
        });
        if (match.index + value.length >= line.length) break;
      }
    }
    for (const denied of options.denylist) {
      if (!line.includes(denied)) continue;
      state.findings.push({
        level: 'block',
        rule: 'S7-denylist',
        file: path.relative(options.root, fullPath),
        line: index + 1,
        snippet: mask(denied),
        note: '命中内部组织名/敏感词清单',
      });
    }
  }

  // 跨行规则：识别"私钥头 + 多行 base64 材料"的真实私钥特征，每个文件最多报一处。
  for (const rule of MULTILINE_RULES) {
    rule.pattern.lastIndex = 0;
    const match = rule.pattern.exec(text);
    if (!match) continue;
    state.findings.push({
      level: rule.level,
      rule: rule.id,
      file: path.relative(options.root, fullPath),
      line: text.slice(0, match.index).split(/\r?\n/).length,
      snippet: '-----BEGIN PRIVATE KEY-----***',
      note: rule.description,
    });
  }
}

function printText(findings) {
  const order = { block: 0, review: 1 };
  const levelLabel = { block: '[阻断]', review: '[复核]' };
  findings.sort((left, right) => {
    if (order[left.level] !== order[right.level]) return order[left.level] - order[right.level];
    if (left.file === right.file) return left.line - right.line;
    return left.file.localeCompare(right.file);
  });
  for (const item of findings) {
    const location = item.line > 0 ? `${item.file}:${item.line}` : item.file;
    console.log(`${levelLabel[item.level]} ${location} ${item.rule} ${item.note} ${item.snippet}`);
  }
  const blockCount = findings.filter((item) => item.level === 'block').length;
  const reviewCount = findings.filter((item) => item.level === 'review').length;
  console.log('');
  console.log(`汇总：阻断 ${blockCount} 项，复核 ${reviewCount} 项。`);
  if (blockCount > 0) {
    console.log('结论：存在阻断项，不得推送公开仓库；先按《开源移植脱敏规范》处置后重扫。');
  } else if (reviewCount > 0) {
    console.log('结论：无阻断项；复核项需逐条人工判定并写入脱敏清单。');
  } else {
    console.log('结论：未发现命中的敏感模式。');
  }
}

function run() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log('用法：node scripts/scan-open-source-sensitive.mjs [--root <目录>] [--denylist <词1,词2>] [--max-size <MB>] [--format text|json]');
    return EXIT_OK;
  }
  if (!fs.existsSync(options.root) || !fs.statSync(options.root).isDirectory()) {
    console.error(`[错误] 目录不存在：${options.root}`);
    return EXIT_USAGE;
  }
  const absoluteRoot = path.resolve(options.root);
  const state = { findings: [] };
  walk(absoluteRoot, { ...options, root: absoluteRoot }, state);

  if (options.format === 'json') {
    console.log(JSON.stringify({ root: absoluteRoot, findings: state.findings }, null, 2));
  } else {
    printText(state.findings);
  }
  return state.findings.some((item) => item.level === 'block') ? EXIT_BLOCK : EXIT_OK;
}

try {
  process.exitCode = run();
} catch (error) {
  console.error(`[错误] ${error.message}`);
  process.exitCode = EXIT_USAGE;
}
