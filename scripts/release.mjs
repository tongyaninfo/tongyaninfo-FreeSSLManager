import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// 构建标识单独记录；产品版本支持稳定版和 SemVer 预发布版，不混入 Docker 标签不支持的 + 元数据。
const number = '(?:0|[1-9]\\d*)';
const identifier = '(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)';
const semver = new RegExp(`^${number}\\.${number}\\.${number}(?:-${identifier}(?:\\.${identifier})*)?$`);
const migrationId = /^\d{14}_[A-Za-z][A-Za-z0-9_]*$/;
const sha256 = /^[a-f0-9]{64}$/;

function requireCondition(condition, message) {
  if (!condition) throw new Error(`版本校验失败：${message}`);
}

async function jsonFile(root, relative) {
  return JSON.parse(await readFile(path.join(root, relative), 'utf8'));
}

function requireText(value, field) {
  requireCondition(typeof value === 'string' && value.trim().length > 0, `${field} 必须填写。`);
}

/** 校验值统一使用 LF，使 Windows 检出换行转换不会被误判为历史迁移改写。 */
export function sourceHash(content) {
  return createHash('sha256').update(content.replace(/\r\n/g, '\n')).digest('hex');
}

async function hashFile(root, relative) {
  return sourceHash(await readFile(path.join(root, relative), 'utf8'));
}

async function currentVersion(root) {
  const version = (await readFile(path.join(root, 'VERSION'), 'utf8')).trim();
  requireCondition(semver.test(version), 'VERSION 必须是完整语义版本，例如 1.0.0 或 1.1.0-rc.1。');
  return version;
}

/** 按 SemVer 比较版本，避免 1.10.0 被字符串排序放到 1.2.0 前。 */
function compareVersions(left, right) {
  const [leftCore, ...leftSuffix] = left.split('-');
  const [rightCore, ...rightSuffix] = right.split('-');
  const a = leftCore.split('.').map(BigInt), b = rightCore.split('.').map(BigInt);
  for (let index = 0; index < 3; index++) {
    if (a[index] !== b[index]) return a[index] > b[index] ? 1 : -1;
  }
  const preA = leftSuffix.join('-'), preB = rightSuffix.join('-');
  if (!preA || !preB) return preA === preB ? 0 : preA ? -1 : 1;
  const partsA = preA.split('.'), partsB = preB.split('.');
  for (let index = 0; index < Math.max(partsA.length, partsB.length); index++) {
    if (partsA[index] === undefined) return -1;
    if (partsB[index] === undefined) return 1;
    if (partsA[index] === partsB[index]) continue;
    const numericA = /^\d+$/.test(partsA[index]), numericB = /^\d+$/.test(partsB[index]);
    if (numericA && numericB) return BigInt(partsA[index]) > BigInt(partsB[index]) ? 1 : -1;
    if (numericA !== numericB) return numericA ? -1 : 1;
    return partsA[index] > partsB[index] ? 1 : -1;
  }
  return 0;
}

/** 镜像字段便于 npm/.NET 及隔离构建使用；VERSION 是唯一修改起点。 */
async function versionMirrors(root, version, synchronize) {
  const writes = [];
  for (const component of ['frontend', 'desktop']) {
    for (const file of ['package.json', 'package-lock.json']) {
      const relative = `${component}/${file}`;
      const original = await readFile(path.join(root, relative), 'utf8');
      const metadata = JSON.parse(original);
      if (file === 'package-lock.json') {
        requireCondition(metadata.packages?.[''], `${relative} 缺少 npm 锁文件根包信息。`);
        if (synchronize) metadata.packages[''].version = version;
        else requireCondition(metadata.packages[''].version === version, `${relative} 根包版本与 VERSION 不一致，请执行 sync。`);
      }
      if (synchronize) {
        metadata.version = version;
        // 只更新版本语义，保留锁文件的全部依赖值和完整性；输出统一为两空格与 LF。
        const formatted = JSON.stringify(metadata, null, 2) + '\n';
        if (formatted !== original) writes.push([relative, formatted]);
      } else requireCondition(metadata.version === version, `${relative} 版本与 VERSION 不一致，请执行 sync。`);
    }
  }
  const projectPath = 'backend/SslManager.Api/SslManager.Api.csproj';
  const project = await readFile(path.join(root, projectPath), 'utf8');
  const versions = [...project.matchAll(/<Version>\s*([^<]*?)\s*<\/Version>/g)];
  requireCondition(versions.length === 1, `${projectPath} 必须有且只有一个显式 Version。`);
  if (synchronize) {
    const updated = project.replace(/<Version>\s*[^<]*?\s*<\/Version>/, `<Version>${version}</Version>`);
    if (updated !== project) writes.push([projectPath, updated]);
  } else requireCondition(versions[0][1] === version, '后端编译版本与 VERSION 不一致，请执行 sync。');
  // 所有输入通过校验后再顺序保存；不接触数据库、配置秘密或 Git。
  for (const [relative, content] of writes) await writeFile(path.join(root, relative), content);
}

/** 仅同步应用版本镜像，不创建迁移、不生成或改写任何历史版本记录。 */
export async function syncVersions(root = repositoryRoot) {
  const version = await currentVersion(root);
  await versionMirrors(root, version, true);
  return { version };
}

/** 构建前只读检查：版本一致、累计迁移有登记、历史文件未改写、当前模型快照已归档。 */
export async function checkRelease(root = repositoryRoot) {
  const version = await currentVersion(root);
  await versionMirrors(root, version, false);
  const directory = 'backend/SslManager.Api/Data/Migrations';
  const migrationFiles = await readdir(path.join(root, directory));
  const actualIds = migrationFiles.filter(name => /^\d.*\.cs$/.test(name) && !name.endsWith('.Designer.cs'))
    .map(name => name.slice(0, -3)).sort();
  requireCondition(actualIds.length > 0 && actualIds.every(id => migrationId.test(id)), '迁移目录缺少有效迁移或存在无效迁移名称。');
  const designers = migrationFiles.filter(name => /^\d.*\.Designer\.cs$/.test(name)).map(name => name.replace(/\.Designer\.cs$/, '')).sort();
  requireCondition(JSON.stringify(actualIds) === JSON.stringify(designers), '迁移与 Designer 文件必须一一对应。');

  const files = (await readdir(path.join(root, 'docs/releases'))).filter(name => name.endsWith('.json'));
  const records = new Map();
  for (const file of files) {
    const recordVersion = file.slice(0, -5);
    requireCondition(semver.test(recordVersion), `版本清单文件名无效：${file}。`);
    const record = await jsonFile(root, `docs/releases/${file}`);
    requireCondition(record.schemaVersion === 1 && record.version === recordVersion, `${file} 的格式版本或应用版本不一致。`);
    requireCondition(typeof record.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(record.date), `${file} 缺少封版日期。`);
    requireCondition(record.previousVersion === null || (typeof record.previousVersion === 'string' && semver.test(record.previousVersion)), `${file} 的 previousVersion 无效。`);
    requireCondition(record.database?.provider === 'Microsoft.EntityFrameworkCore.Sqlite', `${file} 必须明确 SQLite 提供程序。`);
    requireCondition(Array.isArray(record.database.migrations) && record.database.migrations.length > 0, `${file} 缺少完整累计迁移清单。`);
    const ids = record.database.migrations.map(item => item.id);
    requireCondition(ids.every(id => typeof id === 'string' && migrationId.test(id)) && new Set(ids).size === ids.length &&
      JSON.stringify(ids) === JSON.stringify([...ids].sort()), `${file} 的迁移 ID 必须唯一并按执行顺序排列。`);
    requireCondition(JSON.stringify(ids) === JSON.stringify(actualIds.slice(0, ids.length)), `${file} 的历史迁移链与源码不一致，历史迁移不能删除、改名或插队。`);
    requireCondition(record.database.targetMigration === ids.at(-1), `${file} 的目标迁移必须是累计迁移末端。`);
    requireCondition(sha256.test(record.database.snapshotSha256 ?? ''), `${file} 缺少模型快照 SHA256。`);
    requireCondition(Array.isArray(record.database.newMigrations), `${file} 必须明确 newMigrations（无新增则为空）。`);
    requireText(record.database.changes, `${file} database.changes`);
    requireCondition(record.upgrade?.requiresExplicitApproval === true && Array.isArray(record.upgrade.supportedFromVersions), `${file} 必须声明升级审批及支持来源版本。`);
    requireText(record.upgrade.strategy, `${file} upgrade.strategy`);
    requireText(record.upgrade.rollback, `${file} upgrade.rollback`);
    requireText(await readFile(path.join(root, `docs/releases/${recordVersion}.md`), 'utf8'), `${recordVersion} 版本说明`);
    for (const item of record.database.migrations) {
      requireText(item.summary, `${file} ${item.id} 变更说明`);
      requireCondition(sha256.test(item.sha256 ?? '') && sha256.test(item.designerSha256 ?? ''), `${file} ${item.id} 缺少源文件校验值。`);
      requireCondition(await hashFile(root, `${directory}/${item.id}.cs`) === item.sha256, `历史迁移 ${item.id}.cs 已改变，必须追加修复迁移。`);
      requireCondition(await hashFile(root, `${directory}/${item.id}.Designer.cs`) === item.designerSha256, `历史迁移 ${item.id}.Designer.cs 已改变。`);
    }
    records.set(recordVersion, record);
  }
  const ordered = [...records.keys()].sort(compareVersions);
  requireCondition(ordered.length > 0 && ordered.at(-1) === version, 'VERSION 必须对应最新的版本清单；不能缺失记录或退回旧版。');
  for (let index = 0; index < ordered.length; index++) {
    const record = records.get(ordered[index]);
    const previous = index === 0 ? null : records.get(ordered[index - 1]);
    requireCondition(record.previousVersion === (previous?.version ?? null), `${record.version} 的 previousVersion 必须连接上一已登记版本。`);
    const previousIds = previous?.database.migrations.map(item => item.id) ?? [];
    const newIds = previous ? record.database.migrations.map(item => item.id).slice(previousIds.length) : [];
    requireCondition(!previous || record.database.migrations.length >= previousIds.length, `${record.version} 不允许回退数据库迁移。`);
    requireCondition(JSON.stringify(record.database.newMigrations) === JSON.stringify(newIds), `${record.version} 的 newMigrations 必须等于相对上一版的新增迁移；首次基线归档为空。`);
    requireCondition(!previous || newIds.length > 0 || record.database.snapshotSha256 === previous.database.snapshotSha256,
      `${record.version} 没有新增迁移时不能改变模型快照，请补充模型变化对应的迁移。`);
    requireCondition(record.upgrade.supportedFromVersions.every(from => records.has(from) && compareVersions(from, record.version) < 0), `${record.version} 的支持升级来源必须是已登记的旧版本。`);
  }
  const release = records.get(version);
  requireCondition(release.database.migrations.length === actualIds.length, '存在尚未登记到当前版本的新迁移，请新增版本及升级记录。');
  requireCondition(await hashFile(root, `${directory}/AppDbContextModelSnapshot.cs`) === release.database.snapshotSha256, '当前模型快照与版本归档不一致，请检查迁移和版本记录。');
  const changelog = await readFile(path.join(root, 'CHANGELOG.md'), 'utf8');
  for (const recordedVersion of ordered) requireCondition(changelog.includes(`[${recordedVersion}]`), `CHANGELOG.md 缺少 [${recordedVersion}]。`);
  // 构建物同时绑定清单摘要，避免历史同名安装包或后端暂存被误当作当前源码基线。
  const binding = { version, targetMigration: release.database.targetMigration,
    manifestSha256: await hashFile(root, `docs/releases/${version}.json`) };
  return { version, release, binding };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const command = process.argv[2] ?? 'check';
    requireCondition(process.argv.length <= 3 && ['check', 'sync'].includes(command), '用法：node scripts/release.mjs [check|sync]。');
    const result = command === 'sync' ? await syncVersions() : await checkRelease();
    console.log(command === 'sync' ? `已同步应用版本 ${result.version}；请补齐版本记录并执行 check。`
      : `版本 ${result.version} 校验通过，数据库目标 ${result.release.database.targetMigration}，累计 ${result.release.database.migrations.length} 个迁移。`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
