import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { brotliDecompressSync, gunzipSync } from 'node:zlib';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const policies = [
  { original: '@stagewise/toolbar', parent: '@umijs/preset-umi', directory: 'tools/toolbar-disabled', name: '@tongyan/build-toolbar-disabled' },
  { original: 'cfonts', parent: '@ant-design/cli', directory: 'tools/cli-banner', name: '@tongyan/build-cli-banner' },
];
const fail = (message) => { throw new Error(`构建依赖检查失败：${message}`); };
const packageName = (location) => location.split('node_modules/').at(-1);
const groups = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

// 仅允许已审查的原创本地替代；原包路径名保留是 npm 覆盖的解析键，不是许可依据。
function checkLocalPackage(policy) {
  const directory = path.join(root, policy.directory);
  const metadata = readJson(path.join(directory, 'package.json'));
  assert.equal(metadata.name, policy.name, `${policy.directory}：替代包身份漂移`);
  assert.equal(metadata.version, '1.0.0', `${policy.directory}：替代包版本需重新审查`);
  assert.equal(metadata.license, 'MIT', `${policy.directory}：替代包许可漂移`);
  for (const group of groups) assert.equal(Object.keys(metadata[group] ?? {}).length, 0, `${policy.directory}：替代包不能新增依赖`);
  assert.ok(fs.readFileSync(path.join(directory, 'LICENSE'), 'utf8').startsWith('MIT License\n'), `${policy.directory}：缺少 MIT 许可正文`);
  return fs.realpathSync(directory);
}

function checkLock() {
  const manifest = readJson(path.join(root, 'package.json'));
  const lock = readJson(path.join(root, 'package-lock.json'));
  const entries = lock.packages ?? fail('锁文件缺少 packages');
  for (const group of groups) assert.deepEqual(entries['']?.[group] ?? {}, manifest[group] ?? {}, `清单与锁文件 ${group} 不一致`);
  for (const policy of policies) {
    checkLocalPackage(policy);
    assert.equal(manifest.devDependencies?.[policy.original], `file:${policy.directory}`, `${policy.original}：必须直接登记本地替代包`);
    assert.equal(manifest.overrides?.[policy.original], `$${policy.original}`, `${policy.original}：本地覆盖配置漂移`);
    const target = entries[`node_modules/${policy.original}`];
    assert.ok(target?.link, `${policy.original}：锁文件必须指向本地替代链接`);
    assert.equal(target.resolved, policy.directory, `${policy.original}：锁文件不能恢复远程原包`);
    const metadata = entries[policy.directory];
    assert.equal(metadata?.name, policy.name, `${policy.original}：锁文件替代身份漂移`);
    assert.equal(metadata?.license, 'MIT', `${policy.original}：锁文件替代许可漂移`);
  }
  for (const [location, metadata] of Object.entries(entries)) {
    for (const policy of policies) {
      if (metadata.name === policy.original) fail(`${location} 保留了原包身份 ${policy.original}`);
      if (packageName(location) === policy.original && location !== `node_modules/${policy.original}`) fail(`${location} 出现未审查的嵌套依赖`);
      for (const group of groups) {
        for (const [name, spec] of Object.entries(metadata[group] ?? {})) {
          const aliasName = /^npm:((?:@[^/]+\/)?[^@]+)(?:@.*)?$/.exec(String(spec))?.[1];
          if (aliasName === policy.original) fail(`${location} 通过别名恢复了 ${policy.original}`);
          if (name === policy.original && location !== '' && location !== `node_modules/${policy.parent}`) fail(`${location} 新增了未审查的 ${policy.original} 依赖边`);
        }
      }
    }
  }
}

function checkInstalled() {
  for (const policy of policies) {
    const localRoot = checkLocalPackage(policy);
    const requireFromParent = createRequire(path.join(root, 'node_modules', policy.parent, 'package.json'));
    const resolved = fs.realpathSync(requireFromParent.resolve(`${policy.original}/package.json`));
    assert.equal(path.dirname(resolved), localRoot, `${policy.original}：当前 node_modules 仍有旧包或未知替代，请按锁文件在干净目录恢复依赖`);
    const metadata = readJson(resolved);
    assert.equal(metadata.name, policy.name);
    assert.equal(metadata.license, 'MIT');
  }
  // 同时拒绝嵌套、别名安装的原包；不只检查顶层文件名。
  const seen = new Set();
  function visitModules(directory) {
    if (!fs.existsSync(directory)) return;
    const realDirectory = fs.realpathSync(directory);
    if (seen.has(realDirectory)) return;
    seen.add(realDirectory);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name.startsWith('.') || !(entry.isDirectory() || entry.isSymbolicLink())) continue;
      const target = path.join(directory, entry.name);
      if (entry.name.startsWith('@')) { visitModules(target); continue; }
      const manifestPath = path.join(target, 'package.json');
      if (fs.existsSync(manifestPath)) {
        const metadata = readJson(manifestPath);
        if (policies.some((policy) => policy.original === metadata.name)) fail(`${path.relative(root, target)} 安装了原始 ${metadata.name} (${metadata.license ?? '许可未知'})`);
      }
      visitModules(path.join(target, 'node_modules'));
    }
  }
  visitModules(path.join(root, 'node_modules'));
}

function checkArtifact(directory) {
  if (!fs.statSync(directory).isDirectory()) fail('产物路径不是目录');
  const rejected = /@stagewise\/toolbar|stagewise-toolbar|TY_BUILD_TOOLBAR_DISABLED|\bcfonts\b/i;
  let count = 0;
  function visit(current) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const target = path.join(current, entry.name);
      if (entry.isDirectory()) visit(target);
      else if (entry.isFile() && /\.(?:js|mjs|cjs|json|map|html|css|txt|gz|br)$/i.test(entry.name)) {
        count++;
        let content = fs.readFileSync(target);
        if (/\.gz$/i.test(entry.name)) content = gunzipSync(content);
        if (/\.br$/i.test(entry.name)) content = brotliDecompressSync(content);
        if (rejected.test(content.toString('utf8'))) fail(`${target} 含被禁用构建工具标记`);
      }
    }
  }
  visit(directory);
  if (count === 0) fail('产物目录没有可检查的文本资源');
  console.log(`产物工具标记检查通过：${count} 个文本资源。`);
}

try {
  const args = process.argv.slice(2);
  if (args.length && !(args.length === 1 && args[0] === '--lock-only') && !(args.length === 2 && args[0] === '--artifact')) fail('用法：check-build-dependencies.mjs [--lock-only | --artifact <目录>]');
  checkLock();
  if (args[0] !== '--lock-only') checkInstalled();
  if (args[0] === '--artifact') checkArtifact(path.resolve(root, args[1]));
  console.log(`构建依赖检查通过：两项开发工具均为已审查的原创本地 MIT 替代${args[0] === '--lock-only' ? '（尚未检查安装树）' : ''}。`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
