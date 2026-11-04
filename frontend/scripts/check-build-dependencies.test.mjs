import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { brotliCompressSync, gzipSync } from 'node:zlib';

const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = fs.readFileSync(path.join(project, 'scripts/check-build-dependencies.mjs'), 'utf8');
const writeJson = (file, data) => fs.writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);

function fixture() {
  // 删除操作须另行授权；测试只创建唯一隔离目录，不清理用户文件或旧产物。
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ssl-build-deps-test-'));
  fs.mkdirSync(path.join(root, 'scripts'));
  fs.writeFileSync(path.join(root, 'scripts/check-build-dependencies.mjs'), source);
  for (const name of ['toolbar-disabled', 'cli-banner']) {
    fs.cpSync(path.join(project, 'tools', name), path.join(root, 'tools', name), { recursive: true });
  }
  const manifest = JSON.parse(JSON.stringify(JSON.parse(fs.readFileSync(path.join(project, 'package.json'), 'utf8'))));
  const lock = JSON.parse(fs.readFileSync(path.join(project, 'package-lock.json'), 'utf8'));
  function save() {
    writeJson(path.join(root, 'package.json'), manifest);
    writeJson(path.join(root, 'package-lock.json'), lock);
  }
  function run(args = ['--lock-only']) {
    save();
    return spawnSync(process.execPath, [path.join(root, 'scripts/check-build-dependencies.mjs'), ...args], { encoding: 'utf8' });
  }
  function installLocal() {
    for (const [parent, original, directory] of [
      ['@umijs/preset-umi', '@stagewise/toolbar', 'toolbar-disabled'],
      ['@ant-design/cli', 'cfonts', 'cli-banner'],
    ]) {
      const parentDirectory = path.join(root, 'node_modules', parent);
      fs.mkdirSync(parentDirectory, { recursive: true });
      writeJson(path.join(parentDirectory, 'package.json'), { name: parent, version: '1.0.0' });
      const link = path.join(root, 'node_modules', original);
      fs.mkdirSync(path.dirname(link), { recursive: true });
      fs.symlinkSync(path.join(root, 'tools', directory), link, 'junction');
    }
  }
  return { root, manifest, lock, run, installLocal };
}

test('本地原创替代与实际解析均接受', () => {
  const state = fixture();
  state.installLocal();
  const result = state.run([]);
  assert.equal(result.status, 0, result.stderr);
});

test('远程原包不能借 MIT 元信息或相同安装路径通过', () => {
  const state = fixture();
  state.lock.packages['node_modules/@stagewise/toolbar'] = {
    version: '0.6.2', resolved: 'https://registry.npmjs.org/@stagewise/toolbar/-/toolbar-0.6.2.tgz', license: 'MIT',
  };
  assert.notEqual(state.run().status, 0);
});

test('移除覆盖配置会阻止构建', () => {
  const state = fixture();
  state.manifest.overrides.cfonts = '3.3.1';
  assert.notEqual(state.run().status, 0);
});

test('通过新别名恢复原包会阻止构建', () => {
  const state = fixture();
  state.lock.packages['node_modules/example'] = { dependencies: { 'hidden-banner': 'npm:cfonts@3.3.1' } };
  assert.notEqual(state.run().status, 0);
});

test('无版本 npm 别名也不能恢复原包', () => {
  const state = fixture();
  state.lock.packages['node_modules/example'] = { dependencies: { 'hidden-toolbar': 'npm:@stagewise/toolbar' } };
  assert.notEqual(state.run().status, 0);
});

test('嵌套原包不能绕过顶层替代', () => {
  const state = fixture();
  state.lock.packages['node_modules/example/node_modules/cfonts'] = { version: '3.3.1', license: 'GPL-3.0-or-later' };
  assert.notEqual(state.run().status, 0);
});

test('旧 node_modules 中的原包会阻止构建', () => {
  const state = fixture();
  state.installLocal();
  const oldPackage = path.join(state.root, 'node_modules/example/node_modules/old-banner');
  fs.mkdirSync(oldPackage, { recursive: true });
  writeJson(path.join(oldPackage, 'package.json'), { name: 'cfonts', license: 'GPL-3.0-or-later' });
  assert.notEqual(state.run([]).status, 0);
});

test('构建产物含工具标记会阻止分发', () => {
  const state = fixture();
  state.installLocal();
  fs.mkdirSync(path.join(state.root, 'dist'));
  fs.writeFileSync(path.join(state.root, 'dist/app.js'), 'window.example = "TY_BUILD_TOOLBAR_DISABLED";');
  assert.notEqual(state.run(['--artifact', 'dist']).status, 0);
});

test('压缩产物中的工具标记同样阻止分发', () => {
  for (const [extension, compress] of [['gz', gzipSync], ['br', brotliCompressSync]]) {
    const state = fixture();
    state.installLocal();
    fs.mkdirSync(path.join(state.root, 'dist'));
    fs.writeFileSync(path.join(state.root, `dist/app.js.${extension}`), compress('window.example = "TY_BUILD_TOOLBAR_DISABLED";'));
    assert.notEqual(state.run(['--artifact', 'dist']).status, 0);
  }
});

test('安装目录存在循环链接时检查可终止', () => {
  const state = fixture();
  state.installLocal();
  fs.mkdirSync(path.join(state.root, 'node_modules/example/node_modules'), { recursive: true });
  writeJson(path.join(state.root, 'node_modules/example/package.json'), { name: 'example' });
  fs.symlinkSync(path.join(state.root, 'node_modules/example'), path.join(state.root, 'node_modules/example/node_modules/example'), 'junction');
  const result = state.run([]);
  assert.equal(result.status, 0, result.stderr);
});

test('原创兼容入口保留横幅文本且拒绝误启用工具栏', async () => {
  const banner = await import(path.join(project, 'tools/cli-banner/index.cjs'));
  const toolbar = await import(path.join(project, 'tools/toolbar-disabled/lib/index.cjs'));
  assert.equal(banner.default.render('ANT DESIGN CLI').string, 'ANT DESIGN CLI');
  assert.throws(() => toolbar.default.initToolbar(), /TY_BUILD_TOOLBAR_DISABLED/);
});
