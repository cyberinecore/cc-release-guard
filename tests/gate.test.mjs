import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = resolve(dirname(fileURLToPath(import.meta.url)), '../cli/shipsafe.mjs');
const root = mkdtempSync(join(tmpdir(), 'shipsafe-test-'));

function pack(name, files, pkgExtra = {}) {
  const dir = join(root, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0', ...pkgExtra }));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  const out = execFileSync('npm', ['pack', '--json', '--pack-destination', root], { cwd: dir, encoding: 'utf8' });
  return join(root, JSON.parse(out)[0].filename);
}

function check(tgz) {
  const r = spawnSync('node', [CLI, 'check', tgz, '--json'], { encoding: 'utf8' });
  return { code: r.status, report: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
}

function hook(command, cwd = root) {
  const r = spawnSync('node', [CLI, 'hook'], {
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command }, cwd, hook_event_name: 'PreToolUse' }),
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout ? JSON.parse(r.stdout).hookSpecificOutput : null;
}

const rules = (report) => [...new Set(report.findings.filter((f) => !f.allowed).map((f) => f.rule))].sort();

const good = pack('good', { 'dist/index.js': 'export const a=1;\n', 'dist/index.d.ts': 'export declare const a: number;\n' });
const leaky = pack('leaky', {
  'dist/index.js': 'export const a=1;\n//# sourceMappingURL=index.js.map\n',
  'dist/index.js.map': JSON.stringify({ version: 3, sources: ['../src/index.ts'], sourcesContent: ['export const a = 1'], mappings: '' }),
  'src/index.ts': 'export const a = 1\n',
  'test/a.test.js': 'x\n',
  'dist/b.spec.js': 'x\n',
  '.env.production': 'X=1\n',
});

test('a clean build passes and reports its sha256', () => {
  const { code, report } = check(good);
  assert.equal(code, 0);
  assert.equal(report.pass, true);
  assert.match(report.sha256, /^[0-9a-f]{64}$/);
});

test('maps, sourcesContent, TypeScript, src, tests and env files all fail', () => {
  const { code, report } = check(leaky);
  assert.equal(code, 1);
  assert.deepEqual(rules(report), ['sensitive-file', 'source-dir', 'source-map', 'sources-content', 'test-path', 'typescript-source']);
});

test('inline and remote source maps fail', () => {
  const inline = pack('inline', { 'index.js': 'a();\n//# sourceMappingURL=data:application/json;base64,eyJ2IjozfQ==\n' });
  const remote = pack('remote', { 'index.js': 'a();\n//# sourceMappingURL=https://cdn.example.com/index.js.map\n' });
  assert.deepEqual(rules(check(inline).report), ['inline-source-map']);
  assert.deepEqual(rules(check(remote).report), ['remote-source-map']);
});

test('storage bucket URLs fail unless allowed with a reason', () => {
  const files = { 'index.js': 'fetch("https://pub-0a1b2c.r2.dev/src.zip");fetch("https://my-bucket.s3.us-east-1.amazonaws.com/x")\n' };
  const blocked = check(pack('bucket', files));
  assert.deepEqual(rules(blocked.report), ['bucket-url']);
  assert.match(blocked.report.findings[0].detail, /r2\.dev/);
  const allowed = check(pack('bucket-allowed', files, {
    shipsafe: { allow: [{ rule: 'bucket-url', path: '*.js', reason: 'public asset bucket, documented download' }, { rule: 'file-size', path: 'x', reason: 'stale entry kept on purpose' }] },
  }));
  assert.equal(allowed.code, 0);
  assert.equal(allowed.report.findings[0].allowed, true);
  assert.deepEqual(allowed.report.warnings, ['unused allow entry: file-size x']);
});

test('an allow entry without a reason is a config error', () => {
  const r = check(pack('noreason', { 'index.js': 'x\n' }, { shipsafe: { allow: [{ rule: 'bucket-url', path: '*' }] } }));
  assert.equal(r.code, 2);
  assert.match(r.stderr, /reason/);
});

test('files over the size threshold fail', () => {
  const r = check(pack('big', { 'index.js': 'x'.repeat(2048) }, { shipsafe: { maxFileBytes: 1024 } }));
  assert.deepEqual(rules(r.report), ['file-size']);
});

test('the hook ignores commands that do not publish', () => {
  for (const c of ['npm install', 'npm run publish', 'git commit -m "npm publish later"', 'npm view publish', 'npm pack', 'npx publish-please']) {
    assert.equal(hook(c), null, c);
  }
});

test('the hook denies publishing an unchecked working tree', () => {
  for (const c of ['npm publish', 'npm publish --access public --otp 123456', 'pnpm --filter x publish', 'npm --loglevel warn publish', 'bun publish', 'yarn npm publish', 'FOO=1 timeout 60 npm publish', 'npm publish ./pkgdir']) {
    assert.equal(hook(c)?.permissionDecision, 'deny', c);
  }
});

test('the hook lets a dry run through', () => {
  assert.equal(hook('npm publish --dry-run'), null);
});

test('the hook allows only a tarball that passes the gate', () => {
  assert.equal(hook(`npm publish ${good} --otp 123456`), null);
  assert.equal(hook(`cd ${root} && npm publish ./good-1.0.0.tgz --access public`), null);
  assert.equal(hook(`cd ${root} && pnpm publish good-*.tgz`), null);
  const denied = hook(`npm publish ${leaky}`);
  assert.equal(denied.permissionDecision, 'deny');
  assert.match(denied.permissionDecisionReason, /source-map/);
  assert.equal(hook('npm publish missing-9.9.9.tgz')?.permissionDecision, 'deny');
  assert.equal(hook('npm publish $TGZ')?.permissionDecision, 'deny');
});

test('check accepts several tarballs and exits with the worst result', () => {
  const both = spawnSync('node', [CLI, 'check', good, leaky], { encoding: 'utf8' });
  assert.equal(both.status, 1);
  assert.equal(both.stdout.match(/^shipsafe \d/gm).length, 2);
  assert.match(both.stdout, /1\/2 tarball\(s\) passed/);
  const json = spawnSync('node', [CLI, 'check', good, good, '--json'], { encoding: 'utf8' });
  assert.equal(json.status, 0);
  const reports = JSON.parse(json.stdout);
  assert.ok(Array.isArray(reports));
  assert.equal(reports.length, 2);
  assert.ok(reports.every((r) => r.pass));
  const missing = spawnSync('node', [CLI, 'check', leaky, join(root, 'missing.tgz'), '--json'], { encoding: 'utf8' });
  assert.equal(missing.status, 2);
  assert.equal(JSON.parse(missing.stdout)[1].error.length > 0, true);
  assert.equal(check(good).report.pass, true);
});

test('the hook sees publishes behind runners, shells, eval, xargs and find', () => {
  for (const c of ['npx npm publish', 'npx --yes npm@10 publish', 'bunx npm publish', 'corepack pnpm publish', 'pnpm dlx npm publish', 'pnpm exec npm publish', 'npm exec -- npm publish', 'npm exec -c "npm publish"', 'bash -c "npm publish"', "sh -c 'cd x && npm publish'", 'zsh -lc "npx npm publish"', 'eval npm publish', `ls ${root}/*.tgz | xargs npm publish`, `find ${root} -name 'good-*.tgz' -exec npm publish {} \;`]) {
    assert.equal(hook(c)?.permissionDecision, 'deny', c);
  }
  assert.match(hook(`ls ${good} | xargs -n1 npm publish`).permissionDecisionReason, /xargs or find/);
  assert.equal(hook(`bash -c "npm publish ${good}"`), null);
  assert.equal(hook(`npx npm@10 publish ${good}`), null);
  assert.equal(hook(`sh -c 'npm publish ${leaky}'`)?.permissionDecision, 'deny');
  for (const c of ['npm exec foo', 'npx eslint .', 'bash -c "npm test"', 'ls | xargs rm', 'find . -exec cat {} +']) {
    assert.equal(hook(c), null, c);
  }
});
