import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
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

function tarEntry(name, body = '', type = '0', linkname = '') {
  const data = Buffer.from(body);
  const h = Buffer.alloc(512);
  h.write(name, 0, 100);
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write(type, 156);
  h.write(linkname, 157, 100);
  h.write('ustar\0' + '00', 257);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return Buffer.concat([h, data, Buffer.alloc((512 - (data.length % 512)) % 512)]);
}

function handBuilt(name, entries, { truncate = 0 } = {}) {
  const pkg = tarEntry('package/package.json', JSON.stringify({ name, version: '1.0.0' }));
  let tar = Buffer.concat([pkg, ...entries, Buffer.alloc(1024)]);
  if (truncate) tar = tar.subarray(0, tar.length - truncate);
  const file = join(root, `${name}.tgz`);
  writeFileSync(file, gzipSync(tar));
  return file;
}

test('hand-built hostile tarballs: links and duplicate paths are archive-integrity findings', () => {
  const link = check(handBuilt('hostile-link', [tarEntry('package/index.js', '', '2', '../../../etc/passwd')]));
  assert.equal(link.code, 1);
  assert.deepEqual(rules(link.report), ['archive-integrity']);
  assert.match(link.report.findings[0].detail, /symlink to/);
  const dup = check(handBuilt('hostile-dup', [tarEntry('package/index.js', 'a'), tarEntry('package/index.js', 'b')]));
  assert.equal(dup.code, 1);
  assert.deepEqual(rules(dup.report), ['archive-integrity']);
  assert.match(dup.report.findings[0].detail, /duplicate path/);
});

test('hand-built hostile tarballs: traversal, absolute paths, truncation and oversized gzip exit 2', () => {
  const cases = [
    [handBuilt('hostile-dotdot', [tarEntry('package/../x.js', 'x')]), /escapes the package root/],
    [handBuilt('hostile-abs', [tarEntry('/etc/x.js', 'x')]), /escapes the package root/],
    [handBuilt('hostile-truncated-tar', [tarEntry('package/index.js', 'x'.repeat(2000))], { truncate: 2048 }), /truncated/],
  ];
  const gz = readFileSync(good);
  const truncatedGz = join(root, 'hostile-truncated-gzip.tgz');
  writeFileSync(truncatedGz, gz.subarray(0, gz.length - 20));
  cases.push([truncatedGz, /gunzip|truncated/]);
  const bomb = join(root, 'hostile-bomb.tgz');
  const member = gzipSync(Buffer.alloc(64 * 1024 * 1024));
  writeFileSync(bomb, Buffer.concat(Array(17).fill(member)));
  cases.push([bomb, /unpacks to more than/]);
  for (const [file, reason] of cases) {
    const r = check(file);
    assert.equal(r.code, 2, file);
    assert.match(r.stderr, reason, file);
  }
  assert.equal(check(good).code, 0);
});

test('install lifecycle scripts fail unless allowed per script with a reason', () => {
  const scripts = { postinstall: 'node setup.js', prepare: 'node -e 0', prepublishOnly: 'node -e 0' };
  const blocked = check(pack('lifecycle', { 'index.js': 'x\n' }, { scripts }));
  assert.equal(blocked.code, 1);
  assert.deepEqual(rules(blocked.report), ['lifecycle-script']);
  assert.deepEqual(blocked.report.findings.map((f) => f.path), ['package.json#postinstall']);
  const text = spawnSync('node', [CLI, 'check', pack('lifecycle-text', { 'index.js': 'x\n' }, { scripts })], { encoding: 'utf8' }).stdout;
  assert.match(text, /HINT .*node-gyp rebuild.*package\.json#postinstall/);
  const allowed = check(pack('lifecycle-allowed', { 'index.js': 'x\n' }, {
    scripts,
    shipsafe: { allow: [{ rule: 'lifecycle-script', path: 'package.json#postinstall', reason: 'downloads the platform binary' }] },
  }));
  assert.equal(allowed.code, 0);
  const gyp = check(pack('lifecycle-gyp', { 'index.js': 'x\n', 'binding.gyp': '{}\n' }));
  assert.equal(gyp.code, 1);
  assert.match(gyp.report.findings[0].detail, /binding\.gyp/);
});

test('publish intent: private, scoped access, registry mismatch and prerelease on latest', () => {
  const priv = check(pack('intent-private', { 'index.js': 'x\n' }, { private: true }));
  assert.equal(priv.code, 1);
  assert.deepEqual(rules(priv.report), ['publish-intent']);
  const pinned = check(pack('intent-pinned', { 'index.js': 'x\n' }, { version: '2.0.0-beta.1', publishConfig: { tag: 'latest' } }));
  assert.deepEqual(rules(pinned.report), ['publish-intent']);
  const pre = pack('intent-pre', { 'index.js': 'x\n' }, { version: '2.0.0-beta.1' });
  assert.match(check(pre).report.warnings.join('\n'), /latest dist-tag/);
  assert.match(hook(`npm publish ${pre}`).permissionDecisionReason, /--tag next/);
  assert.equal(hook(`npm publish ${pre} --tag next`), null);
  assert.equal(hook(`npm publish ${pre} --tag=beta`), null);
  const scoped = pack('intent-scoped', { 'index.js': 'x\n' }, { name: '@probe/intent-scoped' });
  assert.match(hook(`npm publish ${scoped}`).permissionDecisionReason, /--access public/);
  assert.equal(hook(`npm publish ${scoped} --access public`), null);
  assert.equal(hook(`npm publish ${scoped} --access=restricted`), null);
  const scopedConfigured = pack('intent-scoped-config', { 'index.js': 'x\n' }, { name: '@probe/intent-scoped-config', publishConfig: { access: 'public', registry: 'https://registry.npmjs.org/' } });
  assert.equal(hook(`npm publish ${scopedConfigured}`), null);
  assert.equal(hook(`npm publish ${scopedConfigured} --registry https://registry.npmjs.org`), null);
  assert.match(hook(`npm publish ${scopedConfigured} --registry http://127.0.0.1:4873`).permissionDecisionReason, /contradicts publishConfig\.registry/);
});

test('entry points in main, types, bin and exports must exist in the tarball', () => {
  const files = { 'dist/index.js': 'x\n', 'dist/index.d.ts': 'x\n', 'dist/feat/a.js': 'x\n', 'bin/cli.js': 'x\n', 'lib/index.js': 'x\n' };
  const ok = check(pack('entry-ok', files, {
    main: './lib', types: 'dist/index.d.ts', bin: { tool: './bin/cli.js' },
    exports: { '.': { types: './dist/index.d.ts', import: './dist/index.js', default: './dist/index.js' }, './feat/*': './dist/feat/*.js', './internal/*': null, './package.json': './package.json' },
  }));
  assert.equal(ok.code, 0, JSON.stringify(ok.report?.findings));
  const bad = check(pack('entry-bad', files, {
    main: 'dist/missing.js', bin: './bin/nope.js',
    exports: { '.': { node: { import: './dist/index.mjs' }, default: './dist/index.js' }, './x/*': ['./dist/x/*.js'] },
  }));
  assert.equal(bad.code, 1);
  assert.deepEqual(rules(bad.report), ['entry-point']);
  assert.deepEqual(bad.report.findings.map((f) => f.path).sort(), ['package.json#bin', 'package.json#exports["./x/*"][0]', 'package.json#exports["."]["node"]["import"]', 'package.json#main'].sort());
});

test('release orchestrators are denied with a pack-gate-publish hint; npm stage publish is gated', () => {
  for (const c of ['lerna publish', 'npx lerna publish from-git', 'changeset publish', 'pnpm changeset publish', 'yarn changeset publish', 'npx semantic-release', 'semantic-release --ci', 'release-it', 'np', 'npx np 2.0.0']) {
    const r = hook(c);
    assert.equal(r?.permissionDecision, 'deny', c);
    assert.match(r.permissionDecisionReason, /shipsafe check out\/\*\.tgz/, c);
  }
  for (const c of ['lerna version', 'changeset version', 'semantic-release --dry-run', 'release-it --dry-run', 'np --preview', 'np --no-publish', 'release-it --no-npm', 'lerna publish --help']) {
    assert.equal(hook(c), null, c);
  }
  assert.equal(hook('npm stage publish')?.permissionDecision, 'deny');
  assert.equal(hook(`npm stage publish ${good}`), null);
  assert.match(hook(`npm stage publish ${leaky}`).permissionDecisionReason, /source-map/);
});

test('secret tokens in shipped files fail with a redacted detail', () => {
  const fake = (prefix, n, ch = 'A') => prefix + ch.repeat(n);
  const tokens = [
    fake('AK' + 'IA', 16), fake('AS' + 'IA', 16), fake('gh' + 'p_', 36, 'a'), fake('gh' + 's_', 36, 'b'), fake('github' + '_pat_', 40, 'c'),
    fake('np' + 'm_', 36, 'd'), fake('sk' + '_live_', 24, 'e'), fake('rk' + '_live_', 24, 'f'), fake('xo' + 'xb-', 20, '1'),
    '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----',
  ];
  const files = Object.fromEntries(tokens.map((t, i) => [`dist/t${i}.js`, `const k = "${t}";\n`]));
  const r = check(pack('secrets', files));
  assert.equal(r.code, 1);
  assert.deepEqual(rules(r.report), ['secret-token']);
  assert.equal(r.report.findings.length, tokens.length);
  for (const [i, t] of tokens.entries()) {
    const f = r.report.findings.find((x) => x.path === `dist/t${i}.js`);
    assert.ok(f, t.slice(0, 6));
    assert.ok(!f.detail.includes(t), 'detail must be redacted');
    assert.match(f.detail, new RegExp(`\\(${t.length} chars\\)`));
  }
  assert.equal(check(pack('not-secrets', { 'index.js': 'const a = "AKIA_NOT_A_KEY"; const b = "-----BEGIN PUBLIC KEY-----"; const c = "ghp_short";\n' })).code, 0);
});
