import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
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
  for (const c of ['npm publish', 'npm publish --access public --otp 123456', 'pnpm --filter x publish', 'npm --loglevel warn publish', 'bun publish', 'yarn npm publish', 'FOO=1 timeout 60 npm publish', 'env -u A -u B npm publish', 'npm publish ./pkgdir']) {
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

test('extra credential files and build artifacts fail under their own rules', () => {
  const creds = ['.git-credentials', '.netrc', '.pypirc', '.aws/credentials', 'keys/release.jks', 'android.keystore'];
  const artifacts = ['tsconfig.tsbuildinfo', 'coverage/lcov.info', '.nyc_output/out.json', 'dist/meta.json'];
  const files = Object.fromEntries([...creds, ...artifacts].map((p) => [p, 'x\n']));
  files['dist/meta.json'] = JSON.stringify({ inputs: { 'lib/a.js': {} }, outputs: { 'dist/a.js': {} } });
  files['dist/data.json'] = JSON.stringify({ inputs: [], note: 'not a metafile' });
  const r = check(pack('paths', files, { files: ['**/*', '.*', '.aws/*', '.nyc_output/*'] }));
  const byPath = Object.fromEntries(r.report.findings.map((f) => [f.path, f.rule]));
  for (const p of creds) assert.equal(byPath[p], 'sensitive-file', p);
  for (const p of artifacts) assert.equal(byPath[p], 'build-artifact', p);
  assert.equal(byPath['dist/data.json'], undefined);
});

test('unknown config keys and nested archives are warnings, not failures', () => {
  const r = check(pack('warns', { 'index.js': 'x\n', 'assets/bundle.zip': 'PK\n' }, { shipsafe: { maxFilesBytes: 10, allow: [{ rule: 'bucket-url', path: 'x', reason: 'kept to test warnings', note: 'typo' }] } }));
  assert.equal(r.code, 0);
  const text = r.report.warnings.join('\n');
  assert.match(text, /unknown config key shipsafe\.maxFilesBytes/);
  assert.match(text, /unknown key shipsafe\.allow\[0\]\.note/);
  assert.match(text, /nested archive assets\/bundle\.zip was not scanned/);
});

function runAsync(args) {
  return new Promise((done) => {
    execFile('node', [CLI, ...args], { encoding: 'utf8' }, (err, stdout, stderr) => done({ code: err ? err.code : 0, stdout, stderr }));
  });
}

async function withRegistry(packuments, fn) {
  const server = createServer((req, res) => {
    const doc = packuments[decodeURIComponent(req.url.slice(1))];
    if (doc === 500) { res.writeHead(500); res.end(); return; }
    if (Buffer.isBuffer(doc)) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(doc); return; }
    res.writeHead(doc ? 200 : 404, { 'content-type': 'application/json' });
    res.end(JSON.stringify(doc ?? { error: 'not found' }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.close();
  }
}

test('verify matches the registry dist.integrity against the local tarball', async () => {
  const integrity = `sha512-${createHash('sha512').update(readFileSync(good)).digest('base64')}`;
  const scoped = pack('verify-scoped', { 'index.js': 'x\n' }, { name: '@probe/verify-scoped' });
  const scopedIntegrity = `sha512-${createHash('sha512').update(readFileSync(scoped)).digest('base64')}`;
  await withRegistry({
    good: { name: 'good', versions: { '1.0.0': { dist: { integrity } } } },
    '@probe/verify-scoped': { versions: { '1.0.0': { dist: { integrity: scopedIntegrity } } } },
    leaky: { versions: { '1.0.0': { dist: { integrity } } } },
    'verify-old': { versions: { '0.9.0': { dist: { integrity } } } },
    'verify-down': 500,
  }, async (registry) => {
    const ok = await runAsync(['verify', good, '--registry', registry, '--json']);
    assert.equal(ok.code, 0, ok.stderr);
    assert.equal(JSON.parse(ok.stdout).match, true);
    assert.equal((await runAsync(['verify', scoped, `--registry=${registry}`])).code, 0);
    const other = await runAsync(['verify', leaky, '--registry', registry]);
    assert.equal(other.code, 1);
    assert.match(other.stdout, /different file/);
    assert.equal((await runAsync(['verify', pack('verify-missing', { 'index.js': 'x\n' }), '--registry', registry])).code, 1);
    assert.match((await runAsync(['verify', pack('verify-old', { 'index.js': 'x\n' }), '--registry', registry])).stdout, /not published/);
    assert.equal((await runAsync(['verify', pack('verify-down', { 'index.js': 'x\n' }), '--registry', registry])).code, 2);
  });
  const viaConfig = pack('verify-config', { 'index.js': 'x\n' }, { publishConfig: { registry: 'http://127.0.0.1:9/' } });
  const down = await runAsync(['verify', viaConfig]);
  assert.equal(down.code, 2);
  assert.match(down.stderr, /cannot reach http:\/\/127\.0\.0\.1:9/);
});

test('diff lists file changes and labels risk-raising changes', async () => {
  const oldTgz = pack('diff-old', { 'dist/a.js': 'a\n', 'dist/b.js': 'b\n', 'dist/big.js': 'x'.repeat(2000) }, {
    name: 'diffpkg', exports: { '.': './dist/a.js' }, dependencies: { 'left-pad': '^1.0.0' }, bin: { one: './dist/a.js' },
  });
  const newTgz = pack('diff-new', { 'dist/a.js': 'a\n', 'dist/c.js': 'c\n', 'dist/big.js': 'x'.repeat(9000) }, {
    name: 'diffpkg', version: '1.1.0', exports: { '.': './dist/a.js', './c': './dist/c.js' },
    dependencies: { 'left-pad': '^1.0.0', 'is-odd': '^3.0.0' }, bin: { one: './dist/a.js', two: './dist/c.js' },
    scripts: { postinstall: 'node dist/c.js' },
    shipsafe: { allow: [{ rule: 'lifecycle-script', path: 'package.json#postinstall', reason: 'needed for the diff test' }] },
  });
  const local = await runAsync(['diff', newTgz, oldTgz, '--json']);
  assert.equal(local.code, 0, local.stderr);
  const d = JSON.parse(local.stdout);
  assert.equal(d.new, 'diffpkg@1.1.0');
  assert.equal(d.old, 'diffpkg@1.0.0');
  assert.deepEqual(d.added.map((f) => f.path), ['dist/c.js']);
  assert.deepEqual(d.removed.map((f) => f.path), ['dist/b.js']);
  assert.deepEqual(d.grown.map((f) => f.path), ['dist/big.js', 'package.json']);
  assert.deepEqual(d.risks.map((r) => r.label).sort(), ['new-bin', 'new-dependency', 'new-exception', 'new-export', 'new-lifecycle-script', 'size-jump']);
  const text = await runAsync(['diff', newTgz, oldTgz]);
  assert.match(text.stdout, /RISK  new-lifecycle-script +package\.json#postinstall/);
  assert.match(text.stdout, /ADD   dist\/c\.js/);
  const md = await runAsync(['diff', newTgz, oldTgz, '--format', 'markdown']);
  assert.match(md.stdout, /^### shipsafe diff: `diffpkg@1\.1\.0` vs `diffpkg@1\.0\.0`/);
  assert.match(md.stdout, /\| `new-bin` \| two -> \.\/dist\/c\.js \|/);
  const doc = { 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': { dist: {} } } };
  await withRegistry({ diffpkg: doc, '-/diffpkg-1.0.0.tgz': readFileSync(oldTgz) }, async (registry) => {
    doc.versions['1.0.0'].dist.tarball = `${registry}/-/diffpkg-1.0.0.tgz`;
    const viaTag = await runAsync(['diff', newTgz, '--registry', registry, '--json']);
    assert.equal(viaTag.code, 0, viaTag.stderr);
    assert.equal(JSON.parse(viaTag.stdout).old, 'diffpkg@1.0.0');
    const viaVersion = await runAsync(['diff', newTgz, '--against', 'diffpkg@1.0.0', '--registry', registry, '--json']);
    assert.equal(JSON.parse(viaVersion.stdout).risks.length, 6);
    const none = await runAsync(['diff', newTgz, '--against', 'next', '--registry', registry]);
    assert.equal(none.code, 0);
    assert.match(none.stdout, /no baseline/);
  });
});

test('check emits SARIF 2.1.0 and a markdown summary', () => {
  const allowed = pack('sarif-allowed', { 'index.js': 'fetch("https://pub-1.r2.dev/x")\n' }, { shipsafe: { allow: [{ rule: 'bucket-url', path: '*.js', reason: 'documented public bucket' }] } });
  const r = spawnSync('node', [CLI, 'check', leaky, allowed, '--format', 'sarif'], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  const sarif = JSON.parse(r.stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  const { driver } = sarif.runs[0].tool;
  assert.equal(driver.name, 'shipsafe');
  const ruleIds = new Set(driver.rules.map((x) => x.id));
  for (const res of sarif.runs[0].results) {
    assert.ok(ruleIds.has(res.ruleId), res.ruleId);
    assert.ok(res.message.text.length > 0);
    assert.ok(res.locations[0].physicalLocation.artifactLocation.uri.length > 0);
    assert.ok(!res.locations[0].physicalLocation.artifactLocation.uri.includes('#'));
  }
  assert.ok(sarif.runs[0].results.some((x) => x.ruleId === 'source-map' && !x.suppressions));
  assert.equal(sarif.runs[0].results.find((x) => x.ruleId === 'bucket-url').suppressions[0].justification, 'documented public bucket');
  const md = spawnSync('node', [CLI, 'check', leaky, '--format=markdown'], { encoding: 'utf8' });
  assert.equal(md.status, 1);
  assert.match(md.stdout, /^### shipsafe: FAIL `leaky@1\.0\.0`/);
  assert.match(md.stdout, /\| \*\*FAIL\*\* \| `source-map` \| `dist\/index\.js\.map` \|/);
  assert.match(md.stdout, /File inventory \(\d+\)/);
  assert.equal(spawnSync('node', [CLI, 'check', good, '--format', 'xml'], { encoding: 'utf8' }).status, 2);
});

test('audit gates the last N published versions from a registry', async () => {
  const v1 = readFileSync(pack('audit-v1', { 'index.js': 'x\n' }, { name: 'auditpkg' }));
  const v2 = readFileSync(pack('audit-v2', { 'index.js': 'x\n', 'index.js.map': '{}' }, { name: 'auditpkg', version: '1.1.0' }));
  const v3 = readFileSync(pack('audit-v3', { 'index.js': 'y\n' }, { name: 'auditpkg', version: '1.2.0' }));
  const sri = (b) => `sha512-${createHash('sha512').update(b).digest('base64')}`;
  const doc = { name: 'auditpkg', time: { '1.0.0': '2026-01-01T00:00:00Z', '1.1.0': '2026-02-01T00:00:00Z', '1.2.0': '2026-03-01T00:00:00Z' }, versions: {} };
  await withRegistry({ auditpkg: doc, '-/1.0.0.tgz': v1, '-/1.1.0.tgz': v2, '-/1.2.0.tgz': v3 }, async (registry) => {
    for (const [v, b] of [['1.0.0', v1], ['1.1.0', v2], ['1.2.0', v3]]) doc.versions[v] = { dist: { tarball: `${registry}/-/${v}.tgz`, integrity: sri(b) } };
    const two = await runAsync(['audit', 'auditpkg', '--versions', '2', '--registry', registry, '--json']);
    assert.equal(two.code, 1, two.stderr);
    const a = JSON.parse(two.stdout);
    assert.deepEqual(a.results.map((r) => [r.version, r.pass]), [['1.2.0', true], ['1.1.0', false]]);
    assert.equal(a.results[1].findings[0].rule, 'source-map');
    const text = await runAsync(['audit', 'auditpkg', '--versions=1', '--registry', registry]);
    assert.equal(text.code, 0);
    assert.match(text.stdout, /PASS  1\.2\.0/);
    doc.versions['1.2.0'].dist.integrity = sri(v1);
    const tampered = await runAsync(['audit', 'auditpkg', '--versions', '1', '--registry', registry]);
    assert.equal(tampered.code, 2);
    assert.match(tampered.stdout, /does not match dist\.integrity/);
    assert.equal((await runAsync(['audit', 'nope', '--registry', registry])).code, 2);
  });
});

test('check-dir and the deploy hook guard static build output', () => {
  const site = join(root, 'site');
  mkdirSync(join(site, 'dist'), { recursive: true });
  mkdirSync(join(site, 'clean'), { recursive: true });
  mkdirSync(join(site, '.vercel/output/static'), { recursive: true });
  writeFileSync(join(site, 'package.json'), JSON.stringify({ name: 'site', shipsafe: { allow: [{ rule: 'bucket-url', path: 'assets.js', reason: 'public image bucket of the site' }] } }));
  writeFileSync(join(site, 'dist/app.js'), 'a();\n//# sourceMappingURL=app.js.map\n');
  writeFileSync(join(site, 'dist/app.js.map'), '{"version":3}');
  writeFileSync(join(site, 'clean/app.js'), 'a();\n');
  writeFileSync(join(site, 'clean/assets.js'), 'fetch("https://pub-9.r2.dev/logo.png")\n');
  writeFileSync(join(site, '.vercel/output/static/index.html'), '<html></html>\n');
  writeFileSync(join(site, 'firebase.json'), JSON.stringify({ hosting: { public: 'dist' } }));
  writeFileSync(join(site, 'netlify.toml'), '[build]\n  publish = "clean"\n');
  const bad = spawnSync('node', [CLI, 'check-dir', join(site, 'dist'), '--json'], { encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.deepEqual(rules(JSON.parse(bad.stdout)), ['source-map']);
  const ok = spawnSync('node', [CLI, 'check-dir', join(site, 'clean'), '--json'], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stdout);
  assert.equal(JSON.parse(ok.stdout).findings[0].allowed, true);
  assert.match(hook('wrangler pages deploy dist --project-name site', site).permissionDecisionReason, /source-map/);
  assert.equal(hook('npx wrangler pages deploy clean', site), null);
  assert.match(hook('firebase deploy', site).permissionDecisionReason, /check-dir failed/);
  assert.equal(hook('firebase deploy --only functions', site), null);
  assert.equal(hook('netlify deploy --prod', site), null);
  assert.match(hook('netlify deploy --dir=dist', site).permissionDecisionReason, /source-map/);
  assert.equal(hook('vercel deploy --prebuilt', site), null);
  assert.equal(hook('vercel env ls --prebuilt', site), null);
  assert.match(hook('wrangler pages deploy', site).permissionDecisionReason, /names no output directory/);
  assert.match(hook('wrangler pages deploy missing', site).permissionDecisionReason, /not found/);
  assert.equal(hook('wrangler deploy', site), null);
});

test('gh release create and upload gate attached tarballs', () => {
  const rel = join(root, 'release');
  mkdirSync(rel, { recursive: true });
  const leakyTar = join(rel, 'bundle.tar.gz');
  const cleanTar = join(rel, 'clean.tgz');
  const inner = join(rel, 'inner');
  mkdirSync(join(inner, 'bundle'), { recursive: true });
  writeFileSync(join(inner, 'bundle/app.js'), 'a()\n');
  writeFileSync(join(inner, 'bundle/app.js.map'), '{}');
  execFileSync('tar', ['-czf', leakyTar, '-C', inner, 'bundle']);
  execFileSync('tar', ['-czf', cleanTar, '-C', inner, 'bundle/app.js']);
  writeFileSync(join(rel, 'app.zip'), 'PK\n');
  writeFileSync(join(rel, 'SHA256SUMS'), 'x\n');
  assert.match(hook(`gh release create v1 ${leakyTar}#Bundle --notes "x"`, rel).permissionDecisionReason, /source-map/);
  assert.equal(hook(`gh release create v1 clean.tgz SHA256SUMS -t "v1" --generate-notes`, rel), null);
  assert.equal(hook(`gh release upload v1 ${good}`, rel), null);
  assert.match(hook(`gh release upload v1 ${leaky} --clobber`).permissionDecisionReason, /source-map/);
  assert.match(hook('gh release upload v1 *.tar.gz', rel).permissionDecisionReason, /source-map/);
  assert.match(hook('gh release create v1 app.zip', rel).permissionDecisionReason, /could not check .*app\.zip/);
  writeFileSync(join(rel, 'app.jar'), 'PK\n');
  assert.match(hook('gh release create v1 app.jar', rel).permissionDecisionReason, /cannot scan yet/);
  assert.equal(hook('gh release create v1 --generate-notes', rel), null);
  assert.equal(hook('gh release view v1', rel), null);
});

function zipDir(name, tree, extraArgs = []) {
  const dir = join(root, `${name}-src`);
  for (const [path, content] of Object.entries(tree)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  const out = join(root, name);
  execFileSync('zip', ['-qr', ...extraArgs, out, '.'], { cwd: dir });
  return out;
}

test('zip reader: vsix and browser-extension archives are scanned', () => {
  const vsixTree = (extra) => ({
    '[Content_Types].xml': '<Types/>', 'extension.vsixmanifest': '<PackageManifest/>',
    'extension/package.json': JSON.stringify({ name: 'ext', publisher: 'probe', version: '0.0.1', main: './out/extension.js', scripts: { 'vscode:prepublish': 'tsc', postinstall: 'node x' } }),
    'extension/out/extension.js': 'exports.activate=()=>{};\n'.repeat(50),
    ...extra,
  });
  const bad = check(zipDir('bad.vsix', vsixTree({ 'extension/out/extension.js.map': '{}' })));
  assert.equal(bad.code, 1);
  assert.deepEqual(rules(bad.report), ['source-map']);
  assert.equal(bad.report.kind, 'vsix');
  const ok = check(zipDir('ok.vsix', vsixTree({})));
  assert.equal(ok.code, 0, JSON.stringify(ok.report?.findings));
  assert.equal(ok.report.package, 'ext@0.0.1 (vsix)');
  const ext = check(zipDir('ext.zip', {
    'manifest.json': JSON.stringify({ manifest_version: 3, name: 'probe', version: '1.0', host_permissions: ['<all_urls>'] }),
    'bg.js': 'x\n', 'src/bg.ts': 'x\n',
  }));
  assert.equal(ext.code, 1);
  assert.deepEqual(rules(ext.report), ['source-dir', 'typescript-source']);
  assert.match(ext.report.warnings.join('\n'), /broad host access \(<all_urls>\)/);
  const plain = check(zipDir('plain.zip', { 'a.js': 'x\n' }));
  assert.equal(plain.code, 0);
  assert.equal(plain.report.kind, 'generic');
});

test('zip reader: symlinks are findings, truncated or hostile zips exit 2', () => {
  const dir = join(root, 'ziplink-src');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'manifest.json'), '{"name":"l","version":"1"}');
  execFileSync('ln', ['-sf', '/etc/hosts', join(dir, 'hosts')]);
  const linked = join(root, 'link.zip');
  execFileSync('zip', ['-qry', linked, '.'], { cwd: dir });
  const r = check(linked);
  assert.equal(r.code, 1);
  assert.deepEqual(rules(r.report), ['archive-integrity']);
  const whole = readFileSync(zipDir('whole.zip', { 'a.js': 'x'.repeat(5000) }));
  const truncated = join(root, 'hostile-truncated.zip');
  writeFileSync(truncated, whole.subarray(0, whole.length - 30));
  assert.equal(check(truncated).code, 2);
  const cut = join(root, 'hostile-cut.zip');
  writeFileSync(cut, Buffer.concat([whole.subarray(0, 60), whole.subarray(whole.length - 200)]));
  assert.equal(check(cut).code, 2);
});

function asarPack(name, tree, extra = []) {
  const dir = join(root, `${name}-app`);
  for (const [path, content] of Object.entries(tree)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  const out = join(root, `${name}.asar`);
  const r = spawnSync('npx', ['--yes', '@electron/asar', 'pack', dir, out, ...extra], { encoding: 'utf8' });
  return r.status === 0 ? out : null;
}

test('Electron asar archives are scanned, directly and inside a zip', (t) => {
  const bad = asarPack('bad-app', { 'package.json': '{"name":"app"}', 'dist/main.js': 'a()\n', 'dist/main.js.map': '{}', 'src/renderer.ts': 'x\n' });
  if (!bad) { t.skip('@electron/asar is not available'); return; }
  const r = check(bad);
  assert.equal(r.code, 1);
  assert.equal(r.report.kind, 'asar');
  assert.deepEqual(rules(r.report), ['source-map', 'typescript-source']);
  const clean = asarPack('clean-app', { 'package.json': '{"name":"app"}', 'dist/main.js': 'a()\n', 'lib/native.node': 'bin' }, ['--unpack', '*.node']);
  const ok = check(clean);
  assert.equal(ok.code, 0, JSON.stringify(ok.report?.findings));
  assert.match(ok.report.warnings.join('\n'), /lib\/native\.node is unpacked/);
  const zipDirPath = join(root, 'mac-zip-src/App.app/Contents/Resources');
  mkdirSync(zipDirPath, { recursive: true });
  writeFileSync(join(zipDirPath, 'app.asar'), readFileSync(bad));
  const zipped = join(root, 'mac-app.zip');
  execFileSync('zip', ['-qr', zipped, '.'], { cwd: join(root, 'mac-zip-src') });
  const z = check(zipped);
  assert.equal(z.code, 1);
  assert.ok(z.report.findings.some((f) => f.path === 'App.app/Contents/Resources/app.asar/dist/main.js.map'));
  const cut = join(root, 'hostile-cut.asar');
  const whole = readFileSync(bad);
  writeFileSync(cut, whole.subarray(0, whole.length - 10));
  assert.equal(check(cut).code, 2);
});
