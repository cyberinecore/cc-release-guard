import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (p) => JSON.parse(readFileSync(join(root, p), 'utf8'));
const tracked = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
const HOOK_ARGS = ['${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs', 'hook'];

test('versions agree across plugin.json, cli/package.json and the CLI VERSION', () => {
  const cliVersion = /^const VERSION = '([^']+)';$/m.exec(readFileSync(join(root, 'cli/shipsafe.mjs'), 'utf8'))?.[1];
  assert.ok(cliVersion, 'cli/shipsafe.mjs declares VERSION');
  assert.equal(readJson('.claude-plugin/plugin.json').version, cliVersion);
  assert.equal(readJson('cli/package.json').version, cliVersion);
});

test('the manifest carries the metadata the directory reads', () => {
  const m = readJson('.claude-plugin/plugin.json');
  assert.match(m.name, /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/);
  for (const key of ['description', 'version', 'license', 'homepage', 'repository', 'displayName']) assert.ok(m[key], `plugin.json ${key}`);
  assert.ok(m.author?.name, 'plugin.json author.name');
  assert.equal(m.hooks, undefined, 'hooks/hooks.json loads automatically and must not be listed');
  for (const s of [m.displayName, m.author.name]) assert.match(s, /^[\x20-\x7e]+$/, 'ASCII only');
  const market = readJson('.claude-plugin/marketplace.json');
  assert.equal(market.plugins.length, 1);
  assert.equal(market.plugins[0].name, m.name);
  assert.equal(market.plugins[0].source, './');
});

test('every hook runs node on the CLI inside the plugin, exec form, with a timeout', () => {
  const h = readJson('hooks/hooks.json');
  assert.deepEqual(Object.keys(h), ['hooks']);
  assert.deepEqual(Object.keys(h.hooks), ['PreToolUse']);
  assert.ok(existsSync(join(root, 'cli/shipsafe.mjs')));
  const cmds = h.hooks.PreToolUse.flatMap((e) => {
    assert.equal(e.matcher, 'Bash');
    return e.hooks;
  });
  assert.ok(cmds.length > 0);
  for (const cmd of cmds) {
    assert.equal(cmd.type, 'command');
    assert.equal(cmd.command, 'node');
    assert.deepEqual(cmd.args, HOOK_ARGS);
    assert.match(cmd.if, /^Bash\(.+\)$/);
    assert.ok(Number.isInteger(cmd.timeout) && cmd.timeout > 0);
  }
});

test('README and LICENSE satisfy the directory', () => {
  const readme = readFileSync(join(root, 'README.md'), 'utf8').replace(/```[\s\S]*?```/g, '');
  assert.ok(readme.split(/\s+/).filter(Boolean).length >= 40, 'README has at least 40 words outside code blocks');
  assert.match(readFileSync(join(root, 'LICENSE'), 'utf8'), /MIT License/);
});

test('tracked files follow the directory file rules', () => {
  assert.ok(tracked.length <= 512, `${tracked.length} files`);
  const seen = new Map();
  const device = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;
  for (const f of tracked) {
    assert.ok(!f.startsWith('bin/'), 'no top-level bin/');
    assert.ok(!/(^|\/)(\.DS_Store|Thumbs\.db|desktop\.ini|__MACOSX)(\/|$)/.test(f), `system file ${f}`);
    assert.ok(!/(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|\.npmrc|bunfig\.toml|uv\.toml)$/.test(f), `lockfile or registry config ${f}`);
    for (const part of f.split('/')) {
      assert.ok(!/[:<>"|?*\\]/.test(part), `invalid character in ${f}`);
      assert.ok(!/[. ]$/.test(part), `trailing dot or space in ${f}`);
      assert.ok(!device.test(part), `device name in ${f}`);
    }
    const lower = f.toLowerCase();
    assert.ok(!seen.has(lower) || seen.get(lower) === f, `case-only duplicate ${f} vs ${seen.get(lower)}`);
    seen.set(lower, f);
    const p = join(root, f);
    if (!existsSync(p)) continue;
    assert.ok(!lstatSync(p).isSymbolicLink(), `symlink ${f}`);
    const isImage = /\.(png|jpe?g|gif|webp|svg|woff2?|ttf|otf)$/i.test(f);
    if (!isImage) assert.ok(statSync(p).size < 256 * 1024, `${f} is over 256 KiB`);
    if (!isImage) assert.ok(!readFileSync(p).includes(0), `${f} is binary`);
  }
});

test('no .gitattributes rewrites content', () => {
  for (const f of tracked.filter((t) => basename(t) === '.gitattributes')) {
    assert.ok(!/export-ignore|export-subst|filter|eol|text/.test(readFileSync(join(root, f), 'utf8')), f);
  }
});

test('skills have front matter with a single-string description and a matching name', () => {
  const skills = tracked.filter((f) => /^skills\/[^/]+\/SKILL\.md$/.test(f));
  assert.ok(skills.length >= 1);
  for (const f of skills) {
    const text = readFileSync(join(root, f), 'utf8');
    const fm = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(text);
    assert.ok(fm, `${f} has front matter`);
    const desc = /^description: (.+)$/m.exec(fm[1])?.[1].trim();
    assert.ok(desc && !/^[-[{>|&*!%@`'"]/.test(desc), `${f} description is one plain string`);
    assert.ok(!/: |\s#/.test(desc), `${f} description has no YAML mapping or comment marker`);
    assert.equal(/^name: (.+)$/m.exec(fm[1])?.[1].trim(), basename(dirname(f)), `${f} name matches its folder`);
  }
});

test('no root CLAUDE.md, since strict plugin validation rejects it', () => {
  assert.ok(!tracked.includes('CLAUDE.md'));
});
