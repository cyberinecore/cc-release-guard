#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const VERSION = '0.1.0';
const DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024;
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall'];
const MAX_UNPACKED_BYTES = 1024 * 1024 * 1024;
const MANAGERS = new Set(['npm', 'pnpm', 'bun', 'yarn']);
const WRAPPERS = new Set(['time', 'nice', 'nohup', 'command', 'builtin', 'noglob', 'exec', 'sudo']);
const VALUE_OPTS = new Set([
  '-w', '--workspace', '--prefix', '-C', '--dir', '--filter', '-F', '--cwd', '--otp', '--tag',
  '--registry', '--userconfig', '--access', '--config', '--cache', '--auth-type', '--loglevel',
]);
const NON_PUBLISH_COMMANDS = new Set([
  'run', 'run-script', 'exec', 'x', 'dlx', 'install', 'i', 'add', 'ci', 'view', 'info', 'show', 'v',
  'help', 'pack', 'test', 't', 'init', 'create', 'link', 'remove', 'rm', 'uninstall', 'update', 'up',
  'why', 'ls', 'list', 'search', 'outdated', 'audit', 'config', 'set', 'get', 'cache', 'owner',
  'access', 'dist-tag', 'deprecate', 'unpublish', 'whoami', 'login', 'logout', 'adduser', 'version',
  'explain', 'fund', 'doctor', 'build', 'upgrade', 'patch', 'pm',
]);

const RULES = {
  'source-map': 'source map file',
  'sources-content': 'embedded original source (sourcesContent)',
  'inline-source-map': 'inline source map (sourceMappingURL=data:)',
  'remote-source-map': 'source map served from a URL',
  'typescript-source': 'TypeScript source file (only .d.ts is allowed)',
  'source-dir': 'path inside a src/ directory',
  'test-path': 'test file or test directory',
  'sensitive-file': 'credential or VCS file',
  'file-size': 'file over the size threshold',
  'bucket-url': 'URL to a storage bucket',
  'secret-token': 'credential string inside a shipped file',
  'lifecycle-script': 'install script that runs on every consumer machine',
  'publish-intent': 'package metadata that contradicts a public release',
  'entry-point': 'main, module, types, bin or exports target missing from the tarball',
  'archive-integrity': 'link, device or duplicate entry the scan cannot vouch for',
};

const BUCKET_HOSTS = [
  /s3:\/\/[a-z0-9][a-z0-9.-]*/gi,
  /\b(?:[a-z0-9.-]+\.)?s3[a-z0-9.-]*\.amazonaws\.com(?:\.cn)?\b/gi,
  /\b[a-z0-9.-]+\.r2\.cloudflarestorage\.com\b/gi,
  /\b[a-z0-9-]+\.r2\.dev\b/gi,
  /gs:\/\/[a-z0-9][a-z0-9._-]*/gi,
  /\b(?:[a-z0-9.-]+\.)?storage\.googleapis\.com\b/gi,
  /\bstorage\.cloud\.google\.com\b/gi,
  /\b[a-z0-9-]+\.blob\.core\.windows\.net\b/gi,
  /\b(?:[a-z0-9.-]+\.)?digitaloceanspaces\.com\b/gi,
  /\b(?:[a-z0-9.-]+\.)?backblazeb2\.com\b/gi,
  /\b(?:[a-z0-9.-]+\.)?wasabisys\.com\b/gi,
];

const SECRET_PATTERNS = [
  ['AWS access key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, 4],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, 4],
  ['GitHub token', /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g, 11],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/g, 4],
  ['Stripe live key', /\b[rs]k_live_[A-Za-z0-9]{20,247}\b/g, 8],
  ['Slack token', /\bxox[abpr]-[A-Za-z0-9-]{10,250}/g, 5],
  ['private key block', /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/g, 10],
];

class GuardError extends Error {}

function cstr(buf, start, len) {
  const slice = buf.subarray(start, start + len);
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? slice.length : end).toString('utf8');
}

function parseNumeric(buf, start, len) {
  if (buf[start] & 0x80) {
    let n = 0;
    for (let i = start + 1; i < start + len; i++) n = n * 256 + buf[i];
    return n;
  }
  const s = cstr(buf, start, len).trim();
  return s ? parseInt(s, 8) : 0;
}

function headerChecksumOk(h) {
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : h[i];
  return sum === parseNumeric(h, 148, 8);
}

function parsePax(data) {
  const out = {};
  let off = 0;
  const text = data.toString('utf8');
  while (off < text.length) {
    const sp = text.indexOf(' ', off);
    if (sp === -1) break;
    const len = parseInt(text.slice(off, sp), 10);
    if (!len) break;
    const record = text.slice(sp + 1, off + len - 1);
    const eq = record.indexOf('=');
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    off += len;
  }
  return out;
}

function readTar(buf) {
  const entries = [];
  let off = 0;
  let pax = {};
  let longName = null;
  let longLink = null;
  let ended = false;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) { ended = true; break; }
    if (!headerChecksumOk(h)) throw new GuardError(`not a valid tar archive (bad header checksum at byte ${off})`);
    const type = h[156] === 0 ? '0' : String.fromCharCode(h[156]);
    const size = pax.size !== undefined ? Number(pax.size) : parseNumeric(h, 124, 12);
    if (!Number.isSafeInteger(size) || size < 0) throw new GuardError(`malformed tar entry size at byte ${off}`);
    const name = cstr(h, 0, 100);
    const prefix = cstr(h, 257, 6).startsWith('ustar') ? cstr(h, 345, 155) : '';
    off += 512;
    if (off + size > buf.length) throw new GuardError(`the tar archive is truncated (entry at byte ${off - 512} needs ${size} bytes)`);
    const data = buf.subarray(off, off + size);
    off += Math.ceil(size / 512) * 512;
    if (type === 'x') { pax = parsePax(data); continue; }
    if (type === 'g') continue;
    if (type === 'L') { longName = cstr(data, 0, data.length); continue; }
    if (type === 'K') { longLink = cstr(data, 0, data.length); continue; }
    const path = pax.path ?? longName ?? (prefix ? `${prefix}/${name}` : name);
    const linkname = pax.linkpath ?? longLink ?? cstr(h, 157, 100);
    pax = {};
    longName = null;
    longLink = null;
    if (path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.split(/[\\/]/).includes('..')) {
      throw new GuardError(`the tar archive has an entry that escapes the package root: ${path}`);
    }
    entries.push({ path, type, size, data, linkname });
  }
  if (!ended) throw new GuardError('the tar archive is truncated (no end-of-archive marker)');
  return entries;
}

function stripRoot(path) {
  const i = path.indexOf('/');
  return i === -1 ? path : path.slice(i + 1);
}

function globToRegex(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') {
      re += '.*';
      i++;
      if (glob[i + 1] === '/') i++;
    } else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

function loadConfig(files) {
  const pkg = files.findLast((f) => f.path === 'package.json');
  if (!pkg) throw new GuardError('package.json not found at the tarball root');
  let json;
  try {
    json = JSON.parse(pkg.data.toString('utf8'));
  } catch (e) {
    throw new GuardError(`package.json is not valid JSON: ${e.message}`);
  }
  const raw = json.shipsafe ?? {};
  const maxFileBytes = raw.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  if (!Number.isFinite(maxFileBytes) || maxFileBytes <= 0) throw new GuardError('shipsafe.maxFileBytes must be a positive number');
  const allow = (raw.allow ?? []).map((a, i) => {
    if (!a || !RULES[a.rule]) throw new GuardError(`shipsafe.allow[${i}].rule must be one of: ${Object.keys(RULES).join(', ')}`);
    if (typeof a.path !== 'string' || !a.path) throw new GuardError(`shipsafe.allow[${i}].path is required`);
    if (typeof a.reason !== 'string' || a.reason.trim().length < 10) throw new GuardError(`shipsafe.allow[${i}].reason must explain the exception (10+ chars)`);
    return { ...a, re: globToRegex(a.path), used: false };
  });
  const scripts = json.scripts && typeof json.scripts === 'object' ? json.scripts : {};
  const publishConfig = json.publishConfig && typeof json.publishConfig === 'object' ? json.publishConfig : {};
  return { name: json.name, version: json.version, private: json.private === true, publishConfig, maxFileBytes, allow, scripts, pkg: json };
}

function isPrerelease(version) {
  return typeof version === 'string' && /^\d+\.\d+\.\d+-/.test(version);
}

function optionValue(args, name) {
  let value;
  for (let i = 0; i < args.length && args[i] !== '--'; i++) {
    if (args[i] === name) value = args[i + 1];
    else if (args[i].startsWith(`${name}=`)) value = args[i].slice(name.length + 1);
  }
  return value;
}

function entryTargets(pkg) {
  const out = [];
  for (const key of ['main', 'module', 'types', 'typings']) if (typeof pkg[key] === 'string') out.push([key, pkg[key], key === 'main']);
  if (typeof pkg.browser === 'string') out.push(['browser', pkg.browser, true]);
  if (typeof pkg.bin === 'string') out.push(['bin', pkg.bin, false]);
  else if (pkg.bin && typeof pkg.bin === 'object') for (const [k, v] of Object.entries(pkg.bin)) if (typeof v === 'string') out.push([`bin.${k}`, v, false]);
  const walk = (node, key) => {
    if (typeof node === 'string') out.push([key, node, false]);
    else if (Array.isArray(node)) node.forEach((n, i) => walk(n, `${key}[${i}]`));
    else if (node && typeof node === 'object') for (const [k, v] of Object.entries(node)) walk(v, `${key}[${JSON.stringify(k)}]`);
  };
  walk(pkg.exports, 'exports');
  return out;
}

function missingEntryPoints(pkg, present) {
  const missing = [];
  for (const [key, target, legacy] of entryTargets(pkg)) {
    if (key.startsWith('exports') && !target.startsWith('./')) continue;
    const rel = target.replace(/^(\.\/)+/, '').replace(/\/+$/, '');
    if (rel.includes('*')) {
      const re = new RegExp(`^${rel.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.+')}$`);
      if (![...present].some((f) => re.test(f))) missing.push([key, target]);
      continue;
    }
    const candidates = legacy ? [rel, `${rel}.js`, `${rel}.json`, `${rel}.node`, `${rel}/index.js`, `${rel}/index.json`] : [rel];
    if (!candidates.some((c) => present.has(c))) missing.push([key, target]);
  }
  return missing;
}

function scanPath(path) {
  const found = [];
  const segments = path.split('/');
  const dirs = segments.slice(0, -1);
  const base = segments[segments.length - 1];
  if (/\.map$/i.test(base)) found.push(['source-map', '']);
  if (/\.(ts|tsx|mts|cts)$/i.test(base) && !/\.d\.(ts|mts|cts)$/i.test(base)) found.push(['typescript-source', '']);
  if (dirs.includes('src')) found.push(['source-dir', '']);
  if (dirs.some((d) => ['test', 'tests', '__tests__', '__mocks__', '__fixtures__'].includes(d)) || /\.(test|spec)\.[cm]?[jt]sx?$/i.test(base)) found.push(['test-path', '']);
  if ((/^\.env(\..+)?$/.test(base) && !/^\.env\.(example|sample|template)$/.test(base)) || base === '.npmrc' || /\.(pem|key|p12|pfx)$/i.test(base) || /^id_(rsa|ed25519|ecdsa)/.test(base) || dirs.includes('.git')) found.push(['sensitive-file', '']);
  return found;
}

function scanContent(data) {
  const found = [];
  const text = data.toString('latin1');
  if (/sourcesContent\\?["']?\s*:/.test(text)) found.push(['sources-content', '']);
  const inline = text.match(/sourceMappingURL=data:[a-z][^,;\s]{0,60}/i);
  if (inline) found.push(['inline-source-map', inline[0]]);
  const remote = text.match(/sourceMappingURL=https?:\/\/[^\s'"`)]{1,200}/);
  if (remote) found.push(['remote-source-map', remote[0]]);
  const secrets = [];
  for (const [kind, re, keep] of SECRET_PATTERNS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) secrets.push(`${kind} ${m[0].slice(0, keep)}... (${m[0].length} chars)`);
  }
  if (secrets.length) found.push(['secret-token', secrets.slice(0, 5).join(', ') + (secrets.length > 5 ? `, +${secrets.length - 5} more` : '')]);
  const hosts = new Map();
  for (const re of BUCKET_HOSTS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) hosts.set(m[0].toLowerCase(), (hosts.get(m[0].toLowerCase()) ?? 0) + 1);
  }
  if (hosts.size) {
    const list = [...hosts.entries()].slice(0, 5).map(([h, n]) => (n > 1 ? `${h} (x${n})` : h));
    found.push(['bucket-url', list.join(', ') + (hosts.size > 5 ? `, +${hosts.size - 5} more` : '')]);
  }
  return found;
}

export function checkTarball(file) {
  const raw = readFileSync(file);
  const sha256 = createHash('sha256').update(raw).digest('hex');
  let tar;
  try {
    tar = raw[0] === 0x1f && raw[1] === 0x8b ? gunzipSync(raw, { maxOutputLength: MAX_UNPACKED_BYTES }) : raw;
  } catch (e) {
    if (e.code === 'ERR_BUFFER_TOO_LARGE' || e instanceof RangeError) throw new GuardError(`${file} unpacks to more than ${MAX_UNPACKED_BYTES} bytes; refusing to scan it`);
    throw new GuardError(`cannot gunzip ${file}: ${e.message}`);
  }
  const entries = readTar(tar);
  if (!entries.length) throw new GuardError('the tarball is empty');
  const files = entries
    .filter((e) => e.type === '0' || e.type === '7')
    .map((e) => ({ path: stripRoot(e.path), size: e.size, data: e.data }));
  const config = loadConfig(files);
  const findings = [];
  const warnings = [];
  const integrity = new Map();
  const note = (path, detail) => { if (!integrity.has(path)) integrity.set(path, detail); };
  for (const e of entries) {
    const path = stripRoot(e.path);
    if (e.type === '1' || e.type === '2') note(path, `${e.type === '2' ? 'symlink' : 'hardlink'} to ${e.linkname}; the gate cannot scan what it points at`);
    else if (e.type === '3' || e.type === '4' || e.type === '6') note(path, 'device or fifo entry');
    else if (!['0', '7', '5'].includes(e.type)) note(path, `unknown tar entry type ${JSON.stringify(e.type)}`);
  }
  const seen = new Set();
  for (const f of files) {
    if (seen.has(f.path)) note(f.path, 'duplicate path; the last copy wins on install, every copy was scanned');
    seen.add(f.path);
  }
  const record = (path, hits) => {
    for (const [rule, detail] of hits) {
      const allow = config.allow.find((a) => a.rule === rule && a.re.test(path));
      if (allow) allow.used = true;
      findings.push({ rule, path, detail, allowed: !!allow, reason: allow?.reason });
    }
  };
  for (const [path, detail] of integrity) record(path, [['archive-integrity', detail]]);
  for (const name of INSTALL_SCRIPTS) {
    if (typeof config.scripts[name] === 'string') record(`package.json#${name}`, [['lifecycle-script', config.scripts[name].slice(0, 120)]]);
  }
  if (config.private) record('package.json#private', [['publish-intent', '"private": true; npm refuses it, other managers may not']]);
  if (isPrerelease(config.version) && config.publishConfig.tag === 'latest') {
    record('package.json#publishConfig.tag', [['publish-intent', `prerelease ${config.version} pinned to the latest dist-tag`]]);
  } else if (isPrerelease(config.version) && !config.publishConfig.tag) {
    warnings.push(`prerelease ${config.version} goes to the latest dist-tag unless you publish with --tag <name>`);
  }
  const present = new Set(files.map((f) => f.path));
  for (const [key, target] of missingEntryPoints(config.pkg, present)) record(`package.json#${key}`, [['entry-point', `${target} is not in the tarball`]]);
  if (!config.scripts.install && !config.scripts.preinstall && files.some((f) => f.path === 'binding.gyp')) {
    record('package.json#install', [['lifecycle-script', 'implicit `node-gyp rebuild` because binding.gyp ships']]);
  }
  let unpackedBytes = 0;
  for (const f of files) {
    unpackedBytes += f.size;
    const hits = [...scanPath(f.path), ...scanContent(f.data)];
    if (f.size > config.maxFileBytes) hits.push(['file-size', `${f.size} bytes > ${config.maxFileBytes}`]);
    record(f.path, hits);
  }
  for (const a of config.allow) if (!a.used) warnings.push(`unused allow entry: ${a.rule} ${a.path}`);
  return {
    version: VERSION,
    file: resolve(file),
    package: `${config.name}@${config.version}`,
    manifest: { name: config.name, version: config.version, private: config.private, publishConfig: config.publishConfig },
    sha256,
    files: files.length,
    unpackedBytes,
    pass: findings.every((f) => f.allowed),
    findings,
    warnings,
  };
}

function formatReport(r) {
  const lines = [`shipsafe ${r.version}  ${r.package}  ${r.file}`, `sha256 ${r.sha256}  files ${r.files}  unpacked ${r.unpackedBytes} bytes`];
  for (const f of r.findings) {
    const tag = f.allowed ? 'ALLOW' : 'FAIL ';
    const detail = f.detail ? `: ${f.detail}` : '';
    lines.push(`${tag} ${f.rule.padEnd(18)} ${f.path}${detail}${f.allowed ? `  (${f.reason})` : ''}`);
  }
  for (const w of r.warnings) lines.push(`WARN  ${w}`);
  const blocking = r.findings.filter((f) => !f.allowed);
  if (blocking.length) {
    const rules = [...new Set(blocking.map((f) => f.rule))].map((k) => `${k} = ${RULES[k]}`);
    lines.push(`FAIL  ${blocking.length} finding(s). ${rules.join('; ')}`);
    const script = blocking.find((f) => f.rule === 'lifecycle-script');
    if (script) lines.push(`HINT  a native addon build such as \`node-gyp rebuild\` is a legitimate install script; allow it in the packed package.json with "shipsafe": { "allow": [{ "rule": "lifecycle-script", "path": "${script.path}", "reason": "<why consumers must run it>" }] }`);
  } else {
    lines.push(`PASS  publish exactly this file: npm publish ${r.file}`);
  }
  return lines.join('\n');
}

function tokenize(command) {
  const segments = [[]];
  let cur = null;
  const push = () => { if (cur !== null) { segments[segments.length - 1].push(cur); cur = null; } };
  const split = () => { push(); if (segments[segments.length - 1].length) segments.push([]); };
  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    if (c === "'") {
      const end = command.indexOf("'", i + 1);
      cur = (cur ?? '') + command.slice(i + 1, end === -1 ? command.length : end);
      i = end === -1 ? command.length : end;
    } else if (c === '"') {
      let j = i + 1;
      let s = '';
      while (j < command.length && command[j] !== '"') {
        if (command[j] === '\\' && j + 1 < command.length) { s += command[j + 1]; j += 2; } else { s += command[j]; j++; }
      }
      cur = (cur ?? '') + s;
      i = j;
    } else if (c === '\\' && i + 1 < command.length) {
      if (command[i + 1] !== '\n') cur = (cur ?? '') + command[i + 1];
      i++;
    } else if (c === '$' && command[i + 1] === '(') {
      split();
      i++;
    } else if (';&|()\n`'.includes(c)) {
      split();
    } else if (c === ' ' || c === '\t') {
      push();
    } else {
      cur = (cur ?? '') + c;
    }
  }
  push();
  return segments.filter((s) => s.length);
}

function unwrap(tokens) {
  let t = tokens;
  for (;;) {
    while (t.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(t[0])) t = t.slice(1);
    if (!t.length) return t;
    const head = basename(t[0]);
    if (head === 'env') {
      t = t.slice(1);
      while (t.length && (t[0].startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(t[0]))) t = t.slice(1);
    } else if (head === 'timeout') {
      t = t.slice(1);
      while (t.length && t[0].startsWith('-')) t = t.slice(1);
      t = t.slice(1);
    } else if (WRAPPERS.has(head)) {
      t = t.slice(1);
    } else {
      return t;
    }
  }
}

function positionals(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { out.push(...args.slice(i + 1)); break; }
    if (a.startsWith('-')) {
      if (!a.includes('=') && VALUE_OPTS.has(a)) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}

function expandPath(arg, cwd) {
  if (arg === '~') return homedir();
  if (arg.startsWith('~/')) return resolve(homedir(), arg.slice(2));
  return resolve(cwd, arg);
}

function resolveTarball(arg, cwd) {
  if (/[$`]/.test(arg)) return { error: `tarball path "${arg}" uses shell expansion; pass a literal path` };
  const full = expandPath(arg, cwd);
  if (/[*?]/.test(basename(full))) {
    const dir = dirname(full);
    const re = globToRegex(basename(full));
    const matches = existsSync(dir) ? readdirSync(dir).filter((n) => re.test(n)) : [];
    if (matches.length !== 1) return { error: `"${arg}" matches ${matches.length} files; name exactly one tarball` };
    return { path: resolve(dir, matches[0]) };
  }
  return { path: full };
}

const RUNNERS = new Set(['npx', 'bunx', 'pnpx', 'corepack']);
const RUNNER_SUBCOMMANDS = new Set(['exec', 'x', 'dlx']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh']);
const RUNNER_VALUE_OPTS = new Set(['-p', '--package', '--shell-mode']);
const XARGS_VALUE_OPTS = new Set(['-I', '-J', '-L', '-n', '-P', '-s', '-E', '-d', '-a', '-R', '-S']);
const MAX_NESTING = 8;
const ORCHESTRATORS = new Set(['lerna', 'changeset', 'semantic-release', 'release-it', 'np']);
const ORCHESTRATOR_SAFE_FLAGS = new Set(['--help', '-h', '--version', '-v', '-V', '--dry-run', '-d', '--preview', '--no-publish', '--no-npm', '--no-npm.publish', '--npm.publish=false']);

function orchestratorPublishes(prog, args) {
  if (args.some((a) => ORCHESTRATOR_SAFE_FLAGS.has(a))) return false;
  if (prog === 'lerna' || prog === 'changeset') return args[firstPositional(args)] === 'publish';
  return true;
}

function firstPositional(args) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') return i + 1 < args.length ? i + 1 : -1;
    if (a.startsWith('-')) {
      if (!a.includes('=') && VALUE_OPTS.has(a)) i++;
      continue;
    }
    return i;
  }
  return -1;
}

function stripRunnerOpts(args, ctx) {
  let i = 0;
  while (i < args.length && args[i].startsWith('-')) {
    const a = args[i];
    if (a === '--') return args.slice(i + 1);
    if (a === '-c' || a === '--call') {
      if (args[i + 1] !== undefined) scanCommand(args[i + 1], ctx.cwd, ctx);
      return [];
    }
    i += !a.includes('=') && RUNNER_VALUE_OPTS.has(a) ? 2 : 1;
  }
  return args.slice(i);
}

function scanSegment(seg, cwd, ctx) {
  if (ctx.depth > MAX_NESTING) throw new GuardError('the command nests shells or runners too deeply');
  const t = unwrap(seg);
  if (!t.length) return cwd;
  const prog = basename(t[0]).replace(/^(.+?)@.*$/, '$1');
  const nested = (tokens, computed = ctx.computed) => scanSegment(tokens, cwd, { ...ctx, depth: ctx.depth + 1, computed });
  if (prog === 'cd') {
    const target = t[1];
    if (target && target !== '-' && !/[$`]/.test(target)) return expandPath(target, cwd);
    return cwd;
  }
  if (SHELLS.has(prog)) {
    const i = t.findIndex((a, k) => k > 0 && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
    if (i !== -1 && t[i + 1] !== undefined) scanCommand(t[i + 1], cwd, { ...ctx, depth: ctx.depth + 1 });
    return cwd;
  }
  if (prog === 'eval') {
    scanCommand(t.slice(1).join(' '), cwd, { ...ctx, depth: ctx.depth + 1 });
    return cwd;
  }
  if (prog === 'xargs') {
    let i = 1;
    while (i < t.length && t[i].startsWith('-')) i += XARGS_VALUE_OPTS.has(t[i]) ? 2 : 1;
    nested(t.slice(i), true);
    return cwd;
  }
  if (prog === 'find') {
    const i = t.findIndex((a) => a === '-exec' || a === '-execdir' || a === '-ok' || a === '-okdir');
    if (i !== -1) {
      const rest = t.slice(i + 1);
      const stop = rest.findIndex((a) => a === ';' || a === '+');
      nested(stop === -1 ? rest : rest.slice(0, stop), true);
    }
    return cwd;
  }
  if (RUNNERS.has(prog)) {
    nested(stripRunnerOpts(t.slice(1), { ...ctx, cwd, depth: ctx.depth + 1 }));
    return cwd;
  }
  if (ORCHESTRATORS.has(prog)) {
    if (orchestratorPublishes(prog, t.slice(1))) ctx.out.push({ cwd, dryRun: false, computed: false, manager: prog === 'lerna' || prog === 'changeset' ? `${prog} publish` : prog, orchestrator: true });
    return cwd;
  }
  if (!MANAGERS.has(prog)) return cwd;
  const args = t.slice(1);
  const first = firstPositional(args);
  if (first !== -1 && ORCHESTRATORS.has(args[first])) return nested(args.slice(first));
  if (first !== -1 && RUNNER_SUBCOMMANDS.has(args[first]) && !(prog === 'yarn' && args[first] === 'x')) {
    nested(stripRunnerOpts(args.slice(first + 1), { ...ctx, cwd, depth: ctx.depth + 1 }));
    return cwd;
  }
  const pos = positionals(args);
  const dryRun = args.some((a) => a === '--dry-run' || a === '--dry-run=true');
  const base = { cwd, dryRun, computed: ctx.computed, tag: optionValue(args, '--tag'), access: optionValue(args, '--access'), registry: optionValue(args, '--registry') };
  if (prog === 'yarn' && pos[0] === 'npm' && pos[1] === 'publish') {
    ctx.out.push({ ...base, manager: 'yarn npm', tarballArg: null, unsupported: true });
    return cwd;
  }
  const idx = pos.indexOf('publish');
  if (idx === -1) return cwd;
  if (prog === 'npm' && idx === 1 && pos[0] === 'stage') {
    ctx.out.push({ ...base, manager: 'npm stage', tarballArg: pos[2] ?? null, unsupported: false });
    return cwd;
  }
  if (idx > 0 && NON_PUBLISH_COMMANDS.has(pos[0])) return cwd;
  ctx.out.push({ ...base, manager: prog, tarballArg: pos[idx + 1] ?? null, unsupported: false });
  return cwd;
}

function scanCommand(command, cwd, ctx) {
  for (const seg of tokenize(command)) cwd = scanSegment(seg, cwd, ctx);
}

export function findPublishes(command, startCwd) {
  const out = [];
  scanCommand(command, startCwd, { out, depth: 0, computed: false });
  return out;
}

function evaluatePublish(p) {
  const cmd = `${p.manager} publish`;
  if (p.dryRun) return null;
  if (p.orchestrator) return `\`${p.manager}\` packs and publishes on its own, so shipsafe never sees what ships. Pack each package (\`npm pack --workspaces --pack-destination out\`), gate them with \`shipsafe check out/*.tgz\`, then publish each checked file with \`npm publish out/<file>.tgz\`. Dry runs (\`--dry-run\`) pass.`;
  if (p.computed) return `\`${cmd}\` gets its tarball from xargs or find, so shipsafe cannot see which file ships. Name the checked .tgz literally: \`${cmd} <file>.tgz\`.`;
  if (p.unsupported) return `\`${cmd}\` cannot publish a prebuilt tarball. Pack, run \`shipsafe check <file>.tgz\`, then publish that file with \`npm publish <file>.tgz\`.`;
  if (!p.tarballArg) return `\`${cmd}\` without a tarball publishes the working tree, which nothing has checked. Build, pack (\`npm pack\`), run \`shipsafe check <file>.tgz\`, then \`${cmd} <file>.tgz\`.`;
  if (!/\.(tgz|tar\.gz)$/i.test(p.tarballArg)) return `\`${cmd} ${p.tarballArg}\` does not name a .tgz tarball. Publish only a packed tarball that passed \`shipsafe check\`.`;
  const t = resolveTarball(p.tarballArg, p.cwd);
  if (t.error) return t.error;
  if (!existsSync(t.path) || !statSync(t.path).isFile()) return `tarball not found: ${t.path}`;
  let r;
  try {
    r = checkTarball(t.path);
  } catch (e) {
    return `shipsafe could not check ${t.path}: ${e.message}`;
  }
  if (!r.pass) return `shipsafe check failed for ${t.path}:\n${formatReport(r)}`;
  return intentProblem(p, r.manifest, t.path);
}

function intentProblem(p, m, file) {
  const cmd = `${p.manager} publish ${file}`;
  const pc = m.publishConfig;
  if (typeof m.name === 'string' && m.name.startsWith('@') && !p.access && !pc.access) {
    return `${m.name} is scoped and neither --access nor publishConfig.access says who may see it. State it: \`${cmd} --access public\` (or --access restricted).`;
  }
  const norm = (u) => String(u).replace(/\/+$/, '');
  if (p.registry && pc.registry && norm(p.registry) !== norm(pc.registry)) {
    return `--registry ${p.registry} contradicts publishConfig.registry ${pc.registry} in the packed package.json. Drop one so the target is unambiguous.`;
  }
  const tag = p.tag ?? pc.tag ?? 'latest';
  if (isPrerelease(m.version) && tag === 'latest') {
    return `${m.name}@${m.version} is a prerelease and would become the latest dist-tag for every installer. Publish it with \`${cmd} --tag next\`.`;
  }
  return null;
}

function runHook() {
  let input;
  try {
    input = JSON.parse(readFileSync(0, 'utf8'));
  } catch {
    return 0;
  }
  if (input?.tool_name !== 'Bash' || typeof input?.tool_input?.command !== 'string') return 0;
  const command = input.tool_input.command;
  let reasons;
  try {
    reasons = findPublishes(command, input.cwd || process.cwd()).map(evaluatePublish).filter(Boolean);
  } catch (e) {
    if (!/\bpublish\b/.test(command)) return 0;
    reasons = [`shipsafe could not parse this publish command (${e.message}); run the publish as a plain \`npm publish <file>.tgz\``];
  }
  if (!reasons.length) return 0;
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: `shipsafe blocked this publish.\n${reasons.join('\n')}`,
    },
  }));
  return 0;
}

const USAGE = `shipsafe ${VERSION}

Usage:
  shipsafe check <file.tgz>... [--json] scan packed npm tarballs; exit 1 on any finding, 2 on any error
  shipsafe hook                        Claude Code PreToolUse hook (reads JSON on stdin)
  shipsafe --version

Rules: ${Object.keys(RULES).join(', ')}
Config: "shipsafe": { "maxFileBytes": <n>, "allow": [{ "rule", "path", "reason" }] } in the packed package.json`;

function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === '--version' || cmd === '-v') { console.log(VERSION); return 0; }
  if (cmd === 'hook') return runHook();
  if (cmd === 'check') {
    const json = rest.includes('--json');
    const files = rest.filter((a) => a !== '--json');
    if (!files.length || files.some((f) => f.startsWith('-'))) { console.error(USAGE); return 2; }
    const reports = [];
    let code = 0;
    for (const [i, file] of files.entries()) {
      if (!json && i > 0) console.log('');
      try {
        const r = checkTarball(file);
        reports.push(r);
        if (!json) console.log(formatReport(r));
        if (!r.pass) code = Math.max(code, 1);
      } catch (e) {
        if (!(e instanceof GuardError) && e.code !== 'ENOENT' && e.code !== 'EISDIR') throw e;
        console.error(`shipsafe: ${files.length > 1 ? `${file}: ` : ''}${e.message}`);
        reports.push({ version: VERSION, file: resolve(file), pass: false, error: e.message });
        code = 2;
      }
    }
    if (json) {
      const out = files.length === 1 ? reports[0] : reports;
      if (!out.error) console.log(JSON.stringify(out, null, 2));
    } else if (files.length > 1) {
      console.log(`\n${reports.filter((r) => r.pass).length}/${files.length} tarball(s) passed`);
    }
    return code;
  }
  console.error(USAGE);
  return cmd === undefined || cmd === '--help' || cmd === '-h' ? 0 : 2;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exitCode = main(process.argv.slice(2));
}
