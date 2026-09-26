#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const VERSION = '0.1.0';
const DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024;
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
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    if (!headerChecksumOk(h)) throw new GuardError(`not a valid tar archive (bad header checksum at byte ${off})`);
    const type = h[156] === 0 ? '0' : String.fromCharCode(h[156]);
    const size = pax.size ? Number(pax.size) : parseNumeric(h, 124, 12);
    const name = cstr(h, 0, 100);
    const prefix = cstr(h, 257, 6).startsWith('ustar') ? cstr(h, 345, 155) : '';
    off += 512;
    const data = buf.subarray(off, off + size);
    off += Math.ceil(size / 512) * 512;
    if (type === 'x') { pax = parsePax(data); continue; }
    if (type === 'g') continue;
    if (type === 'L') { longName = cstr(data, 0, data.length); continue; }
    const path = pax.path ?? longName ?? (prefix ? `${prefix}/${name}` : name);
    pax = {};
    longName = null;
    entries.push({ path, type, size, data });
  }
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
  const pkg = files.find((f) => f.path === 'package.json');
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
  return { name: json.name, version: json.version, maxFileBytes, allow };
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
    tar = raw[0] === 0x1f && raw[1] === 0x8b ? gunzipSync(raw) : raw;
  } catch (e) {
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
  for (const e of entries) {
    if (e.type === '1' || e.type === '2') warnings.push(`link entry ${stripRoot(e.path)} was not scanned`);
  }
  let unpackedBytes = 0;
  for (const f of files) {
    unpackedBytes += f.size;
    const hits = [...scanPath(f.path), ...scanContent(f.data)];
    if (f.size > config.maxFileBytes) hits.push(['file-size', `${f.size} bytes > ${config.maxFileBytes}`]);
    for (const [rule, detail] of hits) {
      const allow = config.allow.find((a) => a.rule === rule && a.re.test(f.path));
      if (allow) allow.used = true;
      findings.push({ rule, path: f.path, detail, allowed: !!allow, reason: allow?.reason });
    }
  }
  for (const a of config.allow) if (!a.used) warnings.push(`unused allow entry: ${a.rule} ${a.path}`);
  return {
    version: VERSION,
    file: resolve(file),
    package: `${config.name}@${config.version}`,
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

export function findPublishes(command, startCwd) {
  const out = [];
  let cwd = startCwd;
  for (const seg of tokenize(command)) {
    const t = unwrap(seg);
    if (!t.length) continue;
    const prog = basename(t[0]);
    if (prog === 'cd') {
      const target = t[1];
      if (target && target !== '-' && !/[$`]/.test(target)) cwd = expandPath(target, cwd);
      continue;
    }
    if (!MANAGERS.has(prog)) continue;
    const args = t.slice(1);
    const pos = positionals(args);
    const dryRun = args.some((a) => a === '--dry-run' || a === '--dry-run=true');
    if (prog === 'yarn' && pos[0] === 'npm' && pos[1] === 'publish') {
      out.push({ manager: 'yarn npm', cwd, dryRun, tarballArg: null, unsupported: true });
      continue;
    }
    const idx = pos.indexOf('publish');
    if (idx === -1) continue;
    if (idx > 0 && NON_PUBLISH_COMMANDS.has(pos[0])) continue;
    const target = pos[idx + 1] ?? null;
    out.push({ manager: prog, cwd, dryRun, tarballArg: target, unsupported: false });
  }
  return out;
}

function evaluatePublish(p) {
  const cmd = `${p.manager} publish`;
  if (p.dryRun) return null;
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
  if (r.pass) return null;
  return `shipsafe check failed for ${t.path}:\n${formatReport(r)}`;
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
  shipsafe check <file.tgz> [--json]   scan a packed npm tarball; exit 1 on any finding
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
    if (files.length !== 1) { console.error(USAGE); return 2; }
    try {
      const r = checkTarball(files[0]);
      console.log(json ? JSON.stringify(r, null, 2) : formatReport(r));
      return r.pass ? 0 : 1;
    } catch (e) {
      if (!(e instanceof GuardError) && e.code !== 'ENOENT' && e.code !== 'EISDIR') throw e;
      console.error(`shipsafe: ${e.message}`);
      return 2;
    }
  }
  console.error(USAGE);
  return cmd === undefined || cmd === '--help' || cmd === '-h' ? 0 : 2;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exitCode = main(process.argv.slice(2));
}
