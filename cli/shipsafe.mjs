#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync, inflateRawSync } from 'node:zlib';

const VERSION = '0.1.0';
const DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024;
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall'];
const CONFIG_KEYS = ['maxFileBytes', 'growthFactor', 'allow'];
const DEFAULT_GROWTH_FACTOR = 2;
const NESTED_ARCHIVE = /\.(asar|zip|tgz|tar|tar\.gz|gz|jar|war|vsix|whl|7z|rar|xz|bz2|zst)$/i;
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
  'build-artifact': 'build metadata that lists source paths (tsbuildinfo, coverage, esbuild metafile)',
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
  return parseConfig(json);
}

function parseConfig(json) {
  const raw = json.shipsafe ?? {};
  const configWarnings = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new GuardError('shipsafe config in package.json must be an object');
  for (const k of Object.keys(raw)) if (!CONFIG_KEYS.includes(k)) configWarnings.push(`unknown config key shipsafe.${k} is ignored (known: ${CONFIG_KEYS.join(', ')})`);
  const maxFileBytes = raw.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  if (!Number.isFinite(maxFileBytes) || maxFileBytes <= 0) throw new GuardError('shipsafe.maxFileBytes must be a positive number');
  const growthFactor = raw.growthFactor ?? DEFAULT_GROWTH_FACTOR;
  if (!Number.isFinite(growthFactor) || growthFactor <= 1) throw new GuardError('shipsafe.growthFactor must be a number above 1');
  const allow = (raw.allow ?? []).map((a, i) => {
    if (!a || !RULES[a.rule]) throw new GuardError(`shipsafe.allow[${i}].rule must be one of: ${Object.keys(RULES).join(', ')}`);
    if (typeof a.path !== 'string' || !a.path) throw new GuardError(`shipsafe.allow[${i}].path is required`);
    if (typeof a.reason !== 'string' || a.reason.trim().length < 10) throw new GuardError(`shipsafe.allow[${i}].reason must explain the exception (10+ chars)`);
    for (const k of Object.keys(a)) if (!['rule', 'path', 'reason'].includes(k)) configWarnings.push(`unknown key shipsafe.allow[${i}].${k} is ignored`);
    return { ...a, re: globToRegex(a.path), used: false };
  });
  const scripts = json.scripts && typeof json.scripts === 'object' ? json.scripts : {};
  const publishConfig = json.publishConfig && typeof json.publishConfig === 'object' ? json.publishConfig : {};
  return { name: json.name, version: json.version, private: json.private === true, publishConfig, maxFileBytes, growthFactor, allow, scripts, pkg: json, warnings: configWarnings };
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

const DIR_RULES = new Set(['source-map', 'sources-content', 'inline-source-map', 'remote-source-map', 'sensitive-file', 'secret-token', 'bucket-url', 'build-artifact', 'archive-integrity']);
const SKIP_DIRS = new Set(['node_modules']);

function nearestPackageJson(dir) {
  for (let d = dir; ; d = dirname(d)) {
    const p = join(d, 'package.json');
    if (existsSync(p)) return p;
    if (dirname(d) === d) return null;
  }
}

export function checkDirectory(dir) {
  const root = resolve(dir);
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new GuardError(`not a directory: ${root}`);
  const pkgPath = nearestPackageJson(root);
  let json = {};
  if (pkgPath) {
    try {
      json = JSON.parse(readFileSync(pkgPath, 'utf8'));
    } catch (e) {
      throw new GuardError(`${pkgPath} is not valid JSON: ${e.message}`);
    }
  }
  const config = parseConfig(json);
  const findings = [];
  const warnings = [...config.warnings];
  const record = (path, hits) => {
    for (const [rule, detail] of hits) {
      if (!DIR_RULES.has(rule)) continue;
      const allow = config.allow.find((a) => a.rule === rule && a.re.test(path));
      if (allow) allow.used = true;
      findings.push({ rule, path, detail, allowed: !!allow, reason: allow?.reason });
    }
  };
  let count = 0;
  let bytes = 0;
  const walk = (abs) => {
    for (const name of readdirSync(abs).sort()) {
      const full = join(abs, name);
      const rel = relative(root, full).split('\\').join('/');
      const st = lstatSync(full);
      if (st.isSymbolicLink()) { record(rel, [['archive-integrity', 'symlink; the deploy may upload what it points at, which was not scanned']]); continue; }
      if (st.isDirectory()) { if (!SKIP_DIRS.has(name)) walk(full); continue; }
      if (!st.isFile()) continue;
      count++;
      bytes += st.size;
      if (bytes > MAX_UNPACKED_BYTES) throw new GuardError(`${root} holds more than ${MAX_UNPACKED_BYTES} bytes; refusing to scan it`);
      const data = readFileSync(full);
      const hits = [...scanPath(rel), ...scanContent(data)];
      if (isMetafile(rel, data)) hits.push(['build-artifact', 'esbuild metafile']);
      record(rel, hits);
    }
  };
  walk(root);
  for (const a of config.allow) if (!a.used) warnings.push(`unused allow entry: ${a.rule} ${a.path}`);
  return { version: VERSION, kind: 'directory', file: root, package: pkgPath ? `config ${pkgPath}` : 'no package.json config', files: count, unpackedBytes: bytes, pass: findings.every((f) => f.allowed), findings, warnings };
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
  if ((/^\.env(\..+)?$/.test(base) && !/^\.env\.(example|sample|template)$/.test(base)) || ['.npmrc', '.git-credentials', '.netrc', '_netrc', '.pypirc'].includes(base) || (dirs.includes('.aws') && ['credentials', 'config'].includes(base)) || /\.(jks|keystore)$/i.test(base) || /\.(pem|key|p12|pfx)$/i.test(base) || /^id_(rsa|ed25519|ecdsa)/.test(base) || dirs.includes('.git')) found.push(['sensitive-file', '']);
  if (/\.tsbuildinfo$/i.test(base) || dirs.includes('coverage') || dirs.includes('.nyc_output')) found.push(['build-artifact', '']);
  return found;
}

function isMetafile(path, data) {
  if (!/(^|[.-])meta(file)?\.json$/i.test(path.split('/').pop())) return false;
  const text = data.toString('utf8', 0, Math.min(data.length, 4096));
  return /"inputs"\s*:/.test(text) && /"outputs"\s*:/.test(data.toString('utf8'));
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

function checkEntryPath(path) {
  if (path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.split(/[\\/]/).includes('..')) {
    throw new GuardError(`the archive has an entry that escapes its root: ${path}`);
  }
}

function readZip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd === -1) throw new GuardError('not a valid zip archive (no end of central directory)');
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) throw new GuardError('zip64 archives are not supported');
  if (buf.readUInt16LE(eocd + 4) !== 0 || buf.readUInt16LE(eocd + 6) !== 0) throw new GuardError('multi-disk zip archives are not supported');
  if (cdOffset + cdSize > eocd) throw new GuardError('the zip archive is truncated (central directory out of range)');
  const entries = [];
  let off = cdOffset;
  let total = 0;
  for (let n = 0; n < count; n++) {
    if (off + 46 > buf.length || buf.readUInt32LE(off) !== 0x02014b50) throw new GuardError(`malformed zip central directory at byte ${off}`);
    const flags = buf.readUInt16LE(off + 8);
    const method = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const size = buf.readUInt32LE(off + 24);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const mode = buf.readUInt32LE(off + 38) >>> 16;
    const local = buf.readUInt32LE(off + 42);
    const path = buf.subarray(off + 46, off + 46 + nameLen).toString('utf8');
    off += 46 + nameLen + extraLen + commentLen;
    checkEntryPath(path);
    if (flags & 1) throw new GuardError(`encrypted zip entry ${path} cannot be scanned`);
    if (path.endsWith('/')) { entries.push({ path, type: '5', size: 0, data: Buffer.alloc(0), linkname: '' }); continue; }
    if (local + 30 > buf.length || buf.readUInt32LE(local) !== 0x04034b50) throw new GuardError(`malformed zip local header for ${path}`);
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    if (start + compSize > buf.length) throw new GuardError(`the zip archive is truncated (${path})`);
    total += size;
    if (total > MAX_UNPACKED_BYTES) throw new GuardError(`the zip archive unpacks to more than ${MAX_UNPACKED_BYTES} bytes; refusing to scan it`);
    const comp = buf.subarray(start, start + compSize);
    let data;
    if (method === 0) data = comp;
    else if (method === 8) {
      try {
        data = inflateRawSync(comp, { maxOutputLength: Math.max(size, 1) });
      } catch (e) {
        throw new GuardError(`cannot inflate zip entry ${path}: ${e.message}`);
      }
    } else throw new GuardError(`zip entry ${path} uses unsupported compression method ${method}`);
    if (data.length !== size) throw new GuardError(`zip entry ${path} inflates to ${data.length} bytes, header says ${size}`);
    const link = (mode & 0o170000) === 0o120000;
    entries.push({ path, type: link ? '2' : '0', size, data: link ? Buffer.alloc(0) : data, linkname: link ? data.toString('utf8') : '' });
  }
  return entries;
}

function isAsar(buf) {
  return buf.length >= 16 && buf.readUInt32LE(0) === 4 && buf.subarray(16, 26).toString('latin1') === '{"files":{';
}

function readAsar(buf, label = 'app.asar') {
  const headerSize = buf.readUInt32LE(4);
  const jsonLen = buf.readUInt32LE(12);
  if (16 + jsonLen > buf.length || 8 + headerSize > buf.length) throw new GuardError(`${label} is truncated (header out of range)`);
  let index;
  try {
    index = JSON.parse(buf.subarray(16, 16 + jsonLen).toString('utf8'));
  } catch (e) {
    throw new GuardError(`${label} has an unreadable index: ${e.message}`);
  }
  const base = 8 + headerSize;
  const entries = [];
  const unpacked = [];
  let total = 0;
  const walk = (node, prefix, depth) => {
    if (depth > 64) throw new GuardError(`${label} nests directories too deeply`);
    for (const [name, meta] of Object.entries(node.files ?? {})) {
      const path = prefix ? `${prefix}/${name}` : name;
      checkEntryPath(path);
      if (name.includes('/') || name.includes('\\')) throw new GuardError(`${label} has an entry name with a path separator: ${path}`);
      if (meta.files) { entries.push({ path, rel: path, type: '5', size: 0, data: Buffer.alloc(0), linkname: '' }); walk(meta, path, depth + 1); continue; }
      if (typeof meta.link === 'string') { entries.push({ path, rel: path, type: '2', size: 0, data: Buffer.alloc(0), linkname: meta.link }); continue; }
      if (meta.unpacked) { unpacked.push(path); continue; }
      const size = Number(meta.size);
      const offset = Number(meta.offset);
      if (!Number.isSafeInteger(size) || !Number.isSafeInteger(offset) || size < 0 || offset < 0) throw new GuardError(`${label} has a malformed entry: ${path}`);
      if (base + offset + size > buf.length) throw new GuardError(`${label} is truncated (${path})`);
      total += size;
      if (total > MAX_UNPACKED_BYTES) throw new GuardError(`${label} holds more than ${MAX_UNPACKED_BYTES} bytes; refusing to scan it`);
      entries.push({ path, rel: path, type: '0', size, data: buf.subarray(base + offset, base + offset + size), linkname: '' });
    }
  };
  walk(index, '', 0);
  return { entries, unpacked };
}

function expandNestedAsar(entries, warnings) {
  const out = [];
  for (const e of entries) {
    out.push(e);
    if (e.type !== '0' || !/\.asar$/i.test(e.rel) || !isAsar(e.data)) continue;
    const inner = readAsar(e.data, e.rel);
    for (const x of inner.entries) out.push({ ...x, path: `${e.rel}/${x.path}`, rel: `${e.rel}/${x.rel}` });
    for (const u of inner.unpacked) warnings.push(`${e.rel}: ${u} is unpacked (app.asar.unpacked) and scanned only if it ships beside the archive`);
  }
  return out;
}

function openTarball(file) {
  const raw = Buffer.isBuffer(file) ? file : readFileSync(file);
  if (isAsar(raw)) {
    const { entries, unpacked } = readAsar(raw, Buffer.isBuffer(file) ? 'app.asar' : basename(file));
    const files = entries.filter((e) => e.type === '0').map((e) => ({ path: e.rel, size: e.size, data: e.data }));
    return { raw, entries, files, kind: 'asar', format: 'asar', notes: unpacked.map((u) => `${u} is unpacked (app.asar.unpacked) and not inside this archive; check that directory with check-dir`) };
  }
  if (raw.length >= 4 && raw.readUInt32LE(0) === 0x04034b50 || raw.length >= 22 && raw.readUInt32LE(raw.length - 22) === 0x06054b50) {
    const all = readZip(raw);
    if (!all.length) throw new GuardError('the zip archive is empty');
    const names = new Set(all.map((e) => e.path));
    const vsix = names.has('extension/package.json') && (names.has('extension.vsixmanifest') || names.has('[Content_Types].xml'));
    const notes = [];
    const entries = expandNestedAsar(vsix
      ? all.filter((e) => e.path.startsWith('extension/')).map((e) => ({ ...e, rel: e.path.slice(10) })).filter((e) => e.rel)
      : all.map((e) => ({ ...e, rel: e.path.replace(/\/$/, '') })), notes);
    const files = entries.filter((e) => e.type === '0').map((e) => ({ path: e.rel, size: e.size, data: e.data }));
    const kind = vsix ? 'vsix' : names.has('manifest.json') ? 'webext' : 'generic';
    return { raw, entries, files, kind, format: 'zip', notes };
  }
  let tar;
  try {
    tar = raw[0] === 0x1f && raw[1] === 0x8b ? gunzipSync(raw, { maxOutputLength: MAX_UNPACKED_BYTES }) : raw;
  } catch (e) {
    if (e.code === 'ERR_BUFFER_TOO_LARGE' || e instanceof RangeError) throw new GuardError(`${file} unpacks to more than ${MAX_UNPACKED_BYTES} bytes; refusing to scan it`);
    throw new GuardError(`cannot gunzip ${file}: ${e.message}`);
  }
  const entries = readTar(tar).map((e) => ({ ...e, rel: stripRoot(e.path) }));
  if (!entries.length) throw new GuardError('the tarball is empty');
  const files = entries
    .filter((e) => e.type === '0' || e.type === '7')
    .map((e) => ({ path: e.rel, size: e.size, data: e.data }));
  return { raw, entries, files, kind: files.some((f) => f.path === 'package.json') ? 'npm' : 'generic', format: 'tar' };
}

const KIND_RULES = {
  vsix: new Set(Object.keys(RULES).filter((r) => r !== 'lifecycle-script' && r !== 'publish-intent')),
  webext: new Set([...DIR_RULES, 'typescript-source', 'source-dir', 'test-path', 'file-size']),
  asar: new Set([...DIR_RULES, 'typescript-source', 'test-path']),
  generic: DIR_RULES,
};
const BROAD_HOSTS = new Set(['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*', '*://*/', 'http://*/', 'https://*/']);

function webextWarnings(files) {
  const f = files.findLast((x) => x.path === 'manifest.json');
  let m;
  try {
    m = JSON.parse(f.data.toString('utf8'));
  } catch {
    return [{ name: undefined, version: undefined }, ['manifest.json is not valid JSON']];
  }
  const hosts = [...(m.host_permissions ?? []), ...(m.permissions ?? []), ...(m.optional_host_permissions ?? []), ...(m.content_scripts ?? []).flatMap((c) => c?.matches ?? [])];
  const broad = [...new Set(hosts.filter((h) => typeof h === 'string' && BROAD_HOSTS.has(h)))];
  return [m, broad.length ? [`manifest.json requests broad host access (${broad.join(', ')}); stores review this closely, narrow it if you can`] : []];
}

export function checkTarball(file, label, { asset = false } = {}) {
  const { raw, entries, files, kind, format, notes = [] } = openTarball(file);
  const sha256 = createHash('sha256').update(raw).digest('hex');
  if (kind === 'generic' && format === 'tar' && !asset) loadConfig(files);
  const allowed = KIND_RULES[kind];
  const config = kind === 'npm' || kind === 'vsix' ? loadConfig(files) : parseConfig({});
  const [webext, extWarnings] = kind === 'webext' ? webextWarnings(files) : [null, []];
  const findings = [];
  const warnings = [...config.warnings, ...extWarnings, ...notes];
  const integrity = new Map();
  const note = (path, detail) => { if (!integrity.has(path)) integrity.set(path, detail); };
  for (const e of entries) {
    const path = e.rel;
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
      if (allowed && !allowed.has(rule)) continue;
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
    if (NESTED_ARCHIVE.test(f.path) && !(/\.asar$/i.test(f.path) && isAsar(f.data))) warnings.push(`nested archive ${f.path} was not scanned inside`);
    if (isMetafile(f.path, f.data)) hits.push(['build-artifact', 'esbuild metafile']);
    if (f.size > config.maxFileBytes) hits.push(['file-size', `${f.size} bytes > ${config.maxFileBytes}`]);
    record(f.path, hits);
  }
  for (const a of config.allow) if (!a.used) warnings.push(`unused allow entry: ${a.rule} ${a.path}`);
  const report = {
    version: VERSION,
    file: label ?? resolve(file),
    kind,
    package: kind === 'asar' ? 'Electron asar archive' : kind === 'webext' ? `${webext.name}@${webext.version} (browser extension)` : kind === 'generic' ? 'archive without a package manifest' : `${config.name}@${config.version}${kind === 'vsix' ? ' (vsix)' : ''}`,
    manifest: { name: config.name, version: config.version, private: config.private, publishConfig: config.publishConfig },
    sha256,
    files: files.length,
    unpackedBytes,
    pass: findings.every((f) => f.allowed),
    findings,
    warnings,
  };
  Object.defineProperty(report, 'inventory', { value: files.map((f) => ({ path: f.path, size: f.size })), enumerable: false });
  return report;
}

const FORMATS = ['text', 'json', 'sarif', 'markdown'];
const REPO_URL = 'https://github.com/cyberinecore/cc-release-guard';

const mdCell = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

function toSarif(reports) {
  const results = [];
  const used = new Set();
  for (const r of reports) {
    if (r.error) {
      used.add('tarball-error');
      results.push({ ruleId: 'tarball-error', level: 'error', message: { text: `${r.file}: ${r.error}` }, locations: [{ physicalLocation: { artifactLocation: { uri: basename(r.file) } } }] });
      continue;
    }
    for (const f of r.findings) {
      used.add(f.rule);
      const uri = f.path.split('#')[0];
      const text = `${f.rule} in ${r.package}: ${f.path}${f.detail ? ` (${f.detail})` : ''}. ${RULES[f.rule]}.`;
      const result = {
        ruleId: f.rule,
        level: 'error',
        message: { text },
        locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } } }],
        partialFingerprints: { shipsafeFinding: createHash('sha256').update(`${r.package.replace(/@[^@]*$/, '')}|${f.rule}|${f.path}`).digest('hex').slice(0, 32) },
        properties: { tarball: r.file, package: r.package, sha256: r.sha256 },
      };
      if (f.allowed) result.suppressions = [{ kind: 'external', justification: f.reason }];
      results.push(result);
    }
  }
  const descriptions = { ...RULES, 'tarball-error': 'the tarball could not be read or its config is invalid' };
  const rules = [...used].sort().map((id) => ({ id, name: id, shortDescription: { text: descriptions[id] }, defaultConfiguration: { level: 'error' }, helpUri: `${REPO_URL}#rules` }));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'shipsafe', version: VERSION, informationUri: REPO_URL, rules } }, results }],
  };
}

function checkMarkdown(r) {
  if (r.error) return `### shipsafe: ERROR \`${basename(r.file)}\`\n\n${mdCell(r.error)}`;
  const lines = [
    `### shipsafe: ${r.pass ? 'PASS' : 'FAIL'} \`${r.package}\``,
    '',
    r.kind === 'directory' ? `\`${r.file}\` · ${r.files} files · ${r.unpackedBytes} bytes` : `\`${basename(r.file)}\` · sha256 \`${r.sha256}\` · ${r.files} files · ${r.unpackedBytes} bytes unpacked`,
  ];
  if (r.findings.length) {
    lines.push('', '| result | rule | path | detail |', '|---|---|---|---|');
    for (const f of r.findings) lines.push(`| ${f.allowed ? 'allowed' : '**FAIL**'} | \`${f.rule}\` | \`${mdCell(f.path)}\` | ${mdCell(f.allowed ? `${f.detail ? `${f.detail}; ` : ''}exception: ${f.reason}` : f.detail)} |`);
  }
  if (r.warnings.length) lines.push('', ...r.warnings.map((w) => `- warning: ${mdCell(w)}`));
  if (r.inventory) {
    lines.push('', `<details><summary>File inventory (${r.inventory.length})</summary>`, '', '| path | bytes |', '|---|---|');
    for (const f of r.inventory) lines.push(`| \`${mdCell(f.path)}\` | ${f.size} |`);
    lines.push('', '</details>');
  }
  return lines.join('\n');
}

function diffMarkdown(d) {
  const lines = [`### shipsafe diff: \`${d.new}\` vs \`${d.old ?? 'nothing'}\``, ''];
  if (!d.old) return [...lines, `No baseline: nothing published to compare against (${mdCell(d.source)}).`].join('\n');
  lines.push(`${d.added.length} added · ${d.removed.length} removed · ${d.grown.length} grown · ${d.risks.length} risk label(s)`);
  if (d.risks.length) {
    lines.push('', '| risk | detail |', '|---|---|');
    for (const r of d.risks) lines.push(`| \`${r.label}\` | ${mdCell(r.detail)} |`);
  }
  const changes = [...d.added.map((f) => ['added', f.path, `${f.size}`]), ...d.removed.map((f) => ['removed', f.path, `${f.size}`]), ...d.grown.map((f) => ['grown', f.path, `${f.from} -> ${f.to}`])];
  if (changes.length) {
    lines.push('', `<details><summary>File changes (${changes.length})</summary>`, '', '| change | path | bytes |', '|---|---|---|');
    for (const [c, p, b] of changes) lines.push(`| ${c} | \`${mdCell(p)}\` | ${b} |`);
    lines.push('', '</details>');
  }
  return lines.join('\n');
}

const DEFAULT_REGISTRY = 'https://registry.npmjs.org';

async function fetchPackument(registry, name, full = false) {
  const url = `${registry}/${name.replace('/', '%2f')}`;
  const accept = full ? 'application/json' : 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8';
  let res;
  try {
    res = await fetch(url, { headers: { accept }, signal: AbortSignal.timeout(30000) });
  } catch (e) {
    throw new GuardError(`cannot reach ${registry}: ${e.cause?.code ?? e.message}`);
  }
  if (res.status === 404) return null;
  if (!res.ok) throw new GuardError(`${registry} answered HTTP ${res.status} for ${name}`);
  try {
    return await res.json();
  } catch {
    throw new GuardError(`${registry} returned a packument that is not JSON`);
  }
}

export async function verifyTarball(file, registryFlag) {
  const { raw, files } = openTarball(file);
  const config = loadConfig(files);
  const { name, version } = config;
  if (typeof name !== 'string' || typeof version !== 'string') throw new GuardError('package.json needs a name and a version');
  const integrity = `sha512-${createHash('sha512').update(raw).digest('base64')}`;
  const registry = String(registryFlag ?? config.publishConfig.registry ?? DEFAULT_REGISTRY).replace(/\/+$/, '');
  const base = { version: VERSION, file: resolve(file), package: `${name}@${version}`, registry, integrity };
  const doc = await fetchPackument(registry, name);
  if (!doc) return { ...base, published: null, match: false, reason: `${name} is not on ${registry}` };
  const published = doc?.versions?.[version]?.dist?.integrity ?? null;
  if (!published) return { ...base, published: null, match: false, reason: `${name}@${version} is not published on ${registry}` };
  const match = published === integrity;
  return { ...base, published, match, reason: match ? 'the registry holds exactly this file' : 'the registry holds a different file for this version' };
}

function splitSpec(spec, fallbackName) {
  const at = spec.lastIndexOf('@');
  if (at > 0) return [spec.slice(0, at), spec.slice(at + 1)];
  if (at === 0) return [spec, 'latest'];
  return [fallbackName, spec];
}

function packageFacts(opened) {
  const config = loadConfig(opened.files);
  const pkg = config.pkg;
  const bin = typeof pkg.bin === 'string' ? { [String(pkg.name).split('/').pop()]: pkg.bin } : pkg.bin && typeof pkg.bin === 'object' ? pkg.bin : {};
  const deps = {};
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [k, v] of Object.entries(pkg[field] ?? {})) deps[k] = `${v}${field === 'dependencies' ? '' : ` (${field})`}`;
  }
  const exp = pkg.exports;
  const exportKeys = exp === undefined ? [] : typeof exp === 'object' && exp !== null && !Array.isArray(exp) && Object.keys(exp).some((k) => k.startsWith('.')) ? Object.keys(exp) : ['.'];
  const scripts = Object.fromEntries(INSTALL_SCRIPTS.filter((n) => typeof config.scripts[n] === 'string').map((n) => [n, config.scripts[n]]));
  const allow = config.allow.map((a) => `${a.rule} ${a.path}`);
  const files = new Map(opened.files.map((f) => [f.path, f.size]));
  return { config, package: `${config.name}@${config.version}`, bin, deps, exportKeys, scripts, allow, files };
}

export function diffPackages(next, prev) {
  const n = packageFacts(next);
  const out = { version: VERSION, new: n.package, old: null, added: [], removed: [], grown: [], risks: [] };
  if (!prev) return out;
  const o = packageFacts(prev);
  out.old = o.package;
  const byPath = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  for (const [path, size] of n.files) {
    if (!o.files.has(path)) out.added.push({ path, size });
    else if (size > o.files.get(path)) {
      const from = o.files.get(path);
      const ratio = from ? size / from : Infinity;
      out.grown.push({ path, from, to: size });
      if (ratio >= n.config.growthFactor && size - from > 1024) out.risks.push({ label: 'size-jump', detail: `${path} ${from} -> ${size} bytes (x${from ? ratio.toFixed(1) : 'inf'})` });
    }
  }
  for (const [path, size] of o.files) if (!n.files.has(path)) out.removed.push({ path, size });
  for (const [k, v] of Object.entries(n.scripts)) if (o.scripts[k] !== v) out.risks.push({ label: 'new-lifecycle-script', detail: `package.json#${k}: ${v.slice(0, 120)}` });
  for (const [k, v] of Object.entries(n.deps)) if (!(k in o.deps)) out.risks.push({ label: 'new-dependency', detail: `${k}@${v}` });
  for (const [k, v] of Object.entries(n.bin)) if (!(k in o.bin)) out.risks.push({ label: 'new-bin', detail: `${k} -> ${v}` });
  for (const k of n.exportKeys) if (!o.exportKeys.includes(k)) out.risks.push({ label: 'new-export', detail: k });
  for (const a of n.allow) if (!o.allow.includes(a)) out.risks.push({ label: 'new-exception', detail: a });
  out.added.sort(byPath);
  out.removed.sort(byPath);
  out.grown.sort(byPath);
  return out;
}

async function downloadTarball(url, label) {
  let res;
  try {
    res = await fetch(url, { signal: AbortSignal.timeout(120000) });
  } catch (e) {
    throw new GuardError(`cannot download ${label}: ${e.cause?.code ?? e.message}`);
  }
  if (!res.ok) throw new GuardError(`downloading ${label} answered HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

export async function auditPackage(name, count, registryFlag) {
  const registry = String(registryFlag ?? DEFAULT_REGISTRY).replace(/\/+$/, '');
  const doc = await fetchPackument(registry, name, true);
  if (!doc) throw new GuardError(`${name} is not on ${registry}`);
  const time = doc.time ?? {};
  const versions = Object.keys(doc.versions ?? {})
    .map((v, i) => ({ v, i, t: Date.parse(time[v] ?? '') || 0 }))
    .sort((a, b) => b.t - a.t || b.i - a.i)
    .slice(0, count)
    .map((x) => x.v);
  const results = [];
  for (const v of versions) {
    const label = `${name}@${v}`;
    const dist = doc.versions[v]?.dist ?? {};
    try {
      if (!dist.tarball) throw new GuardError('the packument has no dist.tarball');
      const buf = await downloadTarball(dist.tarball, label);
      if (dist.integrity?.startsWith('sha512-') && dist.integrity !== `sha512-${createHash('sha512').update(buf).digest('base64')}`) {
        throw new GuardError('the downloaded tarball does not match dist.integrity');
      }
      const r = checkTarball(buf, label);
      results.push({ version: v, published: time[v] ?? null, pass: r.pass, findings: r.findings.filter((f) => !f.allowed), warnings: r.warnings });
    } catch (e) {
      if (!(e instanceof GuardError)) throw e;
      results.push({ version: v, published: time[v] ?? null, pass: false, error: e.message });
    }
  }
  return { version: VERSION, package: name, registry, scanned: results.length, total: Object.keys(doc.versions ?? {}).length, results };
}

function formatAudit(a) {
  const lines = [`shipsafe ${a.version} audit  ${a.package}  last ${a.scanned} of ${a.total} version(s) on ${a.registry}`];
  for (const r of a.results) {
    const when = r.published ? `  (${r.published.slice(0, 10)})` : '';
    if (r.error) lines.push(`ERROR ${r.version}${when}: ${r.error}`);
    else if (r.pass) lines.push(`PASS  ${r.version}${when}`);
    else lines.push(`FAIL  ${r.version}${when}: ${[...new Set(r.findings.map((f) => f.rule))].join(', ')}`, ...r.findings.slice(0, 20).map((f) => `        ${f.rule.padEnd(18)} ${f.path}${f.detail ? `: ${f.detail}` : ''}`));
  }
  if (a.results.some((r) => !r.pass && !r.error)) lines.push('Leak found: follow /shipsafe:incident. Rotate any exposed credential before anything else.');
  return lines.join('\n');
}

async function loadBaseline(nextOpened, against, oldFile, registryFlag) {
  if (oldFile) return { opened: openTarball(oldFile), source: resolve(oldFile) };
  const config = loadConfig(nextOpened.files);
  const [name, spec] = splitSpec(against ?? 'latest', config.name);
  const registry = String(registryFlag ?? config.publishConfig.registry ?? DEFAULT_REGISTRY).replace(/\/+$/, '');
  const doc = await fetchPackument(registry, name);
  const version = doc?.['dist-tags']?.[spec] ?? (doc?.versions?.[spec] ? spec : null);
  const url = version ? doc.versions[version]?.dist?.tarball : null;
  if (!url) return { opened: null, source: `${name}@${spec} on ${registry}` };
  return { opened: openTarball(await downloadTarball(url, `${name}@${version}`)), source: `${name}@${version} (${spec}) on ${registry}` };
}

function formatDiff(d, source) {
  const lines = [`shipsafe ${d.version} diff  ${d.new} vs ${d.old ?? 'nothing'}  ${source}`];
  if (!d.old) {
    lines.push('no baseline: nothing published to compare against');
    return lines.join('\n');
  }
  for (const r of d.risks) lines.push(`RISK  ${r.label.padEnd(20)} ${r.detail}`);
  for (const f of d.added) lines.push(`ADD   ${f.path}  (${f.size} bytes)`);
  for (const f of d.removed) lines.push(`DEL   ${f.path}`);
  for (const f of d.grown) lines.push(`GROW  ${f.path}  ${f.from} -> ${f.to} bytes`);
  lines.push(`${d.added.length} added, ${d.removed.length} removed, ${d.grown.length} grown, ${d.risks.length} risk label(s)`);
  return lines.join('\n');
}

function formatVerify(r) {
  return [
    `shipsafe ${r.version}  ${r.package}  ${r.file}`,
    `local     ${r.integrity}`,
    `registry  ${r.published ?? '(none)'}  ${r.registry}`,
    `${r.match ? 'MATCH' : 'FAIL '} ${r.reason}`,
  ].join('\n');
}

function formatReport(r) {
  const lines = [`shipsafe ${r.version}  ${r.package}  ${r.file}`, r.kind === 'directory' ? `files ${r.files}  ${r.unpackedBytes} bytes` : `sha256 ${r.sha256}  files ${r.files}  unpacked ${r.unpackedBytes} bytes`];
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
  } else if (r.kind === 'directory') {
    lines.push(`PASS  deploy exactly this directory: ${r.file}`);
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
      while (t.length && (t[0].startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(t[0]))) t = t.slice(['-u', '--unset', '-C', '--chdir', '-P'].includes(t[0]) ? 2 : 1);
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
const DEPLOY_VALUE_OPTS = {
  wrangler: new Set(['--project-name', '--branch', '--commit-hash', '--commit-message', '--env', '-e', '--config', '-c', '--cwd']),
  vercel: new Set(['--cwd', '--scope', '-S', '--token', '-t', '--env', '-e', '--build-env', '-b', '--meta', '-m', '--target', '--archive', '--local-config', '-A', '--team', '-T']),
  netlify: new Set(['--dir', '-d', '--site', '-s', '--auth', '-a', '--message', '-m', '--alias', '--functions', '-f', '--filter', '--context', '--branch', '-b']),
  firebase: new Set(['--only', '--except', '--project', '-P', '--config', '-c', '--message', '-m', '--token']),
};

const VERCEL_OTHER = new Set(['build', 'dev', 'env', 'ls', 'list', 'rm', 'remove', 'domains', 'dns', 'certs', 'logs', 'inspect', 'pull', 'link', 'alias', 'promote', 'rollback', 'redeploy', 'git', 'project', 'projects', 'switch', 'teams', 'whoami', 'login', 'logout', 'help', 'init']);

function deployPositionals(args, valueOpts) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { out.push(...args.slice(i + 1)); break; }
    if (a.startsWith('-')) { if (!a.includes('=') && valueOpts.has(a)) i++; continue; }
    out.push(a);
  }
  return out;
}

function tomlString(file, key) {
  if (!existsSync(file)) return null;
  const m = readFileSync(file, 'utf8').match(new RegExp(`^\\s*${key}\\s*=\\s*["']([^"']+)["']`, 'm'));
  return m ? m[1] : null;
}

function readJsonFile(file) {
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, 'utf8').replace(/^\s*\/\/.*$/gm, ''));
  } catch {
    return null;
  }
}

function findDeploy(prog, args, cwd) {
  const opts = DEPLOY_VALUE_OPTS[prog];
  const pos = deployPositionals(args, opts);
  const at = (base, rel) => resolve(base, rel);
  if (prog === 'wrangler') {
    if (pos[0] !== 'pages' || !['deploy', 'publish'].includes(pos[1])) return null;
    const manager = `wrangler pages ${pos[1]}`;
    const base = optionValue(args, '--cwd') ? at(cwd, optionValue(args, '--cwd')) : cwd;
    if (pos[2]) return { manager, dirs: [at(base, pos[2])] };
    const fromConfig = tomlString(join(base, 'wrangler.toml'), 'pages_build_output_dir')
      ?? readJsonFile(join(base, 'wrangler.json'))?.pages_build_output_dir ?? readJsonFile(join(base, 'wrangler.jsonc'))?.pages_build_output_dir;
    return fromConfig ? { manager, dirs: [at(base, fromConfig)] } : { manager, error: `\`${manager}\` names no output directory and no pages_build_output_dir was found. Name it: \`${manager} dist\`.` };
  }
  if (prog === 'vercel') {
    if (!args.includes('--prebuilt')) return null;
    if (pos.length && VERCEL_OTHER.has(pos[0])) return null;
    const project = pos[0] === 'deploy' ? pos[1] : pos[0];
    const base = at(optionValue(args, '--cwd') ? at(cwd, optionValue(args, '--cwd')) : cwd, project ?? '.');
    return { manager: 'vercel deploy --prebuilt', dirs: [join(base, '.vercel/output/static')] };
  }
  if (prog === 'netlify' || prog === 'ntl') {
    if (pos[0] !== 'deploy') return null;
    const dir = optionValue(args, '--dir') ?? optionValue(args, '-d');
    if (dir) return { manager: 'netlify deploy', dirs: [at(cwd, dir)] };
    const fromConfig = tomlString(join(cwd, 'netlify.toml'), 'publish');
    return fromConfig ? { manager: 'netlify deploy', dirs: [at(cwd, fromConfig)] } : { manager: 'netlify deploy', error: '`netlify deploy` names no directory and netlify.toml has no publish setting. Name it: `netlify deploy --dir dist`.' };
  }
  if (prog === 'firebase') {
    if (pos[0] !== 'deploy') return null;
    const only = optionValue(args, '--only');
    if (only && !only.split(',').some((t) => t.trim().split(':')[0] === 'hosting')) return null;
    const configPath = at(cwd, optionValue(args, '--config') ?? optionValue(args, '-c') ?? 'firebase.json');
    const hosting = readJsonFile(configPath)?.hosting;
    const list = (Array.isArray(hosting) ? hosting : hosting ? [hosting] : []).map((h) => h?.public).filter((x) => typeof x === 'string');
    if (!list.length) return only ? { manager: 'firebase deploy', error: `no hosting.public directory found in ${configPath}; name it there before deploying hosting.` } : null;
    return { manager: 'firebase deploy', dirs: list.map((d) => at(dirname(configPath), d)) };
  }
  return null;
}
const GH_VALUE_OPTS = new Set(['-t', '--title', '-n', '--notes', '-F', '--notes-file', '--target', '--discussion-category', '-R', '--repo', '--notes-start-tag', '--notes-from-tag']);
const SCANNABLE_ASSET = /\.(tgz|tar\.gz|zip|vsix|asar)$/i;

function findReleaseAssets(args, cwd) {
  const pos = deployPositionals(args, GH_VALUE_OPTS);
  if (pos[0] !== 'release' || !['create', 'upload'].includes(pos[1])) return null;
  const assets = [];
  for (const raw of pos.slice(3)) {
    const arg = raw.replace(/#[^/]*$/, '');
    if (/[$`]/.test(arg)) return { error: `release asset "${arg}" uses shell expansion; name each asset literally` };
    const full = expandPath(arg, cwd);
    if (/[*?]/.test(basename(full))) {
      const dir = dirname(full);
      const re = globToRegex(basename(full));
      assets.push(...(existsSync(dir) ? readdirSync(dir).filter((n) => re.test(n)).map((n) => resolve(dir, n)) : []));
    } else {
      assets.push(full);
    }
  }
  return assets.length ? { assets } : null;
}

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
  if (prog === 'gh') {
    const r = findReleaseAssets(t.slice(1), cwd);
    if (r) ctx.out.push({ ...r, manager: 'gh release', cwd, dryRun: false, computed: ctx.computed, release: true });
    return cwd;
  }
  if (prog in DEPLOY_VALUE_OPTS || prog === 'ntl') {
    const d = findDeploy(prog, t.slice(1), cwd);
    if (d) ctx.out.push({ ...d, cwd, dryRun: false, computed: ctx.computed, deploy: true });
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

function evaluateDeploy(p) {
  if (p.error) return p.error;
  for (const dir of p.dirs) {
    if (!existsSync(dir) || !statSync(dir).isDirectory()) return `\`${p.manager}\` output directory not found: ${dir}. Build first, then run \`shipsafe check-dir ${dir}\`.`;
    let r;
    try {
      r = checkDirectory(dir);
    } catch (e) {
      return `shipsafe could not check ${dir}: ${e.message}`;
    }
    if (!r.pass) return `shipsafe check-dir failed for ${dir}:\n${formatReport(r)}`;
  }
  return null;
}

function evaluateRelease(p) {
  if (p.error) return p.error;
  for (const file of p.assets) {
    if (!SCANNABLE_ASSET.test(file)) {
      if (NESTED_ARCHIVE.test(file)) return `release asset ${file} is an archive shipsafe cannot scan yet. Check its contents yourself, or attach a .tgz that passes \`shipsafe check\`.`;
      continue;
    }
    if (!existsSync(file) || !statSync(file).isFile()) return `release asset not found: ${file}`;
    let r;
    try {
      r = checkTarball(file, undefined, { asset: true });
    } catch (e) {
      return `shipsafe could not check ${file}: ${e.message}`;
    }
    if (!r.pass) return `shipsafe check failed for release asset ${file}:\n${formatReport(r)}`;
  }
  return null;
}

function evaluatePublish(p) {
  if (p.release) return evaluateRelease(p);
  if (p.deploy) return evaluateDeploy(p);
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
      permissionDecisionReason: `shipsafe blocked this publish or deploy.\n${reasons.join('\n')}`,
    },
  }));
  return 0;
}

const USAGE = `shipsafe ${VERSION}

Usage:
  shipsafe check <file.tgz>... [--json | --format text|json|sarif|markdown]
                                       scan npm tarballs, .vsix, .asar and extension .zip; exit 1 on any finding, 2 on any error
  shipsafe check-dir <dir>... [--json | --format ...]
                                       scan a static build output (maps, sourcesContent, credentials, secrets, buckets)
  shipsafe verify <file.tgz> [--registry <url>] [--json]
                                       exit 0 only if the registry's dist.integrity for name@version equals this file
  shipsafe diff <new.tgz> [<old.tgz> | --against <name@version|dist-tag>] [--registry <url>] [--json | --format markdown]
                                       list added, removed and grown files and label risk-raising changes (default: against latest)
  shipsafe audit <name> [--versions <n>] [--registry <url>] [--json]
                                       incident tool: download and gate the last n published versions (default 5)
  shipsafe hook                        Claude Code PreToolUse hook (reads JSON on stdin)
  shipsafe --version

Rules: ${Object.keys(RULES).join(', ')}
Config: "shipsafe": { "maxFileBytes": <n>, "allow": [{ "rule", "path", "reason" }] } in the packed package.json`;

async function runVerify(rest) {
  const json = rest.includes('--json');
  const args = rest.filter((a) => a !== '--json');
  let registry;
  const files = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--registry') registry = args[++i];
    else if (args[i].startsWith('--registry=')) registry = args[i].slice(11);
    else files.push(args[i]);
  }
  if (files.length !== 1 || files[0].startsWith('-') || (registry !== undefined && !/^https?:\/\//.test(registry))) { console.error(USAGE); return 2; }
  try {
    const r = await verifyTarball(files[0], registry);
    console.log(json ? JSON.stringify(r, null, 2) : formatVerify(r));
    return r.match ? 0 : 1;
  } catch (e) {
    if (!(e instanceof GuardError) && e.code !== 'ENOENT' && e.code !== 'EISDIR') throw e;
    console.error(`shipsafe: ${e.message}`);
    return 2;
  }
}

async function runDiff(rest) {
  const { format, args } = takeFormat(rest);
  let registry;
  let against;
  const files = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--registry') registry = args[++i];
    else if (a.startsWith('--registry=')) registry = a.slice(11);
    else if (a === '--against') against = args[++i];
    else if (a.startsWith('--against=')) against = a.slice(10);
    else files.push(a);
  }
  const bad = !files.length || files.length > 2 || files.some((f) => !f || f.startsWith('-')) || (files.length === 2 && against !== undefined)
    || (registry !== undefined && !/^https?:\/\//.test(registry)) || against === '';
  if (bad || !format || format === 'sarif') { console.error(USAGE); return 2; }
  try {
    const next = openTarball(files[0]);
    const base = await loadBaseline(next, against, files[1], registry);
    const d = diffPackages(next, base.opened);
    d.source = base.source;
    console.log(format === 'json' ? JSON.stringify(d, null, 2) : format === 'markdown' ? diffMarkdown(d) : formatDiff(d, base.source));
    return 0;
  } catch (e) {
    if (!(e instanceof GuardError) && e.code !== 'ENOENT' && e.code !== 'EISDIR') throw e;
    console.error(`shipsafe: ${e.message}`);
    return 2;
  }
}

function takeFormat(rest) {
  let format = 'text';
  const args = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--json') format = 'json';
    else if (a === '--format') format = rest[++i];
    else if (a.startsWith('--format=')) format = a.slice(9);
    else args.push(a);
  }
  return { format: FORMATS.includes(format) ? format : null, args };
}

function runCheck(rest, dirMode = false) {
  const { format, args: files } = takeFormat(rest);
  if (!format || !files.length || files.some((f) => f.startsWith('-'))) { console.error(USAGE); return 2; }
  const reports = [];
  let code = 0;
  for (const [i, file] of files.entries()) {
    if (format === 'text' && i > 0) console.log('');
    try {
      const r = dirMode ? checkDirectory(file) : checkTarball(file);
      reports.push(r);
      if (format === 'text') console.log(formatReport(r));
      if (!r.pass) code = Math.max(code, 1);
    } catch (e) {
      if (!(e instanceof GuardError) && e.code !== 'ENOENT' && e.code !== 'EISDIR') throw e;
      console.error(`shipsafe: ${files.length > 1 ? `${file}: ` : ''}${e.message}`);
      reports.push({ version: VERSION, file: resolve(file), pass: false, error: e.message });
      code = 2;
    }
  }
  if (format === 'json') {
    const out = files.length === 1 ? reports[0] : reports;
    if (!out.error) console.log(JSON.stringify(out, null, 2));
  } else if (format === 'sarif') {
    console.log(JSON.stringify(toSarif(reports), null, 2));
  } else if (format === 'markdown') {
    console.log(reports.map(checkMarkdown).join('\n\n'));
  } else if (files.length > 1) {
    console.log(`\n${reports.filter((r) => r.pass).length}/${files.length} tarball(s) passed`);
  }
  return code;
}

async function runAudit(rest) {
  const { format, args } = takeFormat(rest);
  let registry;
  let count = 5;
  const names = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--registry') registry = args[++i];
    else if (a.startsWith('--registry=')) registry = a.slice(11);
    else if (a === '--versions') count = Number(args[++i]);
    else if (a.startsWith('--versions=')) count = Number(a.slice(11));
    else names.push(a);
  }
  const bad = names.length !== 1 || names[0].startsWith('-') || !Number.isInteger(count) || count < 1 || (registry !== undefined && !/^https?:\/\//.test(registry));
  if (bad || (format !== 'text' && format !== 'json')) { console.error(USAGE); return 2; }
  try {
    const a = await auditPackage(names[0], count, registry);
    console.log(format === 'json' ? JSON.stringify(a, null, 2) : formatAudit(a));
    if (a.results.some((r) => r.error)) return 2;
    return a.results.every((r) => r.pass) ? 0 : 1;
  } catch (e) {
    if (!(e instanceof GuardError)) throw e;
    console.error(`shipsafe: ${e.message}`);
    return 2;
  }
}

function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === '--version' || cmd === '-v') { console.log(VERSION); return 0; }
  if (cmd === 'hook') return runHook();
  if (cmd === 'verify') return runVerify(rest);
  if (cmd === 'diff') return runDiff(rest);
  if (cmd === 'audit') return runAudit(rest);
  if (cmd === 'check') return runCheck(rest);
  if (cmd === 'check-dir') return runCheck(rest, true);
  console.error(USAGE);
  return cmd === undefined || cmd === '--help' || cmd === '-h' ? 0 : 2;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  Promise.resolve(main(process.argv.slice(2))).then((code) => { process.exitCode = code; });
}
