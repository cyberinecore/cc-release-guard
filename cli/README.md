# shipsafe

A zero-dependency release gate for Node 18+. It reads the exact artifact you are about to publish and fails when it carries things that should never ship: source maps, `sourcesContent`, TypeScript sources, `src/` and test paths, credential files, secret tokens, storage-bucket URLs, install scripts and oversized files.

It reads npm tarballs, Python wheels and sdists, Rust crates, `.vsix`, browser-extension zips, Electron `.asar`, `.nupkg`, `.jar`, `.gem`, Helm charts, `docker save` / OCI image archives, and static-site build directories.

shipsafe prevents accidental leaks. It does not make JavaScript unreversable: logic that must stay secret belongs on a server.

## Install

Add it to `devDependencies` at an exact version, so `npm ci` installs the reviewed version from the lockfile:

```sh
npm install --save-dev --save-exact @cyberinecore/shipsafe
```

## Use

Gate the packed file, publish that same file, then prove the registry holds it:

```sh
npm pack --pack-destination out
node_modules/.bin/shipsafe check out/*.tgz
for f in out/*.tgz; do npm publish "$f" --access public; done
for f in out/*.tgz; do node_modules/.bin/shipsafe verify "$f"; done
```

| command | what it does |
|---|---|
| `shipsafe check <file>...` | scan artifacts; exit 0 clean, 1 on any finding, 2 on a usage or config error |
| `shipsafe check-dir <dir>...` | scan a static build output such as `dist/` |
| `shipsafe verify <file>` | exit 0 only when the registry holds this exact file (npm, PyPI, crates.io) |
| `shipsafe diff <new.tgz> [<old.tgz>]` | list added, removed and grown files against the last release and label risk-raising changes |
| `shipsafe audit <name>` | incident tool: download and gate the last published versions |

Output formats: text (default), `--json`, `--format sarif` for GitHub code scanning, and `--format markdown` for a PR or job summary.

## Configure

Configuration lives in the packed `package.json`, so every run judges the same artifact the same way. There are no flags that change rules.

```json
"shipsafe": {
  "maxFileBytes": 10485760,
  "allow": [
    { "rule": "bucket-url", "path": "dist/*.js", "reason": "documented public download bucket" }
  ]
}
```

Every exception needs a reason; unused exceptions are reported as warnings.

## Network and data

`check`, `check-dir` and the hook make no network calls and have no telemetry. `verify`, `diff` and `audit` contact only the registry the command targets and send a package name and version. shipsafe never reads, stores or sends registry tokens or OTPs.

## Claude Code plugin

The same CLI powers the Cyberine ReleaseGuard plugin, whose hook asks before an unchecked publish, upload or deploy:

```sh
claude plugin marketplace add cyberinecore/cc-release-guard
claude plugin install cyberine-releaseguard@cyberine-releaseguard
```

Full rule list and documentation: https://github.com/cyberinecore/cc-release-guard

## License

MIT
