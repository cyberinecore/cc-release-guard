# shipsafe

A Claude Code plugin and a standalone CLI that stop npm packages from shipping their source by accident. Claude Code's own npm package leaked its full source twice this way (an inline source map in February 2025, a 60 MB `cli.js.map` with `sourcesContent` in March 2026): the bundler emitted maps by default and nothing checked the tarball that was published.

What it does not do: make JavaScript unreversable. Minified JS, and the JS embedded in a Bun single-file executable, stay readable with effort. shipsafe prevents accidental leaks and keeps the release process honest; logic that must stay secret belongs on a server.

## Parts

- **`shipsafe check <file.tgz>...`**: a zero-dependency Node CLI (Node 18+). It reads each real packed tarball and exits 1 on any finding, 2 on a usage or config error, 0 when every tarball is clean, printing each tarball's sha256. With `--json` it prints one report object for a single file and an array for several.
- **PreToolUse hook**: fires only for Bash commands that look like `npm`, `pnpm`, `bun` or `yarn` publishes. It denies a publish that does not name a `.tgz`, re-runs the gate on the named tarball and denies it on any finding, and always denies `yarn npm publish`, which cannot publish a prebuilt tarball. Dry runs pass. It never approves anything, so the normal permission flow still applies to a clean publish.
- **Skills** (slash commands): `/shipsafe:release` runs the whole release, auto-triggered when you ask Claude to publish; `/shipsafe:init` sets a repo up (files allowlist, maps off, prepack build, CI gate); `/shipsafe:check` gates a package without publishing; `/shipsafe:help` routes to the right one. The release skill carries the build, pack, gate and hand-over procedure for libraries (bundle, minify, no maps, bundled `.d.ts`, `files` allowlist) and executables (`bun build --compile --minify` per platform, shipped as per-platform packages behind a launcher). The OTP step stays with the human.

## Rules

| rule | fails on |
|---|---|
| `source-map` | any `*.map` file |
| `sources-content` | any file containing a `sourcesContent` key |
| `inline-source-map` | `sourceMappingURL=data:...` |
| `remote-source-map` | `sourceMappingURL=http(s)://...` |
| `typescript-source` | `.ts`, `.tsx`, `.mts`, `.cts` other than declaration files |
| `source-dir` | any path inside a `src/` directory |
| `test-path` | `test/`, `tests/`, `__tests__/`, `__mocks__/`, `__fixtures__/`, `*.test.*`, `*.spec.*` |
| `sensitive-file` | `.env*` (except `.env.example`), `.npmrc`, `*.pem`, `*.key`, `id_rsa*`, `.git/` |
| `file-size` | a file larger than `maxFileBytes` (default 5 MiB) |
| `bucket-url` | S3, R2, GCS, Azure Blob, DigitalOcean Spaces, Backblaze B2 or Wasabi hostnames and `s3://` / `gs://` URLs |
| `lifecycle-script` | a `preinstall`, `install` or `postinstall` script in the packed `package.json`, or a shipped `binding.gyp` (npm then runs `node-gyp rebuild` on install); allow one with `"path": "package.json#<script>"` |
| `archive-integrity` | symlink, hardlink, device or FIFO entries and duplicate paths, which the scan cannot vouch for |

A tarball that is truncated, malformed, has an entry escaping the package root (`..` or an absolute path), or unpacks to more than 1 GiB is a hard error (exit 2), not a finding.

## Configuration

Configuration lives in the packed `package.json`, so the CLI in CI and the hook in Claude Code judge the same tarball the same way:

```json
"shipsafe": {
  "maxFileBytes": 262144000,
  "allow": [
    { "rule": "bucket-url", "path": "dist/*.js", "reason": "documented public download bucket" }
  ]
}
```

`path` takes `*`, `**` and `?`. Every exception needs a reason, and unused exceptions are reported as warnings.

## Install the plugin

```sh
claude plugin marketplace add cyberinecore/cc-release-guard
claude plugin install shipsafe@shipsafe
```

Official sources are only `github.com/cyberinecore/cc-release-guard` and the npm package `@cyberinecore/shipsafe`; anything under another owner is not this project.

The hook needs `node` on `PATH`. If `node` is missing, the hook errors without blocking.

## Use in CI

```sh
npm pack --pack-destination out
npx --yes @cyberinecore/shipsafe@0.1.0 check out/*.tgz
for f in out/*.tgz; do npm publish "$f" --access public; done
```

For a workspace, pack every package into `out/` (`npm pack --workspaces --pack-destination out`); `check` gates them all in one run and fails if any one fails.

Publish the file the gate checked, never the working tree: `npm pack --dry-run` does not run `prepublishOnly`, so it can list a different file set from the one that ships.

## Limits

- The hook sees commands Claude runs. A publish inside `npm run release`, a script, or a terminal outside Claude Code is not intercepted; run the gate in CI for those.
- Command matching is best-effort by design: it targets accidents, not a user deliberately bypassing it.
- The hook looks through `sh|bash|zsh -c`, `eval`, `npx`, `bunx`, `corepack` and `npm|pnpm|yarn exec|dlx`. A publish fed its tarball by `xargs` or `find -exec` is always denied, because the file that ships cannot be known before it runs.
- npm only for now. PyPI and crates.io are planned.

## License

MIT
