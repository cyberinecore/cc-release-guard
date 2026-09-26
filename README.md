# shipsafe

A Claude Code plugin and a standalone CLI that stop npm packages from shipping their source by accident. Claude Code's own npm package leaked its full source twice this way (an inline source map in February 2025, a 60 MB `cli.js.map` with `sourcesContent` in March 2026): the bundler emitted maps by default and nothing checked the tarball that was published.

What it does not do: make JavaScript unreversable. Minified JS, and the JS embedded in a Bun single-file executable, stay readable with effort. shipsafe prevents accidental leaks and keeps the release process honest; logic that must stay secret belongs on a server.

## Parts

- **`shipsafe check <file.tgz>...`**: a zero-dependency Node CLI (Node 18+). It reads each real packed tarball and exits 1 on any finding, 2 on a usage or config error, 0 when every tarball is clean, printing each tarball's sha256. With `--json` it prints one report object for a single file and an array for several; `--format sarif` prints one SARIF 2.1.0 run for GitHub code scanning (allowed findings carry a suppression with their reason), and `--format markdown` prints a PR-ready summary with the sha256, findings, exceptions and a collapsible file inventory. `diff` takes `--format markdown` too.
- **`shipsafe diff <new.tgz> [<old.tgz> | --against <name@version|dist-tag>]`**: what changed since the previous release (default: the `latest` tarball on the registry, downloaded from the packument's `dist.tarball`). It lists added, removed and grown files and labels risk-raising changes: `new-lifecycle-script`, `new-dependency`, `new-bin`, `new-export`, `new-exception` (a new `shipsafe.allow` entry) and `size-jump` (a file that grew by `growthFactor`, default 2, and more than 1 KiB). Informational: it exits 0 unless it cannot run. The first release prints `no baseline`.
- **`shipsafe audit <name> [--versions N]`**: an incident tool, not a release stage. It downloads the last N published versions (default 5), checks each against its `dist.integrity`, and gates it with the same rules; exit 1 when any version leaks.
- **Other archives**: `check` also reads `.vsix` files (rooted at `extension/`, with every rule except `lifecycle-script` and `publish-intent`, since VS Code runs no install scripts) and browser-extension `.zip` files (`manifest.json` at the root; the leak rules plus TypeScript, `src/` and test paths, and a warning for broad host permissions such as `<all_urls>`). The zip reader handles stored and deflate entries, rejects zip64, encrypted and multi-disk archives, and treats symlinks as `archive-integrity` findings. The `vsce publish` and store upload steps are not intercepted: gate the file before you upload it.
- **`shipsafe check-dir <dir>...`**: the same engine for a static-site build output (`dist/`, `build/`): source maps, `sourcesContent`, inline or remote maps, credential files and strings, bucket URLs and build metadata. `node_modules/` is skipped and symlinks are findings. Config comes from the `shipsafe` key of the nearest `package.json` at or above the directory, so no extra file deploys to the CDN.
- **PreToolUse hook**: fires only for Bash commands that look like `npm`, `pnpm`, `bun` or `yarn` publishes. It denies a publish that does not name a `.tgz`, re-runs the gate on the named tarball and denies it on any finding, and always denies `yarn npm publish`, which cannot publish a prebuilt tarball. It also denies a publish whose flags contradict the packed metadata: a scoped package with neither `--access` nor `publishConfig.access`, a `--registry` that differs from `publishConfig.registry`, and a prerelease version headed for the `latest` dist-tag (publish it with `--tag next`). Dry runs pass. It never approves anything, so the normal permission flow still applies to a clean publish.
- **Skills** (slash commands): `/shipsafe:release` runs the whole release, auto-triggered when you ask Claude to publish; `/shipsafe:init` sets a repo up (files allowlist, maps off, prepack build, CI gate); `/shipsafe:check` gates a package without publishing; `/shipsafe:verify` proves the registry holds exactly the checked tarball; `/shipsafe:incident` handles a leak already on npm; `/shipsafe:help` routes to the right one. The release skill carries the build, pack, gate and hand-over procedure for libraries (bundle, minify, no maps, bundled `.d.ts`, `files` allowlist) and executables (`bun build --compile --minify` per platform, shipped as per-platform packages behind a launcher). The OTP step stays with the human.

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
| `sensitive-file` | `.env*` (except `.env.example`), `.npmrc`, `.git-credentials`, `.netrc`, `.pypirc`, `.aws/credentials`, `.aws/config`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `id_rsa*`, `.git/` |
| `build-artifact` | `*.tsbuildinfo`, `coverage/`, `.nyc_output/`, and esbuild metafiles (`meta.json` / `metafile.json` with `inputs` and `outputs`), which list every source path |
| `file-size` | a file larger than `maxFileBytes` (default 5 MiB) |
| `bucket-url` | S3, R2, GCS, Azure Blob, DigitalOcean Spaces, Backblaze B2 or Wasabi hostnames and `s3://` / `gs://` URLs |
| `lifecycle-script` | a `preinstall`, `install` or `postinstall` script in the packed `package.json`, or a shipped `binding.gyp` (npm then runs `node-gyp rebuild` on install); allow one with `"path": "package.json#<script>"` |
| `secret-token` | AWS `AKIA`/`ASIA` keys, GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_` tokens, npm `npm_` tokens, Stripe `sk_live_`/`rk_live_` keys, Slack `xox[abpr]-` tokens and PEM private key blocks inside any shipped file; the report shows only the kind, prefix and length |
| `publish-intent` | `"private": true`, or a prerelease version with `publishConfig.tag` set to `latest` (a prerelease with no tag at all is a warning, since `--tag` may come on the command line) |
| `entry-point` | a `main`, `module`, `types`/`typings`, `browser`, `bin` or `exports` target (conditions, arrays and `*` subpath patterns included) that is not in the tarball; export shape itself is left to publint and attw |
| `archive-integrity` | symlink, hardlink, device or FIFO entries and duplicate paths, which the scan cannot vouch for |

A tarball that is truncated, malformed, has an entry escaping the package root (`..` or an absolute path), or unpacks to more than 1 GiB is a hard error (exit 2), not a finding.

## Configuration

Configuration lives in the packed `package.json`, so the CLI in CI and the hook in Claude Code judge the same tarball the same way:

```json
"shipsafe": {
  "maxFileBytes": 262144000,
  "growthFactor": 3,
  "allow": [
    { "rule": "bucket-url", "path": "dist/*.js", "reason": "documented public download bucket" }
  ]
}
```

`path` takes `*`, `**` and `?`. Every exception needs a reason, and unused exceptions are reported as warnings. Rules about `package.json` itself use `package.json#<field>` as the path, for example `package.json#postinstall`. Unknown keys (a typo such as `maxFilesBytes`) are warnings, and so is any nested archive (`.zip`, `.tgz`, `.jar`, ...), because the gate does not look inside it.

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
for f in out/*.tgz; do npx --yes @cyberinecore/shipsafe@0.1.0 verify "$f"; done
```

`shipsafe verify <file.tgz> [--registry <url>]` reads name@version from the tarball, fetches the registry's `dist.integrity` (from `publishConfig.registry`, else the npm registry) and exits 0 only when it equals the local file's sha512; 1 when the version is missing or holds a different file; 2 when the registry is unreachable. A publish from CI never passes through the hook, so this is how CI proves the file it checked is the file it published.

For a workspace, pack every package into `out/` (`npm pack --workspaces --pack-destination out`); `check` gates them all in one run and fails if any one fails.

Or use the composite action from this repository, which runs the CLI from its own checkout (no npm install) and writes a markdown report to the job summary:

```yaml
- uses: cyberinecore/cc-release-guard@main
  id: shipsafe
  with:
    working-directory: .
- run: for f in ${{ steps.shipsafe.outputs.tarballs }}; do npm publish "$f" --access public; done
```

Inputs: `tarballs` (a glob such as `out/*.tgz`; empty packs `working-directory` with `npm pack`), `working-directory`, `summary` (`true`/`false`). Output `tarballs` lists the absolute paths that passed, so the publish step uploads exactly those files. Pin a commit SHA instead of `@main` until a versioned tag exists.

To see the result in review, append `--format markdown` output to `$GITHUB_STEP_SUMMARY` and upload `--format sarif` output with `github/codeql-action/upload-sarif` (needs `security-events: write`); this repo's `.github/workflows/ci.yml` does both.

Publish the file the gate checked, never the working tree: `npm pack --dry-run` does not run `prepublishOnly`, so it can list a different file set from the one that ships.

## Limits

- The hook sees commands Claude runs. A publish inside `npm run release`, a script, or a terminal outside Claude Code is not intercepted; run the gate in CI for those.
- Command matching is best-effort by design: it targets accidents, not a user deliberately bypassing it.
- Release orchestrators that pack and publish on their own (`lerna publish`, `changeset publish`, `semantic-release`, `release-it`, `np`) are denied outside their dry-run modes, with a pack, gate, publish-each-tarball recipe. `npm stage publish <file>.tgz` is gated like `npm publish`. Publishes inside `npm run <script>`, Makefiles, or a CI job are not intercepted.
- The hook looks through `sh|bash|zsh -c`, `eval`, `npx`, `bunx`, `corepack` and `npm|pnpm|yarn exec|dlx`. A publish fed its tarball by `xargs` or `find -exec` is always denied, because the file that ships cannot be known before it runs.
- Static deploys: the hook gates `wrangler pages deploy <dir>` (or `pages_build_output_dir` from `wrangler.toml`/`wrangler.json`), `vercel [deploy] --prebuilt` (`.vercel/output/static`), `netlify deploy --dir <dir>` (or `publish` from `netlify.toml`) and `firebase deploy` including hosting (`hosting.public` from `firebase.json`). A deploy whose directory cannot be determined is denied with a hint. `vercel deploy` without `--prebuilt` builds remotely from source and is not gated.
- GitHub releases: `gh release create|upload` is denied when an attached `.tgz`/`.tar.gz` fails the gate (a tarball without a root `package.json` gets the leak rules only), and when an attached archive shipsafe cannot read yet (`.jar`, `.7z`, ...); `.zip` and `.vsix` assets are scanned. Other assets such as binaries and checksums pass unscanned.
- npm packages and static sites only for now. PyPI and crates.io are planned.

## Related tools

These check different things or a different file set; run them alongside shipsafe rather than instead of it.

- [publint](https://publint.dev) and [@arethetypeswrong/cli](https://github.com/arethetypeswrong/arethetypeswrong.github.io) check that a package is well formed: `exports` shapes, module formats, type resolution. shipsafe only checks that entry points exist, and otherwise asks a different question: whether the tarball carries things that should never ship.
- [secretlint](https://github.com/secretlint/secretlint) has a much larger secret rule set and scans the files you point it at. shipsafe's `secret-token` rule covers a short list of high-confidence token formats, but it reads the packed tarball, so it sees exactly what reaches the registry and nothing that stays behind.
- [gitleaks](https://github.com/gitleaks/gitleaks) and [trufflehog](https://github.com/trufflesecurity/trufflehog) scan git history and repositories. A secret in history never ships in a tarball that excludes it, and a secret generated at build time ships without ever touching git; each tool answers for its own file set.

What shipsafe adds is the tarball-native view (maps, `sourcesContent`, source and test paths, install scripts, archive integrity on the exact file that is published) and the Claude Code hook that re-checks that file at publish time.

## License

MIT
