# Cyberine ReleaseGuard

Cyberine ReleaseGuard (`cyberine-releaseguard`) is a Claude Code plugin, and `shipsafe` (npm `@cyberinecore/shipsafe`) is its standalone CLI; together they stop npm packages from shipping their source by accident. Claude Code's own npm package leaked its full source twice this way (an inline source map in February 2025, a 60 MB `cli.js.map` with `sourcesContent` in March 2026): the bundler emitted maps by default and nothing checked the tarball that was published.

What it does not do: make JavaScript unreversable. Minified JS, and the JS embedded in a Bun single-file executable, stay readable with effort. shipsafe prevents accidental leaks and keeps the release process honest; logic that must stay secret belongs on a server.

## Parts

- **`shipsafe check <file.tgz>...`**: a zero-dependency Node CLI (Node 18+). It reads each real packed tarball and exits 1 on any finding, 2 on a usage or config error, 0 when every tarball is clean, printing each tarball's sha256. With `--json` it prints one report object for a single file and an array for several; `--format sarif` prints one SARIF 2.1.0 run for GitHub code scanning (allowed findings carry a suppression with their reason), and `--format markdown` prints a PR-ready summary with the sha256, findings, exceptions and a collapsible file inventory. `diff` takes `--format markdown` too.
- **`shipsafe diff <new.tgz> [<old.tgz> | --against <name@version|dist-tag>]`**: what changed since the previous release (default: the `latest` tarball on the registry, downloaded from the packument's `dist.tarball`). It lists added, removed and grown files and labels risk-raising changes: `new-lifecycle-script`, `new-dependency`, `new-bin`, `new-export`, `new-exception` (a new `shipsafe.allow` entry) and `size-jump` (a file that grew by `growthFactor`, default 2, and more than 1 KiB). Informational: it exits 0 unless it cannot run. The first release prints `no baseline`.
- **`shipsafe audit <name> [--versions N]`**: an incident tool, not a release stage. It downloads the last N published versions (default 5), checks each against its `dist.integrity`, and gates it with the same rules; exit 1 when any version leaks.
- **Other archives**: `check` also reads `.vsix` files (rooted at `extension/`, with every rule except `lifecycle-script` and `publish-intent`, since VS Code runs no install scripts) and browser-extension `.zip` files (`manifest.json` at the root; the leak rules plus TypeScript, `src/` and test paths, and a warning for broad host permissions such as `<all_urls>`). The zip reader handles stored and deflate entries, rejects zip64, encrypted and multi-disk archives, and treats symlinks as `archive-integrity` findings. It also reads Electron `.asar` archives, directly or nested inside a `.zip` (for example `App.app/Contents/Resources/app.asar`), with the leak rules plus TypeScript and test paths; ordinary app JavaScript is expected there and is not a finding, and files kept in `app.asar.unpacked` are listed as warnings. The `vsce publish` and store upload steps are not intercepted: gate the file before you upload it.
- **`shipsafe check-dir <dir>...`**: the same engine for a static-site build output (`dist/`, `build/`): source maps, `sourcesContent`, inline or remote maps, credential files and strings, bucket URLs and build metadata. `node_modules/` is skipped and symlinks are findings. Config comes from the `shipsafe` key of the nearest `package.json` at or above the directory, so no extra file deploys to the CDN.
- **PreToolUse hook**: fires for Bash commands that look like a publish, upload or deploy. It never blocks anything: when something looks wrong it answers `ask`, so Claude Code pauses and shows you the reason and the suggested fix, and you decide whether the command runs. Measured 2026-09-27 with headless sessions: the ask still stops the command under `bypassPermissions` and when `--allowedTools` allows it; a non-interactive session has no one to answer, so the command does not run there. It asks about a publish that does not name a `.tgz`, re-runs the gate on the named tarball and asks on any finding, and always asks about `yarn npm publish`, which cannot publish a prebuilt tarball. It also asks about a publish whose flags contradict the packed metadata: a scoped package with neither `--access` nor `publishConfig.access`, a `--registry` that differs from `publishConfig.registry`, and a prerelease version headed for the `latest` dist-tag (publish it with `--tag next`). Dry runs pass. A clean command gets no answer from the hook at all, so the normal permission flow applies to it unchanged.
- **Skills** (slash commands): `/cyberine-releaseguard:release` runs the whole release, auto-triggered when you ask Claude to publish; `/cyberine-releaseguard:init` sets a repo up (files allowlist, maps off, prepack build, CI gate); `/cyberine-releaseguard:check` gates a package without publishing; `/cyberine-releaseguard:verify` proves the registry holds exactly the checked tarball; `/cyberine-releaseguard:incident` handles a leak already on npm; `/cyberine-releaseguard:help` routes to the right one. The release skill carries the build, pack, gate and hand-over procedure for libraries (bundle, minify, no maps, bundled `.d.ts`, `files` allowlist) and executables (`bun build --compile --minify` per platform, shipped as per-platform packages behind a launcher). The OTP step stays with the human.

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
claude plugin install cyberine-releaseguard@cyberine-releaseguard
```

Official sources are only `github.com/cyberinecore/cc-release-guard` and the npm package `@cyberinecore/shipsafe`; anything under another owner is not this project.

The plugin needs Claude Code 2.1.139 or later, the first version with exec-form hooks (`args`); on an older Claude Code the hook does not run. The hook needs Node.js 18 or later on `PATH`. If `node` is missing, the hook errors and Claude Code carries on without it.

## Use in CI

```sh
npm pack --pack-destination out
npx --yes @cyberinecore/shipsafe@0.1.0 check out/*.tgz
for f in out/*.tgz; do npm publish "$f" --access public; done
for f in out/*.tgz; do npx --yes @cyberinecore/shipsafe@0.1.0 verify "$f"; done
```

`shipsafe verify <file.tgz> [--registry <url>]` reads name@version from the tarball, fetches the registry's `dist.integrity` (from `publishConfig.registry`, else the npm registry) and exits 0 only when it equals the local file's sha512; 1 when the version is missing or holds a different file; 2 when the registry is unreachable. A publish from CI never passes through the hook, so this is how CI proves the file it checked is the file it published. For a wheel or sdist it compares the file's sha256 with the matching file on PyPI (`--registry` takes another index base such as `https://test.pypi.org`); for a `.crate` it compares with the `cksum` in the crates.io sparse index, which only matches when the checked file is the one cargo uploaded.

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

## Network and data

- The hook and `check`/`check-dir` make no network calls: they read local files only and send nothing anywhere. There is no telemetry.
- `verify`, `diff` (against a registry version) and `audit` contact only the registry the command targets: the npm registry, or `publishConfig.registry`/`--registry`, PyPI or the crates.io index. They send the package name and version and download public metadata and tarballs.
- The hook and the CLI never start another program and never install anything. Package runner names (`npx`, `bunx`, `pnpx`, `corepack`, `uvx`) appear in the source only so the hook can recognize a publish wrapped in one, and commands such as `npx expo export` appear only in hints printed for you to run.
- shipsafe never reads, stores or sends registry tokens or OTPs; the human types the OTP into the publish command.
- The hook writes one empty marker file per tool call in the OS temp directory (`shipsafe-hook-<tool_use_id>`) so overlapping hook filters answer only once; markers older than a day are removed.
- The full privacy policy is in [PRIVACY.md](PRIVACY.md); report security issues as described in [SECURITY.md](SECURITY.md). Release notes are in [CHANGELOG.md](CHANGELOG.md).

## Limits

- The hook fires in every permission mode, `bypassPermissions` included (checked 2026-09-27 with a headless session), and its answer is always `ask`, never a hard block. It does not fire for commands the user types with the `!` prefix (checked 2026-09-27 in an interactive session: `! npm publish` ran with no ask), so a publish the user runs by hand should run the gate in the same line: `shipsafe check x.tgz && npm publish x.tgz`, which is the line `/cyberine-releaseguard:release` hands over.
- The hook sees commands Claude runs. A publish inside `npm run release`, a script, or a terminal outside Claude Code is not intercepted; run the gate in CI for those.
- Command matching is best-effort by design: it targets accidents, not a user deliberately bypassing it.
- Release orchestrators that pack and publish on their own (`lerna publish`, `changeset publish`, `semantic-release`, `release-it`, `np`) trigger an ask outside their dry-run modes, with a pack, gate, publish-each-tarball recipe. `npm stage publish <file>.tgz` is gated like `npm publish`. Publishes inside `npm run <script>`, Makefiles, or a CI job are not intercepted.
- The hook looks through `sh|bash|zsh -c`, `eval`, `npx`, `bunx`, `corepack` and `npm|pnpm|yarn exec|dlx`. A publish fed its tarball by `xargs` or `find -exec` always triggers an ask, because the file that ships cannot be known before it runs.
- Static deploys: the hook gates `wrangler pages deploy <dir>` (or `pages_build_output_dir` from `wrangler.toml`/`wrangler.json`), `vercel [deploy] --prebuilt` (`.vercel/output/static`), `netlify deploy --dir <dir>` (or `publish` from `netlify.toml`) and `firebase deploy` including hosting (`hosting.public` from `firebase.json`). A deploy whose directory cannot be determined triggers an ask with a hint. `vercel deploy` without `--prebuilt` builds remotely from source and is not gated. `wrangler deploy` and `wrangler versions upload` gate a Worker's static assets directory: `--assets <dir>` (or legacy `--site`), else `assets.directory` (or `site.bucket`) from `--config`, the Cloudflare Vite plugin's `.wrangler/deploy/config.json` redirect, `wrangler.jsonc`, `wrangler.json` or `wrangler.toml`, with `--env` overrides; a Worker without assets passes. The Worker script itself is bundled by wrangler during the upload and is not seen.
- Package registries beyond npm: `dotnet nuget push <file>`, `nuget push <file>`, `gem push <file>` and `mvn deploy:deploy-file -Dfile=<file>` are gated on the named `.nupkg`, `.gem` or `.jar` with the leak rules only (source and tests are normal in those ecosystems; a `src/` directory in a non-symbols `.nupkg` is a warning). `mvn deploy` and `gradle publish` name no artifact and pass unseen.
- Python and Rust: `check` reads wheels (`.whl`), sdists and `.crate` files. Source and tests are normal there, so they get the leak rules plus `file-size` and `vcs-dir` (`.venv/`, `.tox/`, caches, `node_modules/`, a crate's `target/`); wheels also get `wheel-record` (RECORD must match the files and their hashes), `entry-point` (console scripts must resolve to a shipped module), `native-debug-info` (`.pdb`, `.dSYM`), `test-path` for a top-level `tests/` package, and warnings for `.pyc` files, test modules inside a package, and unstripped native extensions. Config: sdists read `[tool.shipsafe]` from their packed `pyproject.toml`, crates read `[package.metadata.shipsafe]` from their packed `Cargo.toml`, and wheels, which carry no `pyproject.toml`, read the nearest one on disk at or above the wheel whose `[project].name` matches the wheel; if none matches, strict defaults apply and the report says so.
- Python and Rust uploads: the hook checks the files `twine upload`, `uv publish`, `hatch publish` and `maturin upload` name (also through `python -m`, `pipx run`, `uvx`, `uv run`, `uv tool run`), and the `dist/` directory that `uv publish` with no files, `poetry publish` and `pdm publish --no-build` upload. Commands that build during the upload (`poetry publish --build`, `pdm publish` without `--no-build`, `flit publish`, `maturin publish`) and `hatch publish` with no files trigger an ask with a build, check, upload recipe. `cargo publish` always triggers an ask outside `--dry-run`: it re-packages the tree instead of uploading a checked file, so the ask shows whether `target/package/<name>-<version>.crate` exists, its sha256 and its gate result, and suggests `--locked`.
- Container images: `check image.tar` reads a `docker save` or OCI layout archive and scans every layer, not just the final filesystem, so a `.env` removed by a later `RUN rm` is still reported with the layer that holds it; the image config `Env` and build history are scanned for tokens. Images get only `sensitive-file` and `secret-token`, and system and vendor paths (`/etc/ssl`, `/usr/lib`, `node_modules`, `site-packages`) are skipped, so CA certificates and library fixtures are not findings. zstd layers are reported as not scanned. `docker push` names an image, not a file, so the hook cannot check it: by default it stays silent. Opt in with `{ "askOnDockerPush": true }` in a `.claude/shipsafe.json` at or above the working directory (the nearest file wins, so a repo can turn off a home-wide opt-in) and the hook then asks before `docker push`, `docker image push`, `podman push`, `docker compose push` and `docker build`/`buildx build|bake` with `--push` or a registry output, with the recipe `docker save -o /tmp/image.tar <image>`, `shipsafe check /tmp/image.tar`, then push.
- Helm charts: `check` reads a `helm package` `.tgz` (a root `Chart.yaml` after the chart directory) with the leak rules, and `values*.yaml` keys that look like credentials (`password`, `token`, `secret`, `apiKey`, ...) holding a literal value are `secret-token` findings; empty values, templates, numbers and references (`existingSecret`, `secretName`, `passwordKey`) are not. Subcharts in `charts/*.tgz` are opened and scanned. `templates/tests/` is Helm's own convention and is not a `test-path` finding. The hook gates `helm push <chart>.tgz oci://...` and `helm cm-push <chart>.tgz`, and asks when either names a chart directory instead of a packaged file. Charts carry no config, so strict defaults apply.
- Expo OTA updates: `eas update` (also `npx eas-cli update`) triggers an ask unless it publishes a prebuilt export with `--skip-bundler`; that export directory (`--input-dir`, default `dist`) is gated like `check-dir`. A bundle built during the upload is never seen, which is how source maps reach every installed app.
- GitHub releases: `gh release create|upload` triggers an ask when an attached `.tgz`/`.tar.gz` fails the gate (a tarball without a root `package.json` gets the leak rules only), and when an attached archive shipsafe cannot read yet (`.jar`, `.7z`, ...); `.zip` and `.vsix` assets are scanned. Other assets such as binaries and checksums pass unscanned.

## Related tools

These check different things or a different file set; run them alongside shipsafe rather than instead of it.

- [publint](https://publint.dev) and [@arethetypeswrong/cli](https://github.com/arethetypeswrong/arethetypeswrong.github.io) check that a package is well formed: `exports` shapes, module formats, type resolution. shipsafe only checks that entry points exist, and otherwise asks a different question: whether the tarball carries things that should never ship.
- [secretlint](https://github.com/secretlint/secretlint) has a much larger secret rule set and scans the files you point it at. shipsafe's `secret-token` rule covers a short list of high-confidence token formats, but it reads the packed tarball, so it sees exactly what reaches the registry and nothing that stays behind.
- [gitleaks](https://github.com/gitleaks/gitleaks) and [trufflehog](https://github.com/trufflesecurity/trufflehog) scan git history and repositories. A secret in history never ships in a tarball that excludes it, and a secret generated at build time ships without ever touching git; each tool answers for its own file set.

What shipsafe adds is the tarball-native view (maps, `sourcesContent`, source and test paths, install scripts, archive integrity on the exact file that is published) and the Claude Code hook that re-checks that file at publish time.

## License

MIT
