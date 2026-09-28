---
name: release
description: This skill should be used when the user is about to publish an npm package - "publish to npm", "release this package", "npm publish", "ship a version", "phat hanh len npm", "publish package nay", "len version moi", or asks how to ship a package without its source. Builds, packs the real tarball, gates it with shipsafe, and hands the human the exact publish command for their OTP; never publishes.
---

# shipsafe release (npm)

Goal: the file that reaches the registry is exactly the file the gate checked, and that file carries build output only. This prevents ACCIDENTAL source leaks and raises the cost of reversing. It does not make JavaScript unreversable: minified JS, and the JS inside a `bun build --compile` executable, stay readable with effort (`strings` prints the JS of a Bun executable). Say this plainly whenever the user asks for "protection"; logic that must stay secret belongs on a server the user runs.

## Hard lines

- The human types the OTP. Never ask for it in chat, never store, create or pre-stage an automation token, never print or read a token value (paths and key names only).
- Never run the publish yourself. Prepare everything, then give the user the exact command to run with the `!` prefix.
- Publish only a packed `.tgz` that passed the gate, by its path. `npm pack --dry-run` does not run `prepublishOnly` and is not a substitute.
- Do not recommend these as source protection: `bun build --bytecode` (Bun's docs: bytecode "doesn't obscure source code"; it is a startup optimization), Node SEA code cache or snapshots (not documented to hide source; stability 1.1), `javascript-obfuscator` or similar at strong settings (+55% to +295% runtime, largely undone by webcrack-style tools and LLMs).

## 1. Classify the package

Read `package.json`, the build config and the entry points, then pick one:

- **Library**: imported by other code (`main`/`exports`/`types`). Go to 2a.
- **Executable**: a CLI or server the user runs (`bin`). Go to 2b.
- **Contains logic that must stay secret**: tell the user no client-side packaging hides it and propose moving that part behind an API. Continue with 2a or 2b for the rest.

Also check the license field against the intent (closed source with `"license": "MIT"` lets anyone reuse what ships), and look for unreleased feature names, internal hostnames or customer names in the source; strip them at build time with `--define` dead-code elimination rather than shipping them behind runtime flags.

## 2a. Library build

- Bundle and minify with tsup or esbuild. Source maps OFF (`sourcemap: false`). If the user wants maps for their own error tracker, emit them with `sourcesContent: false`, keep them out of the tarball, and upload them privately.
- Types: emit bundled `.d.ts` (tsup `dts: true`, or api-extractor / rollup-plugin-dts). Make sure `node_modules` is installed first: a missing install makes `tsc` degrade imported types to `any` while still exiting 0.
- `package.json`: a `files` allowlist of build output only (for example `["dist"]`), never a `.npmignore` blocklist. `main`/`module`/`types`/`exports`/`bin` must all point inside the allowlist.
- Wire the build so packing always packs fresh output: `"prepack": "npm run build"`.

## 2b. Executable build

- One binary per target, no `--sourcemap`: `bun build ./src/cli.ts --compile --minify --target=bun-<os>-<arch> --outfile dist/<name>` for each of `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`, `windows-x64`.
- Ship each binary as its own package (`<name>-<os>-<arch>` with matching `os` and `cpu` fields) and a small launcher package that lists them all under `optionalDependencies` and execs the one matching `process.platform`/`process.arch`. This is the esbuild and Biome pattern.
- Per-platform binaries are 60-230 MB, so raise the size threshold only in those packages: `"shipsafe": { "maxFileBytes": 262144000 }`.
- Spike first: confirm every dependency (native addons, Ink/React, node-pty) runs under `bun --compile` before promising this route.

## 3. Build, pack, gate

Run from the package directory, in this order, and stop at the first failure:

```sh
npm ci
npm run build
npm pack --pack-destination .local/release
node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" check .local/release/<name>-<version>.tgz
```

Make sure `.local/` is gitignored. The gate fails on any `*.map`, embedded `sourcesContent`, inline or remote source map, `.ts`/`.tsx` other than `.d.ts`, a `src/` or test path, a credential file (`.env*`, `.npmrc`, `.netrc`, keys, keystores) or a credential string (AWS, GitHub, npm, Stripe, Slack tokens, PEM private keys), build metadata that lists source paths (`*.tsbuildinfo`, coverage, esbuild metafiles), a file over `maxFileBytes` (default 5 MiB), a URL to a storage bucket (S3, R2, GCS, Azure Blob, Spaces, B2, Wasabi), an install lifecycle script (`preinstall`/`install`/`postinstall`, or a shipped `binding.gyp`), a `main`/`types`/`bin`/`exports` target missing from the tarball, `"private": true`, and links or duplicate paths in the archive. Fix the build, not the gate. When a finding is genuinely intended, add an exception to `package.json` and show it to the user; every exception needs a reason and ships inside the package:

```json
"shipsafe": { "allow": [{ "rule": "bucket-url", "path": "dist/*.js", "reason": "documented public download bucket" }] }
```

Review the delta before handing over: `node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" diff .local/release/<name>-<version>.tgz` compares against the published `latest` and prints `RISK` lines for new install scripts, dependencies, bins, exports, exceptions and size jumps. Walk the user through every `RISK` line; the first release prints `no baseline`.

Then confirm the version is still free (npm never lets a version be republished): `npm view <name>@<version> version` must return E404.

## 4. Hand over the publish

Everything above happens before the user fetches an OTP, because a code lasts about 30 seconds and a failed build burns it. Give the user one line to run themselves, with the absolute tarball path from the gate's PASS line and the absolute path of this plugin's CLI written out (the user's shell has no `CLAUDE_PLUGIN_ROOT`), so the gate re-runs on the same file in the same line:

```sh
! node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" check /abs/path/<name>-<version>.tgz && npm publish /abs/path/<name>-<version>.tgz --access public --otp <code>
```

Keep the `check && publish` form even though the gate just passed: it has not been verified whether the hook fires for commands the user types with `!`, so the line carries its own gate.

The plugin's hook re-runs the gate on that exact file when Claude runs a publish command and, instead of blocking, asks the user before `npm publish` / `pnpm publish` / `bun publish` without a passing tarball (also behind `npx`, `corepack`, `bash -c`, `eval`), `yarn npm publish` always (it cannot publish a prebuilt tarball), release orchestrators (`lerna publish`, `changeset publish`, `semantic-release`, `release-it`, `np`), a scoped package without an explicit `--access`, and a prerelease headed for the `latest` tag. It does not see publishes hidden inside `npm run <script>` or run outside Claude Code, so CI must run the gate itself.

## 5. After publish

Prove the registry holds the checked file: `node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" verify /abs/path/<name>-<version>.tgz` must print MATCH (exit 0). Then smoke-test the published package without running its scripts, in a scratch directory: `npm install --ignore-scripts <name>@<version>` and import it (or run its `bin --version`). `/cyberine-releaseguard:verify` carries the full procedure.

## CI

Run the same gate before any publish step, on the same file the publish step uploads:

```sh
npm install --global @cyberinecore/shipsafe@0.1.0
npm pack --pack-destination out
shipsafe check out/*.tgz
for f in out/*.tgz; do npm publish "$f" --provenance --access public; done
for f in out/*.tgz; do shipsafe verify "$f"; done
```

CI publishes never pass through the hook, so `verify` on the same file is the CI's proof that the reviewed artifact is the published one.

## CI with trusted publishing (OIDC)

Template checked on 2026-09-27 against https://docs.npmjs.com/trusted-publishers/, which states: trusted publishing needs npm CLI 11.5.1 or later and Node 22.14.0 or higher, the workflow needs `id-token: write`, and provenance is generated automatically. Re-check that page before using this template; it drifts. No token exists anywhere in this flow, so there is nothing for the skill to handle.

First the user links the package to the repository and workflow file on npmjs.com (package settings, Trusted Publisher). That step is theirs; guide them there, never do it for them.

```yaml
name: release
on:
  push:
    tags: ['v*']
permissions:
  contents: read
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22.14.0
          registry-url: https://registry.npmjs.org
      - run: npm install -g npm@11.5.1
      - run: npm ci
      - run: npm install --global @cyberinecore/shipsafe@0.1.0
      - run: npm pack --pack-destination out
      - run: shipsafe check out/*.tgz
      - run: for f in out/*.tgz; do npm publish "$f" --access public; done
      - run: for f in out/*.tgz; do shipsafe verify "$f"; done
```

Pack once, gate that file, publish that same file, verify that same file: the checked artifact and the published artifact are one file. The npm page shows `npm publish` from the project directory and does not say whether publishing a prebuilt `.tgz` path works under trusted publishing; this is unconfirmed, so the first run of this template should publish a throwaway prerelease (with `--tag next`) before the workflow is trusted for real releases.
