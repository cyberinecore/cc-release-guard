---
name: safe-publish
description: Prepare an npm package release that cannot leak source by accident - build, pack the real tarball, run the release-guard gate on it, and hand the human the exact publish command for their OTP. Use when the user says "publish to npm", "release this package", "npm publish", "ship a new version", "phat hanh len npm", "publish package nay", or asks how to bundle a library or CLI so its source is not shipped.
---

# Safe publish (npm)

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
- Per-platform binaries are 60-230 MB, so raise the size threshold only in those packages: `"releaseGuard": { "maxFileBytes": 262144000 }`.
- Spike first: confirm every dependency (native addons, Ink/React, node-pty) runs under `bun --compile` before promising this route.

## 3. Build, pack, gate

Run from the package directory, in this order, and stop at the first failure:

```sh
npm ci
npm run build
npm pack --pack-destination .local/release
node "${CLAUDE_PLUGIN_ROOT}/cli/release-guard.mjs" check .local/release/<name>-<version>.tgz
```

Make sure `.local/` is gitignored. The gate fails on any `*.map`, embedded `sourcesContent`, inline or remote source map, `.ts`/`.tsx` other than `.d.ts`, a `src/` or test path, a credential file (`.env*`, `.npmrc`, keys), a file over `maxFileBytes` (default 5 MiB), or a URL to a storage bucket (S3, R2, GCS, Azure Blob, Spaces, B2, Wasabi). Fix the build, not the gate. When a finding is genuinely intended, add an exception to `package.json` and show it to the user; every exception needs a reason and ships inside the package:

```json
"releaseGuard": { "allow": [{ "rule": "bucket-url", "path": "dist/*.js", "reason": "documented public download bucket" }] }
```

Then confirm the version is still free (npm never lets a version be republished): `npm view <name>@<version> version` must return E404.

## 4. Hand over the publish

Everything above happens before the user fetches an OTP, because a code lasts about 30 seconds and a failed build burns it. Give the user one line to run themselves, with the absolute tarball path from the gate's PASS line:

```sh
! npm publish /abs/path/<name>-<version>.tgz --access public --otp <code>
```

The plugin's hook re-runs the gate on that exact file when Claude runs a publish command and blocks `npm publish` / `pnpm publish` / `bun publish` without a passing tarball, and `yarn npm publish` always (it cannot publish a prebuilt tarball). It does not see publishes hidden inside `npm run <script>` or run outside Claude Code, so CI must run the gate itself.

## 5. After publish

Compare what the registry holds with what was checked: `npm view <name>@<version> dist.integrity` must equal `sha512-$(openssl dgst -sha512 -binary <file>.tgz | base64)`.

## CI

Run the same gate before any publish step, on the same file the publish step uploads:

```sh
npm pack --pack-destination out
npx --yes release-guard@0.1.0 check out/*.tgz
npm publish out/*.tgz --provenance --access public
```
