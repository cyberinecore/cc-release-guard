---
name: init
description: This skill should be used when a repo that publishes to npm should be set up so its releases cannot ship source by accident - "/cyberine-releaseguard:init", "setup shipsafe", "cai shipsafe cho repo nay", "chuan bi repo de publish an toan", "make this package safe to publish". Audits package.json and the build config, proposes the fixes, and runs a first gate on a real tarball.
disable-model-invocation: true
user-invocable: true
---

# shipsafe init

Goal: after this, `npm pack` produces a tarball that passes `shipsafe check` without exceptions, and every future pack builds fresh output first. Change the user's repo only after showing the proposed diff; never commit.

## 1. Read

From the package directory: `package.json`, the build config (`tsup.config.*`, `esbuild` scripts, `vite.config.*`, `rollup.config.*`, `tsconfig*.json`, `bun build` scripts), `.npmignore`, `.gitignore`.

## 2. Propose, in one diff

- `files`: an allowlist of build output only (for example `["dist"]`). Replace a `.npmignore` blocklist with it and say why: a blocklist misses whatever is new.
- `main`, `module`, `types`, `exports`, `bin` all point inside that allowlist.
- Source maps off in the build (`sourcemap: false`, `--sourcemap=none`, `"sourceMap": false` for the emitted JS). If the user wants maps for an error tracker, emit them with `sourcesContent: false`, keep them out of `files`, and upload them privately.
- `"prepack": "npm run build"` when a build script exists, so every pack is fresh.
- `.local/` in `.gitignore` (tarballs are packed to `.local/release/`).
- Add a `"shipsafe"` block only when a finding is genuinely intended; every `allow` entry needs a `reason`. Never add one to make the gate pass.

## 3. First gate

```sh
npm pack --pack-destination .local/release
node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" check .local/release/<name>-<version>.tgz
```

Report findings grouped by rule with the fix for each, and repeat until it passes or the user accepts an exception.

## 4. CI (offer, do not write unasked)

Show the step that gates the same file CI publishes. It needs the CLI to the project's `devDependencies` at an exact version (`"@cyberinecore/shipsafe": "0.1.0"`), so `npm ci` installs the reviewed version from the lockfile, first:

```sh
npm ci
npm pack --pack-destination out
node_modules/.bin/shipsafe check out/<name>-<version>.tgz
npm publish out/<name>-<version>.tgz --provenance --access public
```

Publish the file the gate checked, never the working tree.
