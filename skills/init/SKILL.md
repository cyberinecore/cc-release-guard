---
name: init
description: Use when a repo that publishes to npm should be set up so its releases cannot ship source by accident. Audits package.json and the build config, proposes the fixes, and runs a first gate on a real tarball.
disable-model-invocation: true
user-invocable: true
---

# shipsafe init

Goal: `npm pack` produces a tarball that passes `shipsafe check` without exceptions, and every future pack builds fresh output first. The user's repo changes only after they have seen the proposed diff; committing stays with the user.

## 1. Read

From the package directory: `package.json`, the build config (`tsup.config.*`, `esbuild` scripts, `vite.config.*`, `rollup.config.*`, `tsconfig*.json`, `bun build` scripts), `.npmignore`, `.gitignore`.

## 2. Propose, in one diff

- `files`: an allowlist of build output only (for example `["dist"]`), replacing a `.npmignore` blocklist, because a blocklist misses whatever is new.
- `main`, `module`, `types`, `exports`, `bin` all point inside that allowlist.
- Source maps off in the build (`sourcemap: false`, `--sourcemap=none`, `"sourceMap": false` for the emitted JS). If the user wants maps for an error tracker, emit them with `sourcesContent: false`, keep them out of `files`, and upload them privately.
- `"prepack": "npm run build"` when a build script exists, so every pack is fresh.
- `.shipsafe/` in `.gitignore`, the directory tarballs are packed into.
- A `"shipsafe"` block only for a finding that is genuinely intended, each `allow` entry with a `reason`. An exception is never a way to make the gate pass.

## 3. First gate

```sh
npm pack --pack-destination .shipsafe
node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" check .shipsafe/<name>-<version>.tgz
```

Report findings grouped by rule with the fix for each, and repeat until it passes or the user accepts an exception.

## 4. CI (offer; write it only when asked)

Show the step that gates the same file CI publishes. It needs the CLI in the project's `devDependencies` at an exact version (`npm install --save-dev --save-exact @cyberinecore/shipsafe`), so `npm ci` installs the reviewed version from the lockfile:

```sh
npm ci
npm pack --pack-destination out
node_modules/.bin/shipsafe check out/<name>-<version>.tgz
npm publish out/<name>-<version>.tgz --provenance --access public
```

Publish the file the gate checked, not the working tree.
