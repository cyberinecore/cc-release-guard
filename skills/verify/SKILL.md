---
name: verify
description: Use after an npm publish to prove the registry holds exactly the tarball that was checked. Compares the registry's dist.integrity for name@version with the local .tgz and runs a no-scripts install smoke test.
disable-model-invocation: true
user-invocable: true
---

# shipsafe verify

Read-only: this skill does not publish, log in or read a token. Public packages need no auth.

1. Tarball: the `.tgz` that passed `shipsafe check` and was published, by its path (the release skill packs into `.shipsafe/`). A re-pack is not the same file: its bytes, and so its integrity, differ.
2. Verify: `node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" verify <file.tgz> --json`. It reads name@version from the tarball, fetches the packument from `publishConfig.registry` (or `--registry <url>`, else the npm registry) and compares `versions[v].dist.integrity` with the file's sha512. Exit 0 = the registry holds exactly this file; 1 = not published or a different file; 2 = registry unreachable or a usage error. A new package or version can take several minutes to appear in the registry's public reads, so keep retrying for a few minutes before reporting 1 as "not published".
3. Smoke-test the published package without running its scripts, using the local tarball that step 2 proved byte-identical to the published one, so nothing is fetched from the registry: in a new scratch directory run `npm init -y`, then `npm install --ignore-scripts /abs/path/<name>-<version>.tgz`, then write a `smoke.mjs` holding `import '<name>';` and run `node smoke.mjs`. For a CLI, run its `bin` with `--version` from `node_modules/.bin/`. `--ignore-scripts` stays on, because an install script would run the package's own code on this machine.
4. Report MATCH or FAIL first. A FAIL with "different file" is an incident: something other than the checked tarball was published, so find what published it (a CI job, another machine) before anything else.
