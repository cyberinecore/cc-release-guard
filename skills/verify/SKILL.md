---
name: verify
description: This skill should be used after an npm publish to prove the registry holds exactly the tarball that was checked - "/cyberine-shipsafe:verify", "verify the publish", "kiem tra ban da publish", "registry co dung file khong", "did the right tarball ship". Compares the registry's dist.integrity for name@version with the local .tgz and runs a no-scripts install smoke test.
disable-model-invocation: true
user-invocable: true
---

# shipsafe verify

Read-only: this skill never publishes, never logs in and never reads a token. Public packages need no auth.

1. Tarball: the `.tgz` that passed `shipsafe check` and was published, by its path (the release skill keeps it under `.local/release/`). A re-pack is not the same file: its bytes, and so its integrity, differ.
2. Verify: `node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" verify <file.tgz> --json`. It reads name@version from the tarball, fetches the packument from `publishConfig.registry` (or `--registry <url>`, else the npm registry) and compares `versions[v].dist.integrity` with the file's sha512. Exit 0 = the registry holds exactly this file; 1 = not published or a different file; 2 = registry unreachable or a usage error. A fresh publish can take a minute to appear; retry once before reporting 1.
3. Smoke-test the published package without running its scripts, in a scratch directory: `cd "$(mktemp -d)" && npm init -y >/dev/null && npm install --ignore-scripts <name>@<version> && node -e "import('<name>').then(() => console.log('import ok'))"`. For a CLI, run its `bin` with `--version` from `node_modules/.bin/`. Never drop `--ignore-scripts`: an install script would execute the package's own code on this machine.
4. Report MATCH or FAIL first. On FAIL with "different file", treat it as an incident: something other than the checked tarball was published; find what published it (CI job, another machine) before anything else.
