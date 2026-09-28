---
name: check
description: This skill should be used when the user wants to know whether a package, archive or build output would leak source or secrets without publishing or deploying it - "/cyberine-releaseguard:check", "check tarball", "check dist", "kiem tra truoc khi publish", "co lo source khong", "package nay co ship src khong", "scan this .tgz", "what would ship if I published". Packs the real tarball (or takes a given file or build directory), runs the shipsafe gate, and explains each finding with its fix.
disable-model-invocation: true
user-invocable: true
---

# shipsafe check

Read-only on the user's intent: this skill never publishes and never edits the repo unless the user asks for a fix.

1. Target: a directory the user names (a static build output such as `dist/` or `build/`) is gated with `node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" check-dir <dir> --json`, never with `check`; build first if it is missing, then skip to step 3. A file the user names (`.tgz`, `.vsix`, `.whl`, `.crate`, `.nupkg`, `.gem`, `.asar`, a `docker save` `.tar`, a Helm chart `.tgz`) is gated as is. Otherwise pack a tarball: use the `.tgz` the user named. Otherwise pack one from the package directory: `npm pack --pack-destination .local/release` (make sure `.local/` is gitignored). `npm pack --dry-run` is not a substitute: it skips `prepack`/`prepublishOnly` and can list a different file set.
2. Gate it: `node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" check <file> --json`. Do not replace the gate with hand-written `find`/`grep` scans: if the CLI errors, report the error.
3. Report: PASS or FAIL first, then findings grouped by rule, each with the file path and the build-side fix (turn maps off, tighten `files`, move a credential out of the package directory). Mention unused-exception warnings.
4. An intended finding gets an exception in the packed `package.json` only when the user agrees, shown to them first:

```json
"shipsafe": { "allow": [{ "rule": "bucket-url", "path": "dist/*.js", "reason": "documented public download bucket" }] }
```

Fix the build, not the gate. To publish after a PASS, hand over to `/cyberine-releaseguard:release`.
