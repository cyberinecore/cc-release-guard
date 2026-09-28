---
name: help
description: Use when the request names Cyberine ReleaseGuard, releaseguard or shipsafe but not which `/cyberine-releaseguard:*` command answers it, such as what the plugin can do or which command fits a task. Routes to the one skill that answers it (release, init, check, verify, incident). Does not fire without a shipsafe or releaseguard anchor; a bare publish request goes to /cyberine-releaseguard:release directly.
---

# shipsafe help

Pick the one command that answers the request, say why in one line, then follow that skill. Ask one question only when two commands tie.

| The user wants to | Command |
|---|---|
| Publish or release an npm package now | `/cyberine-releaseguard:release` |
| Set a repo up so its releases are safe (files allowlist, no source maps, prepack build, CI gate) | `/cyberine-releaseguard:init` |
| Know whether a package, archive or build output (`dist/`) would leak, without publishing or deploying | `/cyberine-releaseguard:check` |
| Prove a finished publish shipped exactly the checked tarball | `/cyberine-releaseguard:verify` |
| Respond to a leak already on npm (scan published versions, rotate, unpublish or deprecate) | `/cyberine-releaseguard:incident` |

Always on, no command: the PreToolUse hook. It never blocks: when a publish, upload or deploy that Claude runs looks wrong, it asks the user, showing the reason and the fix. It asks about a publish that does not name a `.tgz`, a tarball that fails the gate, flags that contradict the packed metadata (scoped without `--access`, registry mismatch, prerelease to `latest`), `yarn npm publish`, release orchestrators that publish on their own (`lerna`, `changeset`, `semantic-release`, `release-it`, `np`), and deploys or uploads whose output fails. A clean command goes through the normal permission prompt unchanged. The hook does not see publishes inside `npm run <script>` or other scripts, commands the user types with the `!` prefix, or terminals outside Claude Code; the CI gate covers those. Static deploys it gates are `wrangler pages deploy`, the static assets of `wrangler deploy` and `wrangler versions upload`, `vercel --prebuilt`, `netlify deploy`, `firebase deploy` and `eas update`; for a deploy wrapped in a package script, run `shipsafe check-dir <assets dir>` before it.

The CLI outside Claude Code is the npm package `@cyberinecore/shipsafe`, added to `devDependencies` at an exact version: `shipsafe check <file.tgz>... [--json]` (exit 0 pass, 1 findings, 2 usage or config error), and `shipsafe verify <file.tgz>` after a publish. Configuration lives in the packed `package.json` under `"shipsafe"`.

Beyond npm, `check` reads `.vsix`, Electron `.asar`, browser-extension `.zip`, `.nupkg`, `.jar`, `.gem`, Python wheels and sdists, `.crate` files, Helm chart `.tgz` files and `docker save` images. The hook also covers static deploys, `gh release`, NuGet, RubyGems, Maven `deploy-file`, `helm push`, `docker push` (only with `askOnDockerPush` set in `.claude/shipsafe.json`), Expo `eas update`, and Python and Rust uploads (`twine`, `uv publish`, `poetry`, `hatch`, `pdm`, `flit`, `maturin`, `cargo publish`). `/cyberine-releaseguard:release` covers the npm procedure; for the others, gate the built file with `shipsafe check` before uploading it.

shipsafe does not make JavaScript unreversable. When the user asks for "protection", say so: secret logic belongs on a server.
