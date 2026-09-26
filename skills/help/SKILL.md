---
name: help
description: This skill should be used when the request names shipsafe but not which `/shipsafe:*` command answers it - "shipsafe lam duoc gi", "which shipsafe command", "shipsafe co command nao", "dung shipsafe the nao", "how do I use shipsafe". Routes to the one skill that answers it (release, init, check, verify, incident). Never fires without a shipsafe anchor - a bare "publish" goes to /shipsafe:release directly.
---

# shipsafe help

Pick the one command that answers the request, say why in one line, then follow that skill. Ask one question only when two commands tie.

| The user wants to | Command |
|---|---|
| Publish or release an npm package now | `/shipsafe:release` |
| Set a repo up so its releases are safe (files allowlist, no source maps, prepack build, CI gate) | `/shipsafe:init` |
| Know whether a package would leak, without publishing | `/shipsafe:check` |
| Prove a finished publish shipped exactly the checked tarball | `/shipsafe:verify` |
| Respond to a leak already on npm (scan published versions, rotate, unpublish or deprecate) | `/shipsafe:incident` |

Always on, no command: the PreToolUse hook. Whenever Claude runs `npm`, `pnpm`, `bun` or `yarn` publish, it never blocks: when a command looks wrong it asks the user, showing the reason and the fix. It asks about a publish that does not name a `.tgz`, a tarball that fails the gate, flags that contradict the packed metadata (scoped without `--access`, registry mismatch, prerelease to `latest`), `yarn npm publish`, release orchestrators that publish on their own (`lerna`, `changeset`, `semantic-release`, `release-it`, `np`), and deploys or uploads whose output fails. A clean command passes through the normal permission prompt unchanged. It cannot see publishes inside `npm run <script>`, scripts, or terminals outside Claude Code; the CI gate covers those.

The CLI outside Claude Code: `npx @cyberinecore/shipsafe check <file.tgz>... [--json]` (the installed command is `shipsafe`) (exit 0 pass, 1 findings, 2 usage or config error) and `shipsafe verify <file.tgz>` after a publish. Configuration lives in the packed `package.json` under `"shipsafe"`.

Beyond npm, `check` reads `.vsix`, Electron `.asar`, browser-extension `.zip`, `.nupkg`, `.jar`, `.gem`, Python wheels and sdists, `.crate` files and `docker save` images, and the hook also covers static deploys, `gh release`, NuGet, RubyGems, Maven `deploy-file`, Expo `eas update`, and Python and Rust uploads (`twine`, `uv publish`, `poetry`, `hatch`, `pdm`, `flit`, `maturin`, `cargo publish`). `/shipsafe:release` walks the npm procedure; for the others, gate the built file with `shipsafe check` before uploading it.

What shipsafe does not do: make JavaScript unreversable. Say so when the user asks for "protection"; secret logic belongs on a server.
