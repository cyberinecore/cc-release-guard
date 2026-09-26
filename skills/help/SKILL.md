---
name: help
description: This skill should be used when the request names shipsafe but not which `/shipsafe:*` command answers it - "shipsafe lam duoc gi", "which shipsafe command", "shipsafe co command nao", "dung shipsafe the nao", "how do I use shipsafe". Routes to the one skill that answers it (release, init, check, verify). Never fires without a shipsafe anchor - a bare "publish" goes to /shipsafe:release directly.
---

# shipsafe help

Pick the one command that answers the request, say why in one line, then follow that skill. Ask one question only when two commands tie.

| The user wants to | Command |
|---|---|
| Publish or release an npm package now | `/shipsafe:release` |
| Set a repo up so its releases are safe (files allowlist, no source maps, prepack build, CI gate) | `/shipsafe:init` |
| Know whether a package would leak, without publishing | `/shipsafe:check` |
| Prove a finished publish shipped exactly the checked tarball | `/shipsafe:verify` |

Always on, no command: the PreToolUse hook. Whenever Claude runs `npm`, `pnpm`, `bun` or `yarn` publish, it denies a publish that does not name a `.tgz`, re-runs the gate on the named tarball and denies it on any finding, denies publishes whose flags contradict the packed metadata (scoped without `--access`, registry mismatch, prerelease to `latest`), and always denies `yarn npm publish` and release orchestrators that publish on their own (`lerna`, `changeset`, `semantic-release`, `release-it`, `np`). It never approves anything, so the normal permission prompt still applies to a clean publish. It cannot see publishes inside `npm run <script>`, scripts, or terminals outside Claude Code; the CI gate covers those.

The CLI outside Claude Code: `npx @cyberinecore/shipsafe check <file.tgz>... [--json]` (the installed command is `shipsafe`) (exit 0 pass, 1 findings, 2 usage or config error) and `shipsafe verify <file.tgz>` after a publish. Configuration lives in the packed `package.json` under `"shipsafe"`.

What shipsafe does not do: make JavaScript unreversable. Say so when the user asks for "protection"; secret logic belongs on a server.
