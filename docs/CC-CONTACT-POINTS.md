# Claude Code contact points

Every place where this plugin depends on Claude Code behaviour. `cc-plugin-compat` judges each Claude Code release against this list, so add a row whenever the plugin starts using a new hook, output key, manifest key, component or loading rule. Plugins cannot declare a minimum Claude Code version (no `engines` key; anthropics/claude-code#17272 was closed as not planned), so record in "Needs CC" the version a feature first needs, as the docs state it.

| Contact point | Where in this repo | Needs CC | Breaks if Claude Code changes |
|---|---|---|---|
| hooks.json shape: top-level `"hooks"` wrapper | hooks/hooks.json | | the plugin's hooks stop loading |
| `PreToolUse` hook, matcher `Bash`, 26 entries sharing one script | hooks/hooks.json | | the hook stops firing, or fires on other tools |
| `if` filter `Bash(<glob>)` with `*` wildcards on the command text, 26 patterns (`*publish*`, `*docker*push*`, `*wrangler*deploy*`, `np`, `* np *`, ...) | hooks/hooks.json | 2.1.85 | a filter stops matching, or glob semantics change (substring vs anchored, quoting, compound commands) |
| Exec form `command: "node"` + `args: ["${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs", "hook"]` | hooks/hooks.json | 2.1.139 | the hook fails to spawn; on older CC the hook silently never runs |
| `timeout: 300` per entry | hooks/hooks.json | | a slow gate (large tarball, registry fetch) is cut off before it answers |
| Hook input fields `tool_name`, `tool_input.command`, `tool_use_id`, `cwd` (JSON on stdin) | cli/shipsafe.mjs `runHook` | | wrong command text, wrong base dir for relative paths, or no dedupe |
| Hook output `hookSpecificOutput` with `hookEventName: "PreToolUse"`, `permissionDecision: "ask"`, `permissionDecisionReason`; exit 0 with JSON on stdout; silent exit 0 means no opinion | cli/shipsafe.mjs `runHook` | | the ask is ignored, reinterpreted as deny, or a silent exit is treated as an error |
| `ask` still stops the command under `bypassPermissions` and under `--allowedTools`; a non-interactive session has no one to answer, so the command does not run (measured 2026-09-27) | README.md, cli/shipsafe.mjs | | a publish runs unreviewed under bypass or headless |
| Several entries can match one call: dedupe by `tool_use_id` via a marker file in `tmpdir()` (24h sweep) | cli/shipsafe.mjs `claimToolUse` | | `tool_use_id` missing, reused across calls, or CC itself dedupes entries so the marker blocks a later legitimate run |
| Fail-soft on hook error: a hook that cannot start (no `node` on PATH, exit 1) lets the command through; `onFailure` left at its default | hooks/hooks.json, README.md | | the default `onFailure` flips to block, or an exit-1 hook starts blocking |
| `${CLAUDE_PLUGIN_ROOT}` substitution inside `args` | hooks/hooks.json | | the script is not found |
| Skill loading: `check`, `help`, `incident`, `init`, `release`, `verify`, namespaced as `cyberine-releaseguard:<name>`; `disable-model-invocation: true` + `user-invocable: true` on check, incident, init, verify; help and release model-invocable | skills/*/SKILL.md | | a skill is not listed, invocable by the model when it should not be, or the namespace prefix changes |
| Manifest keys: `$schema`, `name`, `version`, `description`, `author`, `homepage`, `repository`, `privacyPolicyUrl`, `license`, `keywords`, `displayName` | .claude-plugin/plugin.json | | install or `plugin validate --strict` fails on an unrecognized key |
| Marketplace entry `source: "./"`, `category: "security"`, `owner` | .claude-plugin/marketplace.json | | install fails |
| `node` (18+) on PATH, no plugin `bin/` | hooks/hooks.json, cli/shipsafe.mjs | | the hook errors and Claude Code carries on without it |
| README install lines (`claude plugin marketplace add`, `claude plugin install`) | README.md | | `plugin validate` advice only, never an exit-code change |
| `claude plugin validate <path> --strict` as a CI gate, pinned to `@anthropic-ai/claude-code@2.1.283` | .github/workflows/ci.yml | | CI fails on a new strict rule, or the pin drifts from what users run |
| Live hook check `claude -p --plugin-dir . --allowedTools "Bash(npm publish *)"`: depends on one-plugin-per-name loading and on `ask` under `--allowedTools` | .claude/CLAUDE.md | | the check exercises the marketplace-installed copy instead of the working tree, or the ask no longer stops the command |
| Hook handler `type: "command"` with `command` and `args` keys | hooks/hooks.json | 2.1.139 | the handler type or key names change |
| Commands typed with the `!` prefix do not fire PreToolUse hooks; the release skill relies on it | skills/release/SKILL.md | | a `!` command starts firing the hook, or stops bypassing it |
| `${CLAUDE_PLUGIN_ROOT}` substitution inside skill markdown text | skills/release/SKILL.md | | the path reaches the model unexpanded |
| Plugin id form `<plugin>@<marketplace>` and the one-plugin-per-name rule | README.md | | install lines stop resolving, or a same-named copy silences the hooks |
| marketplace.json keys `$schema`, `name`, `description`, `plugins[].name`, `plugins[].description` | .claude-plugin/marketplace.json | | `plugin validate --strict` fails on an unrecognized key |
| Skill frontmatter `name` and `description` as auto-trigger wording for the model-invocable skills `help` and `release` | skills/help/SKILL.md, skills/release/SKILL.md | | the skills stop triggering, or trigger too often |

Last verified: 2.1.296 (Claude Code), 2026-10-11
