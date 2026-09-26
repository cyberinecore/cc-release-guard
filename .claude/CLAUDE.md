# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`shipsafe`: a Claude Code plugin plus a standalone npm CLI that stop npm packages from shipping source by accident (source maps, `sourcesContent`, TypeScript sources, `src/`/test paths, credential files, oversized files, storage-bucket URLs). It prevents accidental leaks; it does not make JS unreversable, and docs must never claim otherwise. npm only for now; PyPI and crates are planned.

## Commands

- All tests: `npm test` (runs `node --test tests/*.test.mjs`; `node --test tests/` fails because Node treats the dir as a module).
- One test: `node --test --test-name-pattern "inline and remote" tests/gate.test.mjs`
- Gate a tarball: `node cli/shipsafe.mjs check <file.tgz>... [--json]` (exit 0 all pass, 1 any findings, 2 any usage/config error; `--json` gives an array for several files).
- Dogfood the CLI package: `cd cli && npm pack --pack-destination /tmp && node shipsafe.mjs check /tmp/cyberinecore-shipsafe-<version>.tgz` must PASS.
- Validate the plugin: `claude plugin validate . --strict` and `claude plugin validate .claude-plugin/plugin.json --strict` (neither parses skill frontmatter). This file sits in `.claude/` because a root `CLAUDE.md` makes the strict plugin validation fail.
- Live hook check: `echo "<prompt>" | claude -p --model haiku --plugin-dir . --allowedTools "Bash(npm publish *)"` from a temp dir holding a `"private": true` package and `--registry http://127.0.0.1:9`, so a hook failure still cannot publish. Pass the prompt on stdin: `--allowedTools` is variadic and swallows a positional prompt.

No build step and no dependencies: the CLI is one plain ESM file for Node 18+.

## Architecture

The repo root is simultaneously the plugin root and a single-plugin marketplace (`.claude-plugin/marketplace.json` with `source: "./"`). The npm package is the `cli/` subdirectory only; the root `package.json` is `private` and exists for `npm test`.

`cli/shipsafe.mjs` is the single source of truth for both consumers:

- `check` mode is what CI and humans run.
- `hook` mode is what `hooks/hooks.json` runs (exec form: `node ${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs hook`). It reads the PreToolUse JSON on stdin, finds publish invocations in the Bash command, and re-runs the same `checkTarball()` on the named `.tgz`. It only ever emits `ask` or nothing: it never blocks (user decision 2026-09-27: the plugin suggests, the user decides) and never returns `allow`, so normal permission prompts still apply to a clean publish.

Key design decisions (do not reverse without the user):

- Naming: brand, plugin and marketplace are `shipsafe`; the npm package is `@cyberinecore/shipsafe` (bin `shipsafe`). Every executable reference (npm scope, GitHub repo, marketplace, Action) uses the one handle `cyberinecore`, because the GitHub name `cyberine` belongs to someone else and a `@cyberine` npm scope would invite users to guess `github.com/cyberine/...`. Docs always spell out full install commands.
- No receipts/hash cache: the hook re-scans the exact tarball at publish time, so nothing can be forged or go stale.
- `check-dir` (static-site output) reads config from the nearest `package.json` at or above the directory, not from a file inside it, so nothing extra deploys to the CDN. It applies only the leak rules in `DIR_RULES`.
- Config lives in the PACKED `package.json` under `shipsafe` (`maxFileBytes`, `allow[]` with mandatory `reason`), so CI and the hook judge the same artifact identically. There are deliberately no CLI flags that change rules.
- `yarn npm publish` always triggers an ask (it cannot publish a prebuilt tarball); `--dry-run` publishes pass; a publish with no `.tgz` argument triggers an ask.
- Content rules are written so the gate's own source does not trip them (`sourcesContent` must be followed by `:`; inline maps need `data:<letter>`). Keep that property when adding rules, or the dogfood check fails.
- The `if` filters in `hooks/hooks.json` (`Bash(*publish*)`, plus `semantic-release`, `release-it` and `np` shapes, which carry no `publish` word) only limit when the hook spawns; exact detection happens in `findPublishes()` (shell-ish tokenizer, `cd` tracking, wrapper/env stripping, value-taking option skipping, recursion into `sh|bash|zsh -c`, `eval`, package runners `npx`/`bunx`/`corepack`/`<pm> exec|dlx|x`, and `xargs`/`find -exec`, whose tarball is unknowable and so always asked about). A leading `*` is required: `Bash(npm*publish*)` never spawns for `npx npm publish`. Claude Code's `if` matching is best-effort, and publishes hidden in `npm run <script>` are out of reach by design.

Archive parsing is hand-written to stay zero-dependency: tar (gzip via `node:zlib`, ustar + pax + GNU longname; entries rooted by stripping the first path segment, `package/`) and zip (central directory, stored + deflate via `inflateRawSync`; `.vsix` rooted at `extension/`). `openTarball()` returns a `kind` (`npm`, `vsix`, `webext`, `generic`) and `KIND_RULES` limits which rules apply to each. The zip reader is meant to be reused for PyPI wheels.

## Plugin constraints

- No top-level `bin/`: claude.ai and Cowork refuse a plugin that has one. The CLI lives in `cli/`.
- `plugin.json` pins `version`; bump it on every release, together with `cli/package.json` and `VERSION` in `cli/shipsafe.mjs`.
- Skills are `release` (model-invocable; auto-triggers on publish intent), `init`, `check`, `verify`, `incident` (slash-only) and `help` (router, fires only with a shipsafe anchor), following the Cyberine ecosystem convention of `/<brand>:<verb>`. The `release` skill stops before the publish command: the human runs it and types the OTP. Never add token storage or reading of token values.
- Tests build real fixtures with `npm pack` in a temp dir; keep them that way rather than hand-crafting tar bytes.
