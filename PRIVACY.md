# Privacy policy

shipsafe is a Claude Code plugin and a CLI that run only on your computer. This policy covers the plugin and the npm package `@cyberinecore/shipsafe` as published from https://github.com/cyberinecore/cc-release-guard.

## What it collects

Nothing. shipsafe has no telemetry and sends no data to its author, to Anthropic, or to anyone else.

## Network use

- The PreToolUse hook, `check` and `check-dir` make no network requests.
- `verify`, `diff` (against a registry version) and `audit` contact only the registry the command targets (the npm registry or the one set by `publishConfig.registry`/`--registry`, PyPI, or the crates.io index). They send a package name and version and download public metadata and tarballs. They run only when you or a skill you started invoke them.

## What it reads locally

To judge a publish or deploy, shipsafe reads, on your machine only: the Bash command Claude Code hands to the hook, the archive or build directory that command names, the packed `package.json`, `pyproject.toml` or `Cargo.toml`, the nearest on-disk `package.json` or `pyproject.toml` that configures an artifact, deploy config files that name an output directory (`wrangler.toml`/`wrangler.json`/`wrangler.jsonc`, `netlify.toml`, `firebase.json`, `.vercel/output`), and the nearest `.claude/shipsafe.json`. It never reads your conversation, Claude's memory, environment variables, registry tokens or OTPs.

## What it stores locally, and for how long

The hook writes one empty marker file per tool call (`shipsafe-hook-<tool_use_id>`) in the OS temp directory, so that overlapping hook filters answer only once. Markers older than a day are removed on the next run. Nothing else is stored.

## Children

shipsafe is a developer tool and is not directed at children under 18.

## Contact

Questions or concerns: open an issue at https://github.com/cyberinecore/cc-release-guard/issues or email xinchao@nghia-pham.com. Security reports: see `SECURITY.md`.

## Changes

Changes to this policy are published in this file in the repository, with the history kept by git.
