# Changelog

All notable changes to shipsafe. Versions follow `version` in `.claude-plugin/plugin.json`, which always equals `cli/package.json` and `VERSION` in `cli/shipsafe.mjs`.

## [0.1.0] - Unreleased

- `shipsafe check` gates npm tarballs, `.vsix`, browser-extension zips, Electron `.asar`, wheels, sdists, crates, `.nupkg`, `.jar`, `.gem`, Helm charts and container image archives; `check-dir` gates static-site output. Output as text, JSON, SARIF 2.1.0 or markdown.
- `shipsafe diff` and `shipsafe audit` compare against and scan published registry versions.
- PreToolUse hook that asks before an unchecked or failing publish, upload or deploy (npm, pnpm, yarn, bun, semantic-release, release-it, np, twine, uv, cargo, helm, wrangler, vercel, netlify, firebase, and opt-in docker push); it never blocks and never auto-allows.
- Skills `/shipsafe:release`, `/shipsafe:init`, `/shipsafe:check`, `/shipsafe:verify`, `/shipsafe:incident` and `/shipsafe:help`.
- GitHub Action (`action.yml`) that packs and gates in CI.
