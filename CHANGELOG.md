# Changelog

All notable changes to shipsafe. Versions follow `version` in `.claude-plugin/plugin.json`, which always equals `cli/package.json` and `VERSION` in `cli/shipsafe.mjs`.

## [0.2.0] - 2026-10-12

- The hook looks inside script wrappers: `npm|pnpm|yarn|bun run <script>` (with `pre`/`post` scripts and the `prepublishOnly`...`postpublish` chain of a working-tree publish) and `make <target>` (with `-C`, `-f`, `$(VAR)` and one `$(MAKE)` level); the ask is prefixed `via npm run <script>` or `via make <target>`. One nested level is followed. The new `if` filters match only scripts and targets named with `release`, `publish`, `deploy` or `ship`, so `npm run build` never spawns the hook.
- Bucket and server uploads gate their local source directory like `check-dir`: `aws s3 sync|cp`, `gsutil rsync|cp`, `gcloud storage rsync|cp`, `az storage blob upload-batch|sync`, `azcopy copy|sync`, `rclone sync|copy`, `rsync` and `scp -r` to a remote. Downloads, bucket-to-bucket copies, single files and local destinations pass.
- New asks for publishes without a checkable artifact: `jsr publish` and `deno publish` (working directory, leak rules only, `.gitignore` and `publish.exclude` honored), `vsce publish` and `ovsx publish` (gated when `--packagePath` names a `.vsix`), `vercel` without `--prebuilt`, `fly deploy`, `railway up`, `gcloud run deploy --source`, `gcloud app|functions deploy`, `sam deploy`, `cdk deploy`, `serverless|sls deploy`, `goreleaser release`, `mvn deploy`, `gradle publish*`.
- Opt-in `askOnTagPush` in `.claude/shipsafe.json`: asks before `git push --tags`, `--follow-tags`, and a pushed tag that a `.github/workflows` file runs `on: push: tags` for.
- `sensitive-file` also matches `.dev.vars*`, `*.tfstate`, `*.tfstate.backup`, `*.tfvars`, `kubeconfig`, `.kube/config`, `.docker/config.json`, `.ssh/`, `.mcp.json` and `.claude/settings.local.json`. New rule `data-file` for `*.sqlite`, `*.sqlite3`, `*.db`, `*.dump` and `.sql` files that hold rows, so fixtures can be allowed with a reason.
- `secret-token` also matches GitLab `glpat-` tokens, SendGrid `SG.` keys and Azure storage `AccountKey=` values, formats confirmed against the vendors' documentation; placeholders and `EXAMPLE` suffixes are skipped as before. Hugging Face `hf_` and Google `GOCSPX-` were not added: neither vendor documents the token length.
- `tests/coverage-probe.test.mjs`: 157 real publish, deploy and must-stay-silent commands, each also checked against the `if` filters in `hooks/hooks.json`.

## [0.1.0] - 2026-09-28

- `shipsafe check` gates npm tarballs, `.vsix`, browser-extension zips, Electron `.asar`, wheels, sdists, crates, `.nupkg`, `.jar`, `.gem`, Helm charts and container image archives; `check-dir` gates static-site output. Output as text, JSON, SARIF 2.1.0 or markdown.
- `shipsafe diff` and `shipsafe audit` compare against and scan published registry versions.
- PreToolUse hook that asks before an unchecked or failing publish, upload or deploy (npm, pnpm, yarn, bun, semantic-release, release-it, np, twine, uv, cargo, helm, wrangler, vercel, netlify, firebase, and opt-in docker push); it never blocks and never auto-allows.
- Skills `/cyberine-releaseguard:release`, `/cyberine-releaseguard:init`, `/cyberine-releaseguard:check`, `/cyberine-releaseguard:verify`, `/cyberine-releaseguard:incident` and `/cyberine-releaseguard:help`.
- GitHub Action (`action.yml`) that packs and gates in CI.
- The Claude Code plugin and marketplace are named `cyberine-releaseguard` (display name Cyberine ReleaseGuard), so skills live under `/cyberine-releaseguard:*`; the npm package `@cyberinecore/shipsafe` and the `shipsafe` command keep their names.
