<!-- nf-rulegen:scaffold name=ci by=nf-vibe-coding tpl=1 sha=04b2eb30907b274cefda4c58dc938654312fc9af218e73d74c974c8d96ff2648 -->
# CI/CD facts

Project facts about CI/CD, filled by hand: read the repo's CI config and record what it does — no skill scans it. A re-run appends missing sections and never overwrites an edited one.

## Platform
<!-- nf:section platform -->

- Platform: GitHub Actions
- Config: `.github/workflows/ci.yml` (`npm test` plus the cli/ dogfood check on Node 18, 20 and 22, and strict `claude plugin validate`, on every push and pull request)

## Deploy triggers
<!-- nf:section deploy-triggers -->

Which push lands where.

- None: no push deploys anything. npm publishing stays a manual step.

## Skip CI
<!-- nf:section skip-ci -->

Which skip string actually works on this platform.

- `[skip ci]`
