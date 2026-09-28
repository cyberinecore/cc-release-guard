---
name: incident
description: This skill should be used when a published npm package may have leaked source or a secret - "/cyberine-releaseguard:incident", "we leaked source on npm", "lo source roi", "published a secret to npm", "token bi lo trong package", "audit published versions", "unpublish a leaked version". Scans published versions with shipsafe audit, separates credential exposure (rotate first) from source exposure, and walks the user through npm's unpublish and deprecate rules without promising removal.
disable-model-invocation: true
user-invocable: true
---

# shipsafe incident

On demand only, never a routine release stage. This skill never logs in, never publishes, unpublishes or deprecates by itself and never reads a token value: every registry-changing command goes to the user with the `!` prefix, because it needs their OTP.

## 1. Find what shipped

`node "${CLAUDE_PLUGIN_ROOT}/cli/shipsafe.mjs" audit <name> --versions <n> --json` downloads the last n published versions (default 5, newest first by publish time), checks each against its `dist.integrity`, and gates it with the same rules as `check`. Exit 1 means at least one version leaks; 2 means a download or registry error. Widen `--versions` until the oldest affected version is found.

## 2. Classify each finding

- **Credential exposure** (`secret-token`, `sensitive-file` such as `.env`, `.npmrc`, keys): assume it was harvested the moment it was public. Rotate or revoke it at the issuing provider FIRST, before any cleanup: removing the package does not un-leak the value, and mirrors and caches (unpkg, jsDelivr, corporate proxies) may keep copies. Then review the provider's access logs for use since the publish time the audit printed.
- **Source exposure** (`source-map`, `sources-content`, `typescript-source`, `source-dir`, `build-artifact`, `bucket-url`): nothing to rotate, but the source must be treated as public from now on. Check the exposed code for embedded credentials, internal hostnames and unreleased feature names, and handle those as credential exposure.

## 3. Stop the next install from getting it

1. Fix the build, pack, `check`, and publish a new patch version through `/cyberine-releaseguard:release`. npm never lets a used `name@version` be published again, even after an unpublish.
2. Point `latest` at the fixed version if it is not already: `! npm dist-tag add <name>@<fixed> latest --otp <code>`.
3. Remove or mark the leaking versions, choosing by npm's unpublish policy (https://docs.npmjs.com/policies/unpublish/), checked at the time of the incident:
   - Within 72 hours of publishing, a version can be unpublished if no other package in the public registry depends on the package.
   - After 72 hours, only if all hold: no dependents in the public registry, fewer than 300 downloads in the last week, and a single owner or maintainer.
   - Unpublishing every version blocks new publishes of that name for 24 hours.
   - If unpublish is allowed: `! npm unpublish <name>@<version> --otp <code>`. If npm refuses, contact npm support; never tell the user removal is guaranteed.
   - Otherwise deprecate: `! npm deprecate <name>@<version> "contains leaked build artifacts, use <fixed>" --otp <code>`. Deprecation only warns: the tarball stays downloadable.
4. Run `shipsafe verify` on the fixed tarball and `audit` again to confirm the newest version is clean.

## 4. Report

List affected versions and their publish dates, what was exposed per class, what was rotated (by name, never by value), which versions were unpublished or deprecated, and what still needs the user (provider rotations, npm support tickets).
