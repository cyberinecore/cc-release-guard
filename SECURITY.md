# Security policy

shipsafe is a release gate, so an artifact that leaks source or a secret and still passes the gate is a security bug.

## Reporting

Report privately through GitHub's "Report a vulnerability" button on https://github.com/cyberinecore/cc-release-guard/security, or by email to xinchao@nghia-pham.com. Please include the shipsafe version, the command or artifact involved (a minimal reproduction without real secrets), what shipsafe reported and what you expected. Do not open a public issue for a bypass until a fix is released.

## Scope

In scope: a packed artifact carrying a source map, `sourcesContent`, a credential file or a token that `check` or `check-dir` passes; a publish command the hook should have asked about under the README's rules and did not; a crafted archive that crashes the parser, makes it read outside the archive, or hides an entry from the rules; and any finding output that prints a secret value.

Out of scope, documented as limits in the README: publishes hidden inside `npm run <script>` or other scripts, Claude Code's best-effort `if` matching, a missing `node`, a hook timeout, and making JavaScript unreversable, which shipsafe does not claim.
