<!-- nf-rulegen:scaffold name=push-gates by=nf-vibe-coding tpl=1 sha=61e37135011b68fd3e85ccf3b98e75344a82a600877f4f91a0582a938cc2fd07 -->
# Push gates

Project facts that gate auto-commit / push, filled by hand. A re-run appends missing sections and never overwrites an edited one. The `:section` comment is the section's identity — keep it, rename the heading freely. Empty means nothing beyond the rules already loaded, not nothing exists.

## Protected branches
<!-- nf:section protected-branches -->

One branch per bullet.

- The remote's default branch, read live with `git ls-remote --symref origin HEAD`.

## Preconditions
<!-- nf:section preconditions -->

Commands that must pass before any push to a protected branch.

## Branch conventions
<!-- nf:section branch-conventions -->

Project-specific naming or flow beyond the global git rule.
