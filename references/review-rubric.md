# Review Rubric

Use this when `grill-me-code` is asked to review code, diffs, PRs, repos, implementation plans, or release readiness.

## Depth

`quick`:
- scan explicit files or diff for obvious blockers
- check secrets, unsafe shell, eval, path traversal, missing awaits, empty catches, TODO/FIXME in shipped paths
- output only the highest-signal issues

`standard`:
- read every scoped source file
- trace important imports and called helpers
- verify edge cases, error handling, test coverage, and project conventions
- default to this mode

`deep`:
- build a cross-file mental model
- inspect architecture contracts, migrations, state transitions, security boundaries, rollback, and deployment order
- use for large refactors, auth/payment/data flows, public APIs, and risky releases

## Scope Resolution

Use this precedence:

1. User-provided file list, diff, branch, PR, or plan.
2. Current git diff.
3. Recent commits if the user asks for "latest changes".
4. Repo map plus targeted samples if the user asks for full repo review.

Filter out generated files, vendored dependencies, lockfiles, build outputs, and planning artifacts unless the user explicitly asks to inspect them.

In diff or PR-like reviews, distinguish introduced risk from legacy risk. A pre-existing blocker in a changed file should be reported, but it should not be described as introduced by the current diff unless the changed line map proves it.

If the scope is too large, split it:

- changed behavior
- critical paths
- tests
- configuration and deploy
- docs that encode contracts

## Severity

`Blocked`:
- missing files, missing plan/config, inaccessible scope, or unsafe permissions prevent a trustworthy review
- use for setup/configuration failures, not for confirmed bad code

`Blocker`:
- wrong behavior
- crash, data loss, security exposure, auth bypass
- unsafe production operation
- migration or deploy risk without rollback
- tests missing for a critical new behavior

`Warning`:
- likely bug in edge cases
- weak error handling
- brittle contract or hidden coupling
- test is shallow, flaky, or does not assert the real behavior
- maintainability issue that will slow future work

`Question`:
- domain requirement is ambiguous
- tradeoff depends on user preference
- external system behavior needs confirmation

`Nit`:
- polish, naming, small consistency issue
- never bury blockers under nits

Config/setup failures should usually produce `BLOCKED`. Confirmed code hazards should produce `DO NOT SHIP`.

## Finding Shape

Each serious finding should include:

```markdown
### Blocker: short title

File: `path/to/file.ext:42`
Why it matters: behavior or risk.
Evidence: concrete code path, missing check, or failed command.
Fix: specific change or test.
```

## Grilling Questions

Ask questions that change implementation quality:

- What invariant must never break here?
- What input makes this branch lie?
- What happens when the dependency times out, returns partial data, or changes shape?
- What proves this is wired into the real user path?
- What fails safely?
- What is the rollback if this migration or deploy goes sideways?
- Which test would have failed before this fix?
- What unrelated existing behavior could this refactor break?
- What secret, ID, path, or account-specific detail could leak?
