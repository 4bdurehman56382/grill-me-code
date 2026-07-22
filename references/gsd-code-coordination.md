# GSD Code Coordination

This file imports the useful coordination patterns from the local GSD workflow without depending on Claude-only commands or vendoring the full GSD repository.

## GSD Patterns To Use

Scope with explicit precedence:

1. user-specified files or diff
2. structured artifact file list, such as REVIEW.md or SUMMARY.md
3. git diff fallback
4. repo-wide sampling only when requested

Review before fixing:

- produce findings first
- classify severity
- keep exact file scope
- only auto-fix after the user asks for implementation or the request clearly includes it

Fix with bounded iteration:

- apply fixes in small groups
- verify after each group
- re-review the same scope
- cap auto-loops at three passes before escalating

Verify goal achievement, not task completion:

- identify observable truths
- identify required artifacts
- verify key wiring
- run tests that prove behavior
- record human checks that remain

## Coordination Markers

Use these final H2 markers when useful for downstream agents:

- `## GRILLING COMPLETE`
- `## ISSUES FOUND`
- `## FIX LOOP COMPLETE`
- `## BLOCKED`

If producing an artifact, use a stable file name:

- `CODE-GRILL-REVIEW.md`
- `CODE-GRILL-FIX.md`
- `CODE-GRILL-VERIFY.md`

## Artifact Frontmatter

For `CODE-GRILL-REVIEW.md`:

```yaml
---
status: clean | issues_found | skipped
depth: quick | standard | deep
files_reviewed: 0
findings:
  blocker: 0
  warning: 0
  question: 0
  nit: 0
  total: 0
---
```

For `CODE-GRILL-FIX.md`:

```yaml
---
status: all_fixed | partial | none_fixed
iterations: 1
fixed: 0
skipped: 0
verification:
  passed: 0
  failed: 0
---
```

For `CODE-GRILL-VERIFY.md`:

```yaml
---
status: passed | gaps_found | human_needed
score: 0/0
---
```

## Subagent Coordination

When using subagents or parallel reviewers:

- give each one an explicit scope and output contract
- do not keep editing the same files while a fixer subagent is active
- wait for the result, then verify on the main thread
- merge findings by severity and evidence
- never let multiple agents apply overlapping fixes without a coordinator

## GSD-Inspired Review Commands

Use these as conceptual modes, not required slash commands:

- `review`: scoped adversarial review
- `fix`: apply verified fixes to review findings
- `verify`: goal-backward proof that behavior works
- `converge`: repeat review and fix until blockers are gone or iteration cap is hit
