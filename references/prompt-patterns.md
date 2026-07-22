# Prompt Patterns

Use these patterns when the user asks for a specific kind of grilling.

## Plan Grilling

```text
Use $grill-me-code at deep depth on this implementation plan.
Do not edit files yet. Return blockers, warnings, questions, and missing verification.
```

## Diff Review

```text
Use $grill-me-code to review the current git diff at standard depth.
Focus on correctness, tests, security, and rollout risk.
```

## Refactor Review

```text
Use $grill-me-code to grill this refactor.
Prove behavior is preserved, identify contract changes, and list tests that must pass.
```

## Fix Loop

```text
Use $grill-me-code to review and fix the current diff.
Apply narrow fixes, run project checks, then re-grill the changed surface.
```

## Release Gate

```text
Use $grill-me-code at deep depth as a release gate.
Check migrations, config, auth, rollback, observability, tests, and user-impacting edge cases.
```

## Output Contract

For review-only:

```markdown
## ISSUES FOUND

### Blocker
- ...

### Warning
- ...

### Question
- ...

### Nit
- ...
```

For clean results:

```markdown
## GRILLING COMPLETE

No blockers found. Remaining risk: ...
Verification checked: ...
```
