---
session_id: sample
mode: scope
depth: standard
verdict: DO NOT SHIP
risk_score: 62
proof_score: 40
ship_score: 28
---

# CODE-GRILL-REPORT

## Verdict

Decision: **DO NOT SHIP**
Risk score: **62/100** (high)
Introduced risk: **42/100**
Legacy risk: **20/100**
Legacy risk level: **low**
Total risk: **62/100**
Proof score: **40/100** (weak)
Ship score: **28/100**

### Verdict Reasons

- 1 introduced/scope blocker finding(s)
- 1 failed check(s)

## Scope

Files reviewed: 2
- `src/config.ts`
- `src/config.test.ts`

## Scan Limits

Skipped files: 1
- `fixtures/large-snapshot.json` (6500000 bytes > 2000000)

## Diff Awareness

Diff-aware scoring: `true`
Diff filter: `worktree`
Changed-line files: 2
Introduced findings: 2
Legacy findings: 1

## Cache

Enabled: `true`
Path: `.grill-me-code/cache.json`
Hits: 4
Misses: 2

## Configuration

Config: `.grill-me-code.yaml`
Minimalism mode: `full`
Baseline: `.grill-me-code/baseline.json`
Suppressed findings: 1

## Test Proof

Test files: 0
Assertions found: 0
Trivial assertions: 0

## Findings

### Blocker: SEC-001-001 - Possible hardcoded secret

Source: `builtin-static`
Diff status: `introduced`
Location: `src/config.ts:12`
Evidence: `apiToken = "live-token-value"`

### Warning: TEST-PROOF-001 - No test files are included in the reviewed scope

Source: `test-aware-verification`
Diff status: `scope`
Location: n/a
Evidence: n/a

### Question: MIN-001-001 - Dependency may be replaceable by native or stdlib code.

Source: `minimalism`
Diff status: `scope`
Location: `package.json:18`
Evidence: `moment in dependencies; native: Intl.DateTimeFormat or Date for simple formatting/parsing.`

## Suppressed Findings

- `BUG-002-003` Unresolved implementation marker in reviewed scope. (baseline) at `src/config.ts:22`

## Checks

- **FAIL** `npm run test`
  - kind: `test`
  - timed out: `False`

## Session Delta

Old session: `previous`
New session: `sample`
Old verdict: **SHIP WITH RISKS**
New verdict: **DO NOT SHIP**
Added findings: 1
Resolved findings: 0
Persisting findings: 2

### Added

- `SEC-001-001` blocker Possible hardcoded secret at `src/config.ts:12`

## Reasoning Plugins

### llm-reviewer

Status: **PASS**
Structured verdict: **DO NOT SHIP**
Confidence: `0.78`

#### Summary

The blocker is real unless the token source is replaced with environment-backed configuration.

#### Questions

- Which assertion proves the config source is no longer hardcoded?

```text
The blocker is real unless the token source is replaced with environment-backed configuration.
```

## Jury Scores

### Security

Verdict: **DO NOT SHIP**
Risk score: **30/100**
Findings: 1
Failed checks: 0

### Tester

Verdict: **DO NOT SHIP**
Risk score: **32/100**
Findings: 1
Failed checks: 1

### Minimalist

Verdict: **SHIP**
Risk score: **5/100**
Findings: 1
Failed checks: 0

## Machine Marker

## ISSUES FOUND
