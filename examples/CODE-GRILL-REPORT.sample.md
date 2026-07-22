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
Risk score: **62/100**
Introduced risk: **42/100**
Legacy risk: **20/100**
Total risk: **62/100**
Proof score: **40/100**
Ship score: **28/100**

## Diff Awareness

Diff-aware scoring: `true`
Changed-line files: 2
Introduced findings: 2
Legacy findings: 1

## Configuration

Config: `.grill-me-code.yaml`
Baseline: `.grill-me-code/baseline.json`
Suppressed findings: 1

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

## Suppressed Findings

- `BUG-002-003` Unresolved implementation marker in reviewed scope. (baseline) at `src/config.ts:22`

## Checks

- **FAIL** `npm run test`
  - kind: `test`
  - timed out: `False`

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

## Machine Marker

## ISSUES FOUND
