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
Proof score: **40/100**
Ship score: **28/100**

## Findings

### Blocker: SEC-001-001 - Possible hardcoded secret

Source: `builtin-static`
Location: `src/config.ts:12`
Evidence: `apiToken = "live-token-value"`

### Warning: TEST-PROOF-001 - No test files are included in the reviewed scope

Source: `test-aware-verification`
Location: n/a
Evidence: n/a

## Checks

- **FAIL** `npm run test`
  - kind: `test`
  - timed out: `False`

## Machine Marker

## ISSUES FOUND
