---
title: CODE-GRILL-PACKET
mode: scope
depth: standard
files: 2
---

# CODE-GRILL-PACKET

## Hot Seat Brief

Mode: `scope`
Depth: `standard`

Put the scoped work under pressure before it reaches users. The goal is not to sound harsh; the goal is to make weak proof impossible to hide.

## Files In Scope

| File | Lines | Risk Tags |
|------|-------|-----------|
| `src/auth/session.ts` | 140 | security, async |
| `src/auth/session.test.ts` | 88 | tests |

## Jury Mode

1. **Breaker:** What bad token shape crashes or bypasses this?
2. **Security:** Where is authorization enforced?
3. **Tester:** Which assertion would fail before the fix?
4. **Refactorer:** Which callers depend on the old return shape?
5. **Release Captain:** What log proves auth failures are safe?
6. **Maintainer:** Is the intent obvious to the next engineer?

## Verdict Contract

```markdown
## VERDICT

Decision: SHIP | SHIP WITH RISKS | DO NOT SHIP | BLOCKED
Why:
- ...
Proof:
- ...
Remaining risks:
- ...
```
