# Market Positioning

Use this when explaining why `grill-me-code` is different or when improving the skill for adoption.

## Position

`grill-me-code` is not another hosted PR reviewer. It is a portable adversarial engineering workflow that turns an idea, diff, repo, refactor, or release into a pressure-tested artifact with proof.

## Market Gaps To Own

Most tools are strong in one of these lanes:

- PR comments after code is written
- security or quality rule scanning
- auto-fix suggestions for detected issues
- summaries and walkthroughs for reviewers

The gap: developers also need a local, forkable, agent-native workflow that:

- grills the plan before bad code exists
- produces a review packet without waiting for a PR
- forces proof that tests cover the risky behavior
- checks rollback, wiring, migration, auth, and observability
- coordinates review -> fix -> re-review with bounded loops
- keeps artifacts that humans and agents can resume
- runs available local checks instead of only describing them
- records finding outcomes so the team can learn which grills catch real bugs

## High-End Product Promise

Put the code in the hot seat before users do.

The repo should feel like:

- a senior staff engineer asking the question everyone avoided
- a release captain demanding rollback proof
- a security reviewer looking for the bad input
- a test engineer asking which assertion would have failed yesterday
- a fixer who edits only after the risk is understood

## Differentiating Features

### CODE-GRILL-PACKET

A generated markdown artifact containing scope, risk lenses, hard questions, proof ladder, and verdict contract.

### CODE-GRILL Runner

A dependency-free CLI that resolves scope, runs builtin static heuristics, discovers project checks, optionally runs those checks, assigns risk/proof/ship scores, persists session JSON, and writes `CODE-GRILL-REPORT.md`.

### Jury Mode

The same scope is reviewed through distinct lenses:

- Breaker: how does this fail?
- Security: how is it abused?
- Tester: what proves it works?
- Refactorer: what contract might break?
- Release Captain: what blocks ship?
- Maintainer: what will be confusing later?

### Fix Receipts

Every fix should carry:

- finding addressed
- files changed
- verification command
- result
- remaining risk

### Ship Verdict

The final output says one of:

- `SHIP`
- `SHIP WITH RISKS`
- `DO NOT SHIP`
- `BLOCKED`

Each verdict must include evidence.

### Optional GSD Bridge

The runner detects `.planning/`, `STATE.md`, `ROADMAP.md`, phase files, and `gsd-sdk` when present. It imports GSD context into the report without requiring or vendoring the full GSD runtime.

## Fork Hooks

Make the repo easy to fork by keeping:

- references short and composable
- scripts dependency-free
- artifact formats stable
- marker headings machine-readable
- prompts easy to customize per team
