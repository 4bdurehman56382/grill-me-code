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
- exposes analysis and reasoning plugin hooks instead of pretending every review is LLM-backed
- lets teams tune policy with config, baselines, suppressions, and severity overrides
- separates introduced risk from legacy risk during diff reviews
- scores the same scope through explicit runner-backed jury lenses
- emits CI annotations that land on the file and line developers are already reading
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

A minimal-dependency CLI that resolves scope, runs configurable static heuristics plus targeted Python AST checks, JS/TS alias heuristics, and compiled-language command-use checks, discovers project checks and check plugins, optionally runs those checks, separates setup-blocked findings from code risk, separates introduced risk from legacy risk, assigns risk/proof/ship scores, persists session JSON, and writes `CODE-GRILL-REPORT.md`.

### Plugin Surface

Teams can add:

- check plugins that run real project commands
- analysis plugins that return machine-readable findings
- reasoning plugins that receive the session JSON and attach LLM or expert-review output

The runner should only claim plugin-backed reasoning when a configured command actually ran.

### Test Proof Quality

The runner does not treat every test file as proof. It checks scoped tests for detectable assertions and calls out empty or obviously trivial assertions so `assert True` does not pass as confidence.

### Policy Memory

Baselines and learning records let teams suppress accepted findings by stable fingerprints while still surfacing new evidence.

### Session Compare

Saved sessions can be diffed to show added, resolved, and persisting findings between runs.

### Jury Mode

The same scope is reviewed through distinct lenses:

- Breaker: how does this fail?
- Security: how is it abused?
- Tester: what proves it works?
- Refactorer: what contract might break?
- Release Captain: what blocks ship?
- Maintainer: what will be confusing later?

The runner gives each lens its own score and verdict. LLM-based grilling should use those scores as evidence, then add human-grade reasoning where the script cannot infer intent.

### GitHub Annotations

The CI helper converts active session findings into GitHub Actions annotations so blockers and warnings appear beside the relevant file/line while still preserving the full artifact for deeper review.

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
- config and baseline formats human-editable
- marker headings machine-readable
- prompts easy to customize per team
