---
name: grill-me-code
description: Relentless high-end code grilling, review, refactor coordination, and proof-backed shipping gates for implementation plans, diffs, repositories, architecture, tests, debugging, releases, and technical decisions. Use when Codex should put code or a plan in the hot seat before shipping, generate a CODE-GRILL-PACKET, run multi-lens adversarial review, classify risks, suggest or apply fixes, run verification, coordinate multi-pass review/fix loops, or adapt GSD-style get-it-done execution patterns to code work.
---

# Grill Me Code

Run a `/grilling` session for code when a dedicated grilling runner is available.
When no runner is available, run the grilling loop inline using this skill.

## Core Loop

1. Resolve scope before judging:
   - Prefer explicitly named files, diffs, PRs, plans, or commands.
   - Otherwise use the current git diff.
   - If the user asks for repo-wide grilling, sample architecture first, then inspect hot paths.
   - For a complete engine pass, run `scripts/grill_runner.py` to create packet, report, scores, state, and verdict.
   - Use runner diff mode to separate introduced risk from legacy risk when reviewing PR-like changes.
   - Use configured analysis, check, and reasoning plugins when present; they are the only runner-level path for external SAST tools, project-specific analyzers, or LLM/expert reasoning.
   - For only a reusable artifact, run `scripts/grill_packet.py` to create `CODE-GRILL-PACKET.md`.
   - If the runner script is unavailable or cannot execute in the current environment, say that plainly and fall back to inline review. Do not claim tool-backed checks, scores, or receipts that were not actually produced.
   - Fail closed on unclear destructive or production-impacting actions.
2. Pick depth:
   - `quick`: fast pattern and risk scan.
   - `standard`: default file-by-file review with tests and edge cases.
   - `deep`: cross-file architecture, invariants, migration, security, and release readiness.
   - Use `--progress` for longer runner scans when the user benefits from incremental check status.
3. Grill first:
   - Ask the hard questions that would change the implementation.
   - Identify blockers, warnings, missing proof, and false confidence.
   - Do not accept "tests pass" as proof unless the tests cover the behavior at risk.
4. Act when the user wants changes:
   - Convert findings into a small fix plan.
   - Edit narrowly.
   - Verify with the project's real checks.
   - Re-grill the changed surface once more.
   - Record finding outcomes with `scripts/grill_learn.py` when the user confirms real bug, false positive, accepted risk, or follow-up.
   - Use config, baselines, and learnings when present; do not re-raise accepted findings unless new evidence changes the risk.
5. Close with a machine-readable marker:
   - `## GRILLING COMPLETE` when no blocking concerns remain.
   - `## ISSUES FOUND` when there are unresolved blockers or warnings.
   - `## FIX LOOP COMPLETE` when fixes were applied and verified.
   - `## BLOCKED` when missing access, credentials, source files, or unsafe scope prevents progress.

## What To Read

- For review severity, depth, and output format, read `references/review-rubric.md`.
- For refactor and fix loops, read `references/refactor-playbook.md`.
- For GSD-inspired coordination, artifacts, and handoff contracts, read `references/gsd-code-coordination.md`.
- For reusable prompt shapes, read `references/prompt-patterns.md`.
- For market positioning and fork-worthy product direction, read `references/market-positioning.md`.
- For multi-lens adversarial review, read `references/jury-mode.md`.
- For the runner engine and CI hooks, prefer `scripts/grill_runner.py` and `assets/github-actions/grill-me-code.yml`.

## Review Stance

Be adversarial about correctness and kind about delivery.

Look for:

- wrong behavior, missed edge cases, null/empty boundaries, races, and async mistakes
- security issues, injection paths, leaked secrets, unsafe shell or path handling
- brittle architecture, hidden coupling, circular flow, or orphaned exports
- missing, shallow, flaky, or mis-scoped tests
- operational risks: migrations, auth, rate limits, rollback, observability, deploy order
- refactors that improve names but break contracts

Do not flag taste as risk. Tie every serious concern to behavior, evidence, and a fix.

## Output Defaults

For review-only requests, lead with findings by severity:

- `Blocker`: must fix before shipping
- `Warning`: should fix or consciously accept
- `Question`: needs user or domain confirmation
- `Nit`: optional polish

For implementation requests, provide:

1. short plan
2. edits
3. verification commands and results
4. re-grill summary

Keep outputs concise unless the user asks for a full artifact.

## Signature Modes

- `Hot Seat`: grill an idea or implementation plan before code exists.
- `PR Trial`: interrogate a diff or pull request before review.
- `Refactor Crucible`: prove behavior survives a refactor.
- `Shiproom`: inspect release, migration, rollback, config, and observability risk.
- `Fix Receipts`: apply fixes and produce proof commands/results.
- `Jury Mode`: run the same scope through multiple lenses before verdict. When using the runner, tie each lens to actual findings, check results, or missing proof; when only working inline, label it as reasoning-only.

## Differentiator

Market tools usually start at the PR or static-analysis finding. This skill starts earlier and ends later: plan grilling, packet generation, configurable static heuristics, Python AST checks, JS/TS alias heuristics, compiled-language command-use checks, assertion-quality test proof, diff-aware introduced-vs-legacy scoring, legacy risk levels, per-lens runner jury scores, configurable check/analysis/reasoning plugins, GitHub annotations, baselines, learning records, GSD context bridging, fix loop, verification receipts, session comparison, and a final ship/no-ship verdict.
