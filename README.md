# Grill Me Code

`grill-me-code` is a Codex skill for hard technical review, refactor coordination, and code-focused grilling. It keeps the original hot-seat theme, but turns it into a high-end engineering workflow for code, diffs, plans, architecture, tests, releases, and fix loops.

It is designed to be forkable: dependency-free scripts, stable markdown artifacts, short references, and machine-readable verdict markers.

## Use Cases

- Stress-test an implementation plan before coding.
- Grill a pull request before review.
- Interrogate a refactor, migration, integration, or release plan.
- Sharpen tests, architecture, and technical tradeoffs.
- Apply GSD-style review, fix, verification, and coordination patterns without requiring the full GSD runtime.
- Generate a `CODE-GRILL-PACKET.md` before review so the scope, pressure lenses, proof ladder, and verdict contract are explicit.

## Signature Features

- **CODE-GRILL-PACKET:** dependency-free packet generator for repo, diff, release, fix, or explicit file scopes.
- **Jury Mode:** Breaker, Security, Tester, Refactorer, Release Captain, and Maintainer lenses.
- **Fix Receipts:** every fix should include files changed, verification command, result, and remaining risk.
- **Ship Verdict:** `SHIP`, `SHIP WITH RISKS`, `DO NOT SHIP`, or `BLOCKED`.
- **Pre-code grilling:** interrogates plans before code exists, not just PRs after the damage is done.

## Install

Clone or copy this repo into a Codex skills directory:

```bash
mkdir -p ~/.agents/skills
git clone https://github.com/4bdurehman56382/grill-me-code ~/.agents/skills/grill-me-code
```

Depending on your Codex setup, `~/.codex/skills` may be the preferred skills directory:

```bash
mkdir -p ~/.codex/skills
git clone https://github.com/4bdurehman56382/grill-me-code ~/.codex/skills/grill-me-code
```

## Invoke

```text
Use $grill-me-code to grill this repo before I ship it.
```

Example prompts:

```text
Use $grill-me-code on this implementation plan.
```

```text
Use $grill-me-code to interrogate this diff for correctness, tests, security, and deployment risk.
```

```text
Use $grill-me-code. Do not fix anything yet; just ask the hard questions.
```

```text
Use $grill-me-code to review and fix this diff, run the tests, and re-grill the result.
```

Generate a packet directly:

```bash
python3 scripts/grill_packet.py --mode diff --depth standard
python3 scripts/grill_packet.py --mode repo --depth deep --max-files 40
python3 scripts/grill_packet.py --scope SKILL.md,references/review-rubric.md --output CODE-GRILL-PACKET.md
```

## Skill Contents

- `SKILL.md`: the skill instructions Codex loads when triggered.
- `agents/openai.yaml`: UI metadata for skill lists and prompt chips.
- `references/`: focused rubrics for review, refactor, GSD-style coordination, and prompt patterns.
- `scripts/grill_packet.py`: creates `CODE-GRILL-PACKET.md` artifacts from repo/diff/scope.
- `scripts/validate_skill.py`: local structural validation.

## Validation

Run local validation:

```bash
python3 scripts/validate_skill.py
python3 scripts/grill_packet.py --mode repo --max-files 8 --output /tmp/CODE-GRILL-PACKET.md
```

The GitHub Actions workflow runs the same validator.
