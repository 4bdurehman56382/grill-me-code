# Grill Me Code

`grill-me-code` is a Codex skill for hard technical review, refactor coordination, and code-focused grilling. It still supports the original `/grilling` handoff when that runner exists, but now includes a full inline workflow for code, diffs, plans, architecture, tests, releases, and fix loops.

## Use Cases

- Stress-test an implementation plan before coding.
- Grill a pull request before review.
- Interrogate a refactor, migration, integration, or release plan.
- Sharpen tests, architecture, and technical tradeoffs.
- Apply GSD-style review, fix, verification, and coordination patterns without requiring the full GSD runtime.

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

## Skill Contents

- `SKILL.md`: the skill instructions Codex loads when triggered.
- `agents/openai.yaml`: UI metadata for skill lists and prompt chips.
- `references/`: focused rubrics for review, refactor, GSD-style coordination, and prompt patterns.
- `scripts/validate_skill.py`: local structural validation.

## Validation

Run local validation:

```bash
python3 scripts/validate_skill.py
```

The GitHub Actions workflow runs the same validator.
