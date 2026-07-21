# Grill Me Code

`grill-me-code` is a tiny Codex skill that mirrors `grill-me`, but routes the grilling session toward code, diffs, implementation plans, architecture, tests, and technical decisions.

It intentionally keeps the same handoff-style mechanics as `grill-me`:

```md
Run a `/grilling` session for code.
```

## Use Cases

- Stress-test an implementation plan before coding.
- Grill a pull request before review.
- Interrogate a refactor, migration, integration, or release plan.
- Sharpen tests, architecture, and technical tradeoffs.

## Install

Clone or copy this repo into a Codex skills directory:

```bash
mkdir -p ~/.agents/skills
git clone https://github.com/coldsolutionz/grill-me-code ~/.agents/skills/grill-me-code
```

Depending on your Codex setup, `~/.codex/skills` may be the preferred skills directory:

```bash
mkdir -p ~/.codex/skills
git clone https://github.com/coldsolutionz/grill-me-code ~/.codex/skills/grill-me-code
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

## Skill Contents

- `SKILL.md`: the skill instructions Codex loads when triggered.
- `agents/openai.yaml`: UI metadata for skill lists and prompt chips.

No scripts or heavy references are included. This skill is intentionally lightweight and behaves like `grill-me`, just code-focused.

## Validation

If you have the Codex `skill-creator` validator available:

```bash
python3 /home/coldplay/.codex/skills/.system/skill-creator/scripts/quick_validate.py .
```

The GitHub Actions workflow performs a lightweight structural validation.
