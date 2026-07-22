# Grill Me Code

`grill-me-code` is a Codex skill for hard technical review, refactor coordination, and code-focused grilling. It keeps the original hot-seat theme, but turns it into a high-end engineering workflow for code, diffs, plans, architecture, tests, releases, and fix loops.

It is designed to be forkable: runner scripts with minimal dependencies, stable markdown/JSON artifacts, configurable static patterns, baselines/suppressions, optional GSD context bridging, and machine-readable verdict markers.

## Use Cases

- Stress-test an implementation plan before coding.
- Grill a pull request before review.
- Interrogate a refactor, migration, integration, or release plan.
- Sharpen tests, architecture, and technical tradeoffs.
- Apply GSD-style review, fix, verification, and coordination patterns without requiring the full GSD runtime.
- Generate a `CODE-GRILL-PACKET.md` before review so the scope, pressure lenses, proof ladder, and verdict contract are explicit.

## Signature Features

- **CODE-GRILL-PACKET:** dependency-free packet generator for repo, diff, release, fix, or explicit file scopes, with repo-mode fallback outside git.
- **Runner engine:** scope resolution -> packet -> static findings -> project checks -> scoring -> persisted report.
- **Config file:** `.grill-me-code.yaml`, `.grill-me-code.yml`, or `.grill-me-code.json` can tune thresholds, severity overrides, suppressions, and custom static patterns.
- **Baselines and learnings:** known accepted findings can be suppressed by stable fingerprints instead of reappearing forever.
- **Diff-aware scoring:** diff mode separates introduced findings from legacy findings and can target worktree, staged, or combined diffs.
- **Production artifacts:** every run can emit SARIF for code scanning, trend metrics for health history, and auto-baseline clean `SHIP` runs.
- **Semantic and taint heuristics:** Python AST checks, basic Python/JS taint-style reaching-definition checks, JS/TS alias heuristics, command-use heuristics for Go/Rust/Kotlin/Swift/Dart/Java/C#/PHP, and lightweight JS/TS cross-file source-to-sink signals catch some risks that plain regex misses.
- **Ponytail-inspired minimalism:** optional `lite`, `full`, or `ultra` scans flag replaceable dependencies, tiny delegating wrappers, and speculative interfaces/factories.
- **Test proof checks:** scoped tests are checked for detectable non-trivial assertions across common Python, JS, Java, Kotlin, Swift, Dart, Go, and Rust assertion styles.
- **Scan limits and cache:** oversized files are reported instead of fully loaded, and unchanged files can reuse cached static findings.
- **Runner Jury Mode:** Breaker, Security, Tester, Refactorer, Release Captain, and Maintainer each get a per-lens score.
- **Plugin hooks:** teams can register check, analysis, and reasoning commands without editing the runner; analysis plugins may stream JSONL progress/findings, and reasoning plugins may return structured JSON verdicts/findings.
- **GitHub annotations:** CI can emit file/line annotations from `latest.json`.
- **Verdict bands:** reports include risk/proof bands and verdict reasons so `SHIP WITH RISKS` is not a mystery bucket.
- **Fix Receipts:** every fix should include files changed, verification command, result, and remaining risk.
- **Ship Verdict:** `SHIP`, `SHIP WITH RISKS`, `DO NOT SHIP`, or `BLOCKED`.
- **Pre-code grilling:** interrogates plans before code exists, not just PRs after the damage is done.
- **Optional GSD bridge:** detects `.planning/`, phase files, and `gsd-sdk` without vendoring GSD.

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

YAML config files require PyYAML. JSON config files work without extra packages.

```bash
python3 -m pip install -r requirements.txt
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

Run the engine:

```bash
python3 scripts/grill_runner.py --mode diff --depth standard
python3 scripts/grill_runner.py --init
python3 scripts/grill_runner.py --mode diff --base auto
python3 scripts/grill_runner.py --mode repo --preset react --preset express
python3 scripts/grill_runner.py --mode diff --diff-filter staged
python3 scripts/grill_runner.py --mode diff --diff-filter all
python3 scripts/grill_runner.py --mode repo --depth deep --max-files 40 --run-checks
python3 scripts/grill_runner.py --scope SKILL.md,scripts/grill_runner.py --plan README.md --run-checks
python3 scripts/grill_runner.py --mode repo --run-checks --progress --jobs 8
python3 scripts/grill_runner.py --mode repo --no-cache
python3 scripts/grill_runner.py --mode repo --minimalism full
python3 scripts/grill_runner.py --mode repo --auto-baseline-on-ship
python3 scripts/grill_runner.py --mode repo --sarif-path reports/grill.sarif --trend-file reports/grill-trends.json
python3 scripts/grill_runner.py --mode diff --reasoning-command "llm prompt --system 'Review this CODE-GRILL session JSON.'"
python3 scripts/grill_runner.py --diff-sessions .grill-me-code/sessions/old.json .grill-me-code/latest.json
python3 scripts/grill_runner.py --mode repo --since-session .grill-me-code/latest.json
```

Create or use a baseline:

```bash
python3 scripts/grill_runner.py --mode repo --write-baseline
python3 scripts/grill_runner.py --mode repo --baseline .grill-me-code/baseline.json
```

Record whether a finding was useful:

```bash
python3 scripts/grill_learn.py --finding SEC-001-001 --outcome false_positive --session .grill-me-code/latest.json
```

Learning outcomes marked `false_positive` or `accepted_risk` suppress matching future findings when the runner can match the stored fingerprint.

## Configuration

Copy `.grill-me-code.example.yaml` to `.grill-me-code.yaml` when a repo needs local policy:

```yaml
thresholds:
  ship_with_risks_risk: 40
  min_proof_ship: 65
scan:
  max_file_bytes: 2000000
  cache: true
minimalism:
  # off, lite, full, ultra
  mode: lite
  max_wrapper_lines: 4
severity_overrides:
  BUG-002: nit
ignore:
  paths:
    - examples/**
static_patterns:
  - code: TEAM-001
    severity: warning
    regex: dangerousCall\(
    title: Team-specific dangerous call
check_plugins:
  - name: go-test
    command: ["go", "test", "./..."]
    kind: test
analysis_plugins:
  - name: custom-sast
    command: ["python3", "tools/custom_sast.py"]
    kind: analysis
reasoning_plugins:
  - name: llm-reviewer
    command: ["llm", "prompt", "--system", "Review this CODE-GRILL session JSON."]
    kind: reasoning
```

Analysis plugins receive a JSON payload on stdin and should return a JSON list, `{ "findings": [...] }`, or JSONL lines containing `progress` events and `finding` objects. Plugin findings are schema-normalized before scoring.

Reasoning plugins receive the full session JSON on stdin. Plain text output is attached to the report. Structured JSON can include `summary`, `verdict`, `confidence`, `risks`, `questions`, `recommendations`, `remaining_risks`, and `findings`; returned findings are normalized and scored just like analyzer findings. The runner does not claim LLM-backed reasoning unless one of those commands actually runs.

The built-in analyzer is intentionally lightweight. It includes basic intra-file taint-style heuristics and limited cross-file JS/TS flow signals, but it is not a full call graph, production SAST, or replacement for Semgrep, CodeQL, Bandit, ESLint, type checkers, dependency scanners, or project-specific analysis plugins.

The Minimalist lens is inspired by Ponytail and is scoped to complexity pressure: delete, reuse, use stdlib/native features, avoid one-implementation abstractions, and keep fixes short after the real flow is understood. See `third_party/ponytail/ATTRIBUTION.md`.

Built-in presets are available with `--preset react`, `--preset express`, `--preset django`, and `--preset flask`. Presets are policy overlays; local config still wins.

Production outputs:

- `CODE-GRILL.sarif`: SARIF 2.1.0 for GitHub code scanning or other SARIF consumers.
- `trends.json`: rolling run metrics for verdict, risk, proof, ship score, findings, and checks.
- `--base auto`: resolves a git merge-base from CI/base refs when possible.
- `--auto-baseline-on-ship`: updates the baseline only when the final verdict is `SHIP`.

The score is a transparent heuristic, not a calibrated probability. `scripts/calibrate_scores.py` runs the verdict corpus in `calibration/cases.json` so threshold changes have visible expected outcomes.

## Skill Contents

- `SKILL.md`: the skill instructions Codex loads when triggered.
- `agents/openai.yaml`: UI metadata for skill lists and prompt chips.
- `references/`: focused rubrics for review, refactor, GSD-style coordination, and prompt patterns.
- `scripts/grill_packet.py`: creates `CODE-GRILL-PACKET.md` artifacts from repo/diff/scope.
- `scripts/grill_runner.py`: runs packet generation, static checks, project check discovery, scoring, state, and report output.
- `scripts/grill_learn.py`: records finding outcomes for the learning loop.
- `scripts/calibrate_scores.py`: checks scoring thresholds against known expected cases.
- `scripts/github_annotations.py`: emits GitHub Actions annotations from a session JSON.
- `scripts/validate_skill.py`: local structural validation.
- `presets/`: framework policy overlays for React, Express, Django, and Flask.
- `.grill-me-code.example.yaml`: configurable policy example.
- `calibration/cases.json`: expected verdict cases for scoring drift checks.
- `assets/github-actions/grill-me-code.yml`: optional CI workflow template for consumer repos.
- `examples/`: sample packet and report artifacts.
- `third_party/ponytail/ATTRIBUTION.md`: attribution for the Ponytail-inspired Minimalist lens.

## Validation

Run local validation:

```bash
python3 scripts/validate_skill.py
python3 -m unittest discover -s tests
python3 scripts/calibrate_scores.py
python3 scripts/grill_packet.py --mode repo --max-files 8 --output /tmp/CODE-GRILL-PACKET.md
python3 scripts/grill_runner.py --mode repo --max-files 8 --output-dir /tmp/grill-me-code
python3 scripts/grill_runner.py --mode repo --max-files 8 --base auto --preset react --output-dir /tmp/grill-me-code-prod
python3 scripts/github_annotations.py --session /tmp/grill-me-code/latest.json
```

The GitHub Actions workflow runs the same validator.

## CI Template

`assets/github-actions/grill-me-code.yml` is designed for normal `pull_request` runs with read-only permissions. It fetches the base branch so fork PR diffs can be compared without using `pull_request_target` or granting untrusted code a write token. The workflow uploads `.grill-me-code/` and emits GitHub Actions annotations for active findings.
