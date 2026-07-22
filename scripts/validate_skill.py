#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]


def fail(message):
    print(f"validation failed: {message}", file=sys.stderr)
    sys.exit(1)


def read(path):
    if not path.exists():
        fail(f"missing {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def parse_frontmatter(text):
    if not text.startswith("---\n"):
        fail("SKILL.md must start with YAML frontmatter")
    parts = text.split("---", 2)
    if len(parts) < 3:
        fail("SKILL.md frontmatter is not closed")
    fields = {}
    for line in parts[1].strip().splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            fail(f"invalid frontmatter line: {line}")
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    return fields, parts[2]


def main():
    skill_text = read(ROOT / "SKILL.md")
    fields, body = parse_frontmatter(skill_text)

    if fields.get("name") != "grill-me-code":
        fail("frontmatter name must be grill-me-code")
    if not fields.get("description"):
        fail("frontmatter description is required")

    extra_fields = set(fields) - {"name", "description"}
    if extra_fields:
        fail(f"unexpected frontmatter fields: {', '.join(sorted(extra_fields))}")

    if len(body.splitlines()) > 220:
        fail("SKILL.md body should stay lean; move details to references/")

    required_refs = [
        "references/review-rubric.md",
        "references/refactor-playbook.md",
        "references/gsd-code-coordination.md",
        "references/prompt-patterns.md",
        "references/market-positioning.md",
        "references/jury-mode.md",
        "references/minimalist-review.md",
    ]
    for rel in required_refs:
        text = read(ROOT / rel)
        if "[TODO" in text or "TODO:" in text:
            fail(f"{rel} contains TODO placeholders")

    metadata = read(ROOT / "agents" / "openai.yaml")
    if "Use $grill-me-code" not in metadata:
        fail("agents/openai.yaml default prompt should mention $grill-me-code")

    workflow = ROOT / ".github" / "workflows" / "validate.yml"
    if workflow.exists() and "scripts/validate_skill.py" not in workflow.read_text(encoding="utf-8"):
        fail("GitHub workflow should run scripts/validate_skill.py")
    ci_template = read(ROOT / "assets" / "github-actions" / "grill-me-code.yml")
    if "upload-sarif" not in ci_template or "--base auto" not in ci_template:
        fail("GitHub Actions template should upload SARIF and use --base auto")

    for marker in ["GRILLING COMPLETE", "ISSUES FOUND", "FIX LOOP COMPLETE", "BLOCKED"]:
        if not re.search(rf"`## {re.escape(marker)}`", skill_text):
            fail(f"SKILL.md missing marker {marker}")

    packet_script = ROOT / "scripts" / "grill_packet.py"
    read(packet_script)
    if "CODE-GRILL-PACKET" not in packet_script.read_text(encoding="utf-8"):
        fail("grill_packet.py should generate CODE-GRILL-PACKET artifacts")

    for rel in [
        ".grill-me-code.example.yaml",
        "requirements.txt",
        "calibration/cases.json",
        "scripts/calibrate_scores.py",
        "scripts/github_annotations.py",
        "scripts/grill_runner.py",
        "scripts/grill_learn.py",
        "assets/github-actions/grill-me-code.yml",
        "examples/CODE-GRILL-PACKET.sample.md",
        "examples/CODE-GRILL-REPORT.sample.md",
        "third_party/ponytail/ATTRIBUTION.md",
        "presets/react.yaml",
        "presets/express.yaml",
        "presets/django.yaml",
        "presets/flask.yaml",
        "tests/test_runner.py",
    ]:
        read(ROOT / rel)

    runner = read(ROOT / "scripts" / "grill_runner.py")
    for token in ["load_config", "write_baseline", "split_suppressed_findings", "ThreadPoolExecutor", "git_changed_lines", "resolve_diff_base", "sarif_report", "append_trend", "auto_baseline_on_ship", "BUILTIN_PRESETS", "jury_scores", "diff_sessions", "check_plugins", "analysis_plugins", "reasoning_plugins", "javascript_semantic_findings", "python_taint_findings", "js_taint_findings", "parse_reasoning_output", "write_init_config", "since_session", "npm:audit", "cargo:audit", "minimalism_findings", "MINIMALISM_MODES", "Minimalist", "test_assertion_metrics", "cached_static_findings", "filter_scan_files", "cross_file_flow_findings", "diff_filter"]:
        if token not in runner:
            fail(f"grill_runner.py missing {token}")

    print("skill validation ok")


if __name__ == "__main__":
    main()
