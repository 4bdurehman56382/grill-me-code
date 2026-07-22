#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
from typing import Any

from grill_packet import build_packet, git_diff_files, git_repo_files, repo_root, scoped_files


SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".md",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}

CODE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".ts",
    ".tsx",
}

TEST_PATTERNS = [
    re.compile(r"(^|/)(test|tests|spec|__tests__)(/|$)", re.I),
    re.compile(r"(\.test|\.spec)\.(js|jsx|ts|tsx|py|rb|go|rs)$", re.I),
]

STATIC_PATTERNS = [
    ("blocker", "SEC-001", re.compile(r"\b(eval|exec)\s*\(", re.I), "Dynamic code execution can become injection."),
    ("blocker", "SEC-002", re.compile(r"\b(password|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"]{8,}", re.I), "Possible hardcoded secret."),
    ("blocker", "SEC-003", re.compile(r"shell\s*=\s*True|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True", re.I), "Shell execution with interpolation risk."),
    ("warning", "SEC-004", re.compile(r"innerHTML|dangerouslySetInnerHTML", re.I), "Unsafe HTML sink needs proof of sanitization."),
    ("warning", "BUG-001", re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}|except\s*:\s*(pass)?\s*$", re.I), "Empty or broad error handling can hide failures."),
    ("warning", "BUG-002", re.compile(r"\bTODO\b|\bFIXME\b|\bHACK\b", re.I), "Unresolved implementation marker in reviewed scope."),
    ("question", "OPS-001", re.compile(r"\bmigration\b|\bschema\b|\brollback\b|\bdeploy\b", re.I), "Release-sensitive change needs rollout and rollback proof."),
]


STRING_LITERAL_RE = re.compile(r"(['\"])(?:\\.|(?!\1).)*\1")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def run_command(command: list[str], cwd: Path, timeout: int) -> dict[str, Any]:
    started = utc_now()
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        output = proc.stdout[-8000:]
        return {
            "command": command,
            "started": started,
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "output": output,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or "") if isinstance(error.stdout, str) else ""
        return {
            "command": command,
            "started": started,
            "ok": False,
            "returncode": None,
            "output": output[-8000:],
            "timed_out": True,
        }


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def is_test_file(path: Path) -> bool:
    text = str(path).replace("\\", "/")
    return any(pattern.search(text) for pattern in TEST_PATTERNS)


def is_code_file(path: Path) -> bool:
    return path.suffix in CODE_EXTENSIONS or path.name in {"Dockerfile", "Makefile"}


def resolve_files(root: Path, args: argparse.Namespace) -> tuple[str, list[Path]]:
    mode = args.mode
    if args.scope:
        files = scoped_files(root, args.scope)
        if mode == "diff":
            mode = "scope"
    elif mode == "repo":
        files = git_repo_files(root, args.max_files)
    else:
        files = git_diff_files(root, args.base)
    files = [path for path in files if path.suffix in SOURCE_EXTENSIONS or path.name in {"Dockerfile", "Makefile"}]
    return mode, files


def static_findings(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    findings = []
    ordinal = 1
    for path in files:
        if not is_code_file(path):
            continue
        rel = str(path.relative_to(root))
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            code_surface = STRING_LITERAL_RE.sub('""', line)
            for severity, code, pattern, reason in STATIC_PATTERNS:
                scan_line = line if code == "SEC-002" else code_surface
                if pattern.search(scan_line):
                    findings.append({
                        "id": f"{code}-{ordinal:03d}",
                        "severity": severity,
                        "file": rel,
                        "line": line_number,
                        "title": reason,
                        "evidence": line.strip()[:240],
                        "source": "builtin-static",
                    })
                    ordinal += 1
    return findings


def python_syntax_checks(root: Path, files: list[Path], timeout: int) -> list[dict[str, Any]]:
    checks = []
    for path in files:
        if path.suffix == ".py":
            checks.append(run_command([sys.executable, "-m", "py_compile", str(path.relative_to(root))], root, timeout))
    return checks


def node_syntax_checks(root: Path, files: list[Path], timeout: int) -> list[dict[str, Any]]:
    if not shutil.which("node"):
        return []
    checks = []
    for path in files:
        if path.suffix in {".js", ".mjs"}:
            checks.append(run_command(["node", "--check", str(path.relative_to(root))], root, timeout))
    return checks


def package_scripts(root: Path) -> dict[str, str]:
    package = read_json(root / "package.json")
    scripts = package.get("scripts")
    return scripts if isinstance(scripts, dict) else {}


def discover_project_checks(root: Path) -> list[dict[str, Any]]:
    checks = []
    scripts = package_scripts(root)
    for name in ["lint", "typecheck", "check", "test"]:
        if name in scripts:
            checks.append({"name": f"npm:{name}", "command": ["npm", "run", name], "kind": name})

    if (root / "pyproject.toml").exists() or (root / "pytest.ini").exists() or (root / "tests").exists():
        if shutil.which("pytest"):
            checks.append({"name": "pytest", "command": ["pytest", "-q"], "kind": "test"})
        elif (root / "tests").exists():
            checks.append({"name": "python-unittest", "command": [sys.executable, "-m", "unittest", "discover", "-s", "tests"], "kind": "test"})
        else:
            checks.append({"name": "python-unittest", "command": [sys.executable, "-m", "unittest", "discover"], "kind": "test"})

    for tool, command in [
        ("ruff", ["ruff", "check", "."]),
        ("bandit", ["bandit", "-q", "-r", "."]),
        ("semgrep", ["semgrep", "--config=auto", "--error", "."]),
    ]:
        if shutil.which(tool):
            checks.append({"name": tool, "command": command, "kind": "static-analysis"})

    return checks


def run_project_checks(root: Path, checks: list[dict[str, Any]], timeout: int) -> list[dict[str, Any]]:
    results = []
    for item in checks:
        result = run_command(item["command"], root, timeout)
        result["name"] = item["name"]
        result["kind"] = item["kind"]
        results.append(result)
    return results


def analyze_plan_cross_reference(root: Path, files: list[Path], plan_path: str | None) -> list[dict[str, Any]]:
    if not plan_path:
        return []
    plan = (root / plan_path).resolve()
    try:
        plan.relative_to(root.resolve())
    except ValueError:
        return [{"id": "PLAN-001", "severity": "blocker", "title": "Plan path is outside the repo", "source": "plan-cross-reference"}]
    if not plan.exists():
        return [{"id": "PLAN-002", "severity": "blocker", "title": f"Plan file not found: {plan_path}", "source": "plan-cross-reference"}]

    text = plan.read_text(encoding="utf-8", errors="ignore").lower()
    findings = []
    for path in files:
        rel = str(path.relative_to(root))
        basename = path.name.lower()
        if rel.lower() not in text and basename not in text:
            findings.append({
                "id": f"PLAN-GAP-{len(findings) + 1:03d}",
                "severity": "question",
                "file": rel,
                "title": "Changed file is not mentioned by the plan",
                "source": "plan-cross-reference",
            })
    plan_mentions_tests = "test" in text or "verify" in text or "acceptance" in text
    if plan_mentions_tests and not any(is_test_file(path) for path in files):
        findings.append({
            "id": "PLAN-GAP-TESTS",
            "severity": "warning",
            "title": "Plan mentions verification but scoped changes include no test files",
            "source": "plan-cross-reference",
        })
    return findings


def detect_gsd(root: Path, phase: str | None) -> dict[str, Any]:
    planning = root / ".planning"
    if not planning.exists():
        return {"detected": False}

    state = planning / "STATE.md"
    roadmap = planning / "ROADMAP.md"
    phase_dir = None
    if phase:
        matches = sorted((planning / "phases").glob(f"{phase}*"))
        phase_dir = matches[0] if matches else None
    phase_files = []
    if phase_dir and phase_dir.exists():
        phase_files = [str(path.relative_to(root)) for path in sorted(phase_dir.glob("*.md"))]
    sdk = shutil.which("gsd-sdk")

    return {
        "detected": True,
        "sdk": sdk or "",
        "state": str(state.relative_to(root)) if state.exists() else "",
        "roadmap": str(roadmap.relative_to(root)) if roadmap.exists() else "",
        "phase": phase or "",
        "phase_dir": str(phase_dir.relative_to(root)) if phase_dir else "",
        "phase_files": phase_files,
    }


def score_session(files: list[Path], findings: list[dict[str, Any]], check_results: list[dict[str, Any]], test_files: int, code_files: int) -> dict[str, Any]:
    weights = {"blocker": 30, "warning": 12, "question": 5, "nit": 1}
    severity_counts = {"blocker": 0, "warning": 0, "question": 0, "nit": 0}
    for finding in findings:
        severity = finding.get("severity", "question")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    failed_checks = [result for result in check_results if not result.get("ok")]
    passed_checks = [result for result in check_results if result.get("ok")]
    risk = sum(severity_counts.get(sev, 0) * weight for sev, weight in weights.items())
    risk += len(failed_checks) * 20
    if code_files and test_files == 0:
        risk += 10
    risk = min(100, risk)

    proof = 0
    if files:
        proof += 20
    if test_files:
        proof += 20
    if passed_checks:
        proof += min(40, len(passed_checks) * 15)
    if not failed_checks and check_results:
        proof += 20
    proof = min(100, proof)

    ship_score = max(0, min(100, proof - risk + 50))
    if not files:
        verdict = "BLOCKED"
    elif severity_counts.get("blocker", 0) > 0 or failed_checks:
        verdict = "DO NOT SHIP"
    elif risk >= 35 or proof < 60:
        verdict = "SHIP WITH RISKS"
    else:
        verdict = "SHIP"

    return {
        "risk_score": risk,
        "proof_score": proof,
        "ship_score": ship_score,
        "verdict": verdict,
        "severity_counts": severity_counts,
        "failed_checks": len(failed_checks),
        "passed_checks": len(passed_checks),
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def markdown_report(session: dict[str, Any]) -> str:
    findings = session["findings"]
    checks = session["checks"]["results"]
    score = session["score"]
    lines = [
        "---",
        f"session_id: {session['session_id']}",
        f"generated: {session['generated']}",
        f"mode: {session['mode']}",
        f"depth: {session['depth']}",
        f"verdict: {score['verdict']}",
        f"risk_score: {score['risk_score']}",
        f"proof_score: {score['proof_score']}",
        f"ship_score: {score['ship_score']}",
        "---",
        "",
        "# CODE-GRILL-REPORT",
        "",
        "## Verdict",
        "",
        f"Decision: **{score['verdict']}**",
        f"Risk score: **{score['risk_score']}/100**",
        f"Proof score: **{score['proof_score']}/100**",
        f"Ship score: **{score['ship_score']}/100**",
        "",
        "## Scope",
        "",
        f"Files reviewed: {len(session['files'])}",
        *[f"- `{path}`" for path in session["files"]],
        "",
        "## Findings",
        "",
    ]
    if findings:
        for finding in findings:
            location = f"`{finding.get('file')}:{finding.get('line')}`" if finding.get("file") and finding.get("line") else f"`{finding.get('file', '')}`"
            lines.extend([
                f"### {finding['severity'].title()}: {finding['id']} - {finding['title']}",
                "",
                f"Source: `{finding.get('source', 'unknown')}`",
                f"Location: {location}" if location != "``" else "Location: n/a",
                f"Evidence: `{finding.get('evidence', '')}`" if finding.get("evidence") else "Evidence: n/a",
                "",
            ])
    else:
        lines.append("No static findings in scoped files.")
        lines.append("")

    lines.extend(["## Checks", ""])
    if checks:
        for result in checks:
            status = "PASS" if result.get("ok") else "FAIL"
            command = " ".join(shlex.quote(part) for part in result["command"])
            lines.extend([
                f"- **{status}** `{command}`",
                f"  - kind: `{result.get('kind', 'syntax')}`",
                f"  - timed out: `{result.get('timed_out', False)}`",
            ])
    else:
        discovered = session["checks"]["discovered"]
        if discovered:
            lines.append("Checks discovered but not run. Re-run with `--run-checks`:")
            lines.extend([f"- `{ ' '.join(item['command']) }`" for item in discovered])
        else:
            lines.append("No project checks discovered.")
    lines.append("")

    gsd = session["gsd"]
    lines.extend(["## GSD Bridge", ""])
    if gsd.get("detected"):
        lines.extend([
            "GSD planning context detected.",
            f"- state: `{gsd.get('state') or 'missing'}`",
            f"- roadmap: `{gsd.get('roadmap') or 'missing'}`",
            f"- sdk: `{gsd.get('sdk') or 'not found'}`",
        ])
        if gsd.get("phase_files"):
            lines.append("- phase files:")
            lines.extend([f"  - `{path}`" for path in gsd["phase_files"]])
    else:
        lines.append("No `.planning/` directory detected.")
    lines.append("")

    lines.extend([
        "## Re-Grill Questions",
        "",
        "- Which blocker has the weakest proof?",
        "- Which warning is actually a release risk?",
        "- Which check did not run but should have?",
        "- What would make this verdict wrong?",
        "",
        "## Machine Marker",
        "",
        "## ISSUES FOUND" if findings or score["verdict"] in {"DO NOT SHIP", "BLOCKED"} else "## GRILLING COMPLETE",
        "",
    ])
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a CODE-GRILL engine pass with packet, checks, scoring, state, and verdict.")
    parser.add_argument("--mode", choices=["plan", "diff", "repo", "release", "fix", "scope"], default="diff")
    parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard")
    parser.add_argument("--base", help="Optional git diff base, such as origin/main")
    parser.add_argument("--scope", action="append", default=[], help="Comma-separated file paths. Can be repeated.")
    parser.add_argument("--max-files", type=int, default=60)
    parser.add_argument("--plan", help="Optional design/plan file to cross-reference with scoped files.")
    parser.add_argument("--gsd-phase", help="Optional GSD phase prefix to include from .planning/phases.")
    parser.add_argument("--run-checks", action="store_true", help="Run discovered project lint/type/test/security checks.")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout per command in seconds.")
    parser.add_argument("--output-dir", default=".grill-me-code")
    parser.add_argument("--session-id", help="Stable session id for resume/re-run.")
    parser.add_argument("--fail-on-do-not-ship", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.max_files < 1:
        print("--max-files must be a positive integer.", file=sys.stderr)
        return 2
    if args.timeout < 1:
        print("--timeout must be a positive integer.", file=sys.stderr)
        return 2

    root = repo_root(Path.cwd())
    mode, files = resolve_files(root, args)
    generated = utc_now()
    session_id = args.session_id or generated.replace(":", "").replace("-", "").split("+")[0]
    out_dir = (root / args.output_dir).resolve()
    sessions_dir = out_dir / "sessions"
    packet_path = out_dir / "CODE-GRILL-PACKET.md"
    report_path = out_dir / "CODE-GRILL-REPORT.md"

    packet_path.parent.mkdir(parents=True, exist_ok=True)
    packet_path.write_text(build_packet(root, files, mode, args.depth, "CODE-GRILL-PACKET"), encoding="utf-8")

    findings = static_findings(root, files)
    findings.extend(analyze_plan_cross_reference(root, files, args.plan))
    test_files = sum(1 for path in files if is_test_file(path))
    code_files = sum(1 for path in files if is_code_file(path))
    if code_files and test_files == 0:
        findings.append({
            "id": "TEST-PROOF-001",
            "severity": "warning",
            "title": "No test files are included in the reviewed scope",
            "source": "test-aware-verification",
        })

    syntax_results = python_syntax_checks(root, files, min(args.timeout, 30))
    syntax_results.extend(node_syntax_checks(root, files, min(args.timeout, 30)))
    discovered_checks = discover_project_checks(root)
    project_results = run_project_checks(root, discovered_checks, args.timeout) if args.run_checks else []
    check_results = syntax_results + project_results

    gsd = detect_gsd(root, args.gsd_phase)
    score = score_session(files, findings, check_results, test_files, code_files)
    session = {
        "session_id": session_id,
        "generated": generated,
        "root": str(root),
        "mode": mode,
        "depth": args.depth,
        "files": [str(path.relative_to(root)) for path in files],
        "code_files": code_files,
        "test_files": test_files,
        "packet": display_path(packet_path, root),
        "report": display_path(report_path, root),
        "findings": findings,
        "checks": {
            "discovered": discovered_checks,
            "results": check_results,
            "run_project_checks": args.run_checks,
        },
        "gsd": gsd,
        "score": score,
    }

    report_path.write_text(markdown_report(session), encoding="utf-8")
    write_json(sessions_dir / f"{session_id}.json", session)
    write_json(out_dir / "latest.json", session)

    print(f"CODE-GRILL session: {session_id}")
    print(f"Packet: {packet_path}")
    print(f"Report: {report_path}")
    print(f"Verdict: {score['verdict']} (risk={score['risk_score']}, proof={score['proof_score']}, ship={score['ship_score']})")

    if not files:
        return 2
    if args.fail_on_do_not_ship and score["verdict"] in {"DO NOT SHIP", "BLOCKED"}:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
