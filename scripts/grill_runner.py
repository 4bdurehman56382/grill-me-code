#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
from dataclasses import dataclass
import fnmatch
import json
import os
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

TEST_RELEVANT_EXTENSIONS = {
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
    ".ts",
    ".tsx",
}

TEST_PATTERNS = [
    re.compile(r"(^|/)(test|tests|spec|__tests__)(/|$)", re.I),
    re.compile(r"(\.test|\.spec)\.(js|jsx|ts|tsx|py|rb|go|rs)$", re.I),
]

VALID_SEVERITIES = {"blocked", "blocker", "warning", "question", "nit"}
SUPPRESSING_OUTCOMES = {"false_positive", "accepted_risk"}


@dataclass(frozen=True)
class StaticPattern:
    severity: str
    code: str
    pattern: re.Pattern[str]
    title: str
    include_strings: bool = False
    source: str = "builtin-static"


BUILTIN_STATIC_PATTERNS = [
    StaticPattern("blocker", "SEC-001", re.compile(r"\b(eval|exec)\s*\(", re.I), "Dynamic code execution can become injection."),
    StaticPattern("blocker", "SEC-002", re.compile(r"\b(password|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"]{8,}", re.I), "Possible hardcoded secret.", True),
    StaticPattern("blocker", "SEC-003", re.compile(r"shell\s*=\s*True|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True", re.I), "Shell execution with interpolation risk."),
    StaticPattern("warning", "SEC-004", re.compile(r"innerHTML|dangerouslySetInnerHTML", re.I), "Unsafe HTML sink needs proof of sanitization."),
    StaticPattern("warning", "SEC-005", re.compile(r"\.\./|\b(?:path|pathlib)\.(?:join|resolve)\s*\([^)]*(?:request|req\.|params|query|body)|\bopen\s*\([^)]*(?:request|req\.|params|query|body)", re.I), "Potential path traversal needs normalization and containment proof.", True),
    StaticPattern("blocker", "SEC-006", re.compile(r"\bpickle\.(?:load|loads)\s*\(|\bmarshal\.loads\s*\(|\byaml\.load\s*\(", re.I), "Unsafe deserialization can execute or hydrate attacker-controlled data."),
    StaticPattern("warning", "SEC-007", re.compile(r"\bJSON\.parse\s*\([^)]*(?:localStorage|sessionStorage|req\.|request|body|params|query)", re.I), "JSON.parse on external input needs try/catch and validation."),
    StaticPattern("warning", "SEC-008", re.compile(r"(?:password|token|secret|signature|hmac)\s*==|==\s*(?:password|token|secret|signature|hmac)", re.I), "Timing-sensitive comparison may need constant-time comparison."),
    StaticPattern("warning", "SEC-009", re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*|cors\s*\(\s*\{?\s*origin\s*:\s*['\"]\*", re.I), "Wildcard CORS needs an explicit trust boundary.", True),
    StaticPattern("warning", "SEC-010", re.compile(r"(?:redirect|res\.redirect|window\.location|location\.href)\s*\([^)]*(?:req\.|request|query|params|body)", re.I), "Potential open redirect needs allow-listing."),
    StaticPattern("warning", "SEC-011", re.compile(r"new\s+RegExp\s*\([^)]*(?:req\.|request|query|params|body)|re\.compile\s*\([^)]*\([^)]*[+*][^)]*\)[+*]", re.I), "Potential regex DoS needs bounded input or a safer expression."),
    StaticPattern("question", "OPS-002", re.compile(r"(?:https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)|localhost:\d+|[\"']:\d{4,5}[\"'])", re.I), "Hardcoded URL or port may need environment configuration.", True),
    StaticPattern("warning", "BUG-001", re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}|except\s*:\s*(pass)?\s*$", re.I), "Empty or broad error handling can hide failures."),
    StaticPattern("warning", "BUG-002", re.compile(r"\bTODO\b|\bFIXME\b|\bHACK\b", re.I), "Unresolved implementation marker in reviewed scope."),
    StaticPattern("question", "OPS-001", re.compile(r"\bmigration\b|\bschema\b|\brollback\b|\bdeploy\b", re.I), "Release-sensitive change needs rollout and rollback proof."),
]

DEFAULT_CONFIG = {
    "thresholds": {
        "severity_weights": {"blocker": 30, "warning": 12, "question": 5, "nit": 1, "blocked": 0},
        "failed_check_risk": 20,
        "ship_with_risks_risk": 35,
        "min_proof_ship": 60,
    },
    "test_proof": {
        "mode": "code",
    },
    "ignore": {
        "findings": [],
        "codes": [],
        "fingerprints": [],
        "paths": [],
    },
    "severity_overrides": {},
    "static_patterns": [],
}


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


def emit_progress(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[grill] {message}", file=sys.stderr, flush=True)


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "Null", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        return value


def simple_yaml_load(text: str) -> dict[str, Any]:
    lines = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if line.strip():
            lines.append((len(line) - len(line.lstrip(" ")), line.strip()))

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(lines):
            return {}, index
        is_list = lines[index][0] == indent and lines[index][1].startswith("- ")
        if is_list:
            result = []
            while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
                item_text = lines[index][1][2:].strip()
                index += 1
                if not item_text:
                    item, index = parse_block(index, indent + 2)
                    result.append(item)
                    continue
                if ":" in item_text:
                    key, value = item_text.split(":", 1)
                    item = {key.strip(): parse_scalar(value)}
                    while index < len(lines) and lines[index][0] > indent:
                        child_indent, child_text = lines[index]
                        if child_indent < indent + 2 or child_text.startswith("- "):
                            break
                        if ":" not in child_text:
                            index += 1
                            continue
                        child_key, child_value = child_text.split(":", 1)
                        if child_value.strip():
                            item[child_key.strip()] = parse_scalar(child_value)
                            index += 1
                        else:
                            nested, index = parse_block(index + 1, child_indent + 2)
                            item[child_key.strip()] = nested
                    result.append(item)
                else:
                    result.append(parse_scalar(item_text))
            return result, index

        result: dict[str, Any] = {}
        while index < len(lines) and lines[index][0] == indent:
            _, item_text = lines[index]
            if item_text.startswith("- ") or ":" not in item_text:
                break
            key, value = item_text.split(":", 1)
            index += 1
            if value.strip():
                result[key.strip()] = parse_scalar(value)
            else:
                nested, index = parse_block(index, indent + 2)
                result[key.strip()] = nested
        return result, index

    parsed, _ = parse_block(0, 0)
    return parsed if isinstance(parsed, dict) else {}


def read_structured_config(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        value = json.loads(text)
    else:
        try:
            import yaml  # type: ignore
        except ImportError:
            value = simple_yaml_load(text)
        else:
            value = yaml.safe_load(text) or {}
    if not isinstance(value, dict):
        raise ValueError("config root must be an object")
    return value


def merge_dicts(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    merged = json.loads(json.dumps(base))
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def list_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    ignore = config.setdefault("ignore", {})
    if not isinstance(ignore, dict):
        ignore = {}
        config["ignore"] = ignore
    for old_key, new_key in [
        ("ignore_findings", "findings"),
        ("ignore_codes", "codes"),
        ("ignore_fingerprints", "fingerprints"),
        ("ignore_paths", "paths"),
    ]:
        if old_key in config:
            ignore.setdefault(new_key, [])
            ignore[new_key] = list_value(ignore[new_key]) + list_value(config[old_key])
    for key in ["findings", "codes", "fingerprints", "paths"]:
        ignore[key] = list_value(ignore.get(key))

    overrides = config.get("severity_overrides")
    config["severity_overrides"] = overrides if isinstance(overrides, dict) else {}

    thresholds = config.setdefault("thresholds", {})
    if not isinstance(thresholds, dict):
        thresholds = {}
        config["thresholds"] = thresholds
    weights = thresholds.setdefault("severity_weights", DEFAULT_CONFIG["thresholds"]["severity_weights"])
    if not isinstance(weights, dict):
        thresholds["severity_weights"] = DEFAULT_CONFIG["thresholds"]["severity_weights"]

    test_proof = config.setdefault("test_proof", {})
    if not isinstance(test_proof, dict):
        config["test_proof"] = {"mode": str(test_proof)}
    config["test_proof"].setdefault("mode", "code")

    patterns = config.get("static_patterns")
    config["static_patterns"] = patterns if isinstance(patterns, list) else []
    return config


def config_finding(identifier: str, title: str, evidence: str = "") -> dict[str, Any]:
    finding = {
        "id": identifier,
        "severity": "blocked",
        "title": title,
        "source": "configuration",
    }
    if evidence:
        finding["evidence"] = evidence[:240]
    return finding


def load_config(root: Path, explicit_path: str | None) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    config_path = None
    if explicit_path:
        config_path = (root / explicit_path).resolve()
        try:
            config_path.relative_to(root.resolve())
        except ValueError:
            return normalize_config(merge_dicts(DEFAULT_CONFIG, {})), [config_finding("CONFIG-001", "Config path is outside the repo", explicit_path)], ""
    else:
        for name in [".grill-me-code.yaml", ".grill-me-code.yml", ".grill-me-code.json"]:
            candidate = root / name
            if candidate.exists():
                config_path = candidate
                break

    if not config_path:
        return normalize_config(merge_dicts(DEFAULT_CONFIG, {})), [], ""
    if not config_path.exists():
        return normalize_config(merge_dicts(DEFAULT_CONFIG, {})), [config_finding("CONFIG-002", f"Config file not found: {explicit_path}")], ""

    try:
        raw_config = read_structured_config(config_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return normalize_config(merge_dicts(DEFAULT_CONFIG, {})), [config_finding("CONFIG-003", f"Config file could not be parsed: {config_path.name}", str(error))], str(config_path.relative_to(root))
    return normalize_config(merge_dicts(DEFAULT_CONFIG, raw_config)), [], str(config_path.relative_to(root))


def compile_static_patterns(config: dict[str, Any]) -> tuple[list[StaticPattern], list[dict[str, Any]]]:
    patterns = list(BUILTIN_STATIC_PATTERNS)
    findings = []
    for index, item in enumerate(config.get("static_patterns", []), start=1):
        if not isinstance(item, dict):
            findings.append(config_finding(f"CONFIG-PATTERN-{index:03d}", "Custom static pattern must be an object"))
            continue
        code = str(item.get("code") or f"CUSTOM-{index:03d}")
        severity = str(item.get("severity") or "warning").lower()
        title = str(item.get("title") or "Custom static pattern matched.")
        regex = item.get("regex")
        if severity not in VALID_SEVERITIES - {"blocked"}:
            findings.append(config_finding(f"CONFIG-PATTERN-{index:03d}", f"Invalid severity for custom pattern {code}: {severity}"))
            continue
        if not regex:
            findings.append(config_finding(f"CONFIG-PATTERN-{index:03d}", f"Custom pattern {code} is missing regex"))
            continue
        try:
            compiled = re.compile(str(regex), re.I)
        except re.error as error:
            findings.append(config_finding(f"CONFIG-PATTERN-{index:03d}", f"Custom pattern {code} regex is invalid", str(error)))
            continue
        patterns.append(StaticPattern(severity, code, compiled, title, bool(item.get("include_strings", False)), "custom-static"))
    return patterns, findings


def is_test_file(path: Path) -> bool:
    text = str(path).replace("\\", "/")
    return any(pattern.search(text) for pattern in TEST_PATTERNS)


def is_code_file(path: Path) -> bool:
    return path.suffix in CODE_EXTENSIONS or path.name in {"Dockerfile", "Makefile"}


def is_test_relevant_file(path: Path) -> bool:
    rel = str(path).replace("\\", "/").lower()
    if is_test_file(path):
        return False
    if rel.startswith((".github/", "docs/", "examples/")):
        return False
    return path.suffix in TEST_RELEVANT_EXTENSIONS


def needs_test_proof(files: list[Path], config: dict[str, Any]) -> bool:
    mode = str(config.get("test_proof", {}).get("mode", "code")).lower()
    if mode in {"off", "false", "none"}:
        return False
    if mode == "always":
        return bool(files)
    return any(is_test_relevant_file(path) for path in files)


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


def finding_code(finding: dict[str, Any]) -> str:
    identifier = str(finding.get("id", ""))
    return re.sub(r"-\d{3}$", "", identifier)


def finding_fingerprint(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("source", "")),
        finding_code(finding),
        str(finding.get("file", "")),
        str(finding.get("title", "")),
        str(finding.get("evidence", "")).strip(),
    ]
    return "|".join(parts)


def annotate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for finding in findings:
        finding["code"] = finding_code(finding)
        finding["fingerprint"] = finding_fingerprint(finding)
    return findings


def apply_severity_overrides(findings: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    overrides = config.get("severity_overrides", {})
    if not isinstance(overrides, dict):
        return findings
    for finding in findings:
        override = overrides.get(finding.get("id")) or overrides.get(finding.get("code")) or overrides.get(finding_code(finding))
        if override and str(override).lower() in VALID_SEVERITIES:
            finding["severity"] = str(override).lower()
    return annotate_findings(findings)


def load_baseline(path: Path, enabled: bool) -> dict[str, Any]:
    if not enabled or not path.exists():
        return {"version": 1, "findings": []}
    data = read_json(path)
    if not isinstance(data.get("findings"), list):
        data["findings"] = []
    return data


def load_learnings(path: Path) -> dict[str, Any]:
    data = read_json(path)
    if not isinstance(data.get("outcomes"), list):
        data["outcomes"] = []
    return data


def suppression_reason(finding: dict[str, Any], config: dict[str, Any], baseline: dict[str, Any], learnings: dict[str, Any]) -> str:
    ignore = config.get("ignore", {})
    identifier = str(finding.get("id", ""))
    code = str(finding.get("code") or finding_code(finding))
    fingerprint = str(finding.get("fingerprint") or finding_fingerprint(finding))
    file_path = str(finding.get("file", ""))

    if identifier in ignore.get("findings", []):
        return "config: finding id"
    if code in ignore.get("codes", []):
        return "config: finding code"
    if fingerprint in ignore.get("fingerprints", []):
        return "config: fingerprint"
    for pattern in ignore.get("paths", []):
        if file_path and fnmatch.fnmatch(file_path, pattern):
            return f"config: path {pattern}"

    for item in baseline.get("findings", []):
        if isinstance(item, dict) and item.get("fingerprint") == fingerprint:
            return "baseline"

    for item in learnings.get("outcomes", []):
        if not isinstance(item, dict) or item.get("outcome") not in SUPPRESSING_OUTCOMES:
            continue
        if item.get("fingerprint") == fingerprint:
            return f"learning: {item.get('outcome')}"
        if item.get("finding") == identifier:
            return f"learning: {item.get('outcome')}"
    return ""


def split_suppressed_findings(findings: list[dict[str, Any]], config: dict[str, Any], baseline: dict[str, Any], learnings: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active = []
    suppressed = []
    for finding in findings:
        reason = suppression_reason(finding, config, baseline, learnings)
        if reason:
            item = dict(finding)
            item["suppressed_by"] = reason
            suppressed.append(item)
        else:
            active.append(finding)
    return active, suppressed


def write_baseline(path: Path, findings: list[dict[str, Any]], existing: dict[str, Any]) -> None:
    by_fingerprint = {}
    for item in existing.get("findings", []):
        if isinstance(item, dict) and item.get("fingerprint"):
            by_fingerprint[item["fingerprint"]] = item
    for finding in findings:
        if finding.get("severity") == "blocked":
            continue
        fingerprint = finding.get("fingerprint") or finding_fingerprint(finding)
        by_fingerprint[fingerprint] = {
            "fingerprint": fingerprint,
            "id": finding.get("id"),
            "code": finding.get("code") or finding_code(finding),
            "severity": finding.get("severity"),
            "file": finding.get("file", ""),
            "line": finding.get("line"),
            "title": finding.get("title", ""),
            "source": finding.get("source", ""),
        }
    write_json(path, {"version": 1, "generated": utc_now(), "findings": sorted(by_fingerprint.values(), key=lambda item: item["fingerprint"])})


def static_findings(root: Path, files: list[Path], patterns: list[StaticPattern] | None = None) -> list[dict[str, Any]]:
    patterns = patterns or list(BUILTIN_STATIC_PATTERNS)
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
            context = "\n".join(lines[max(0, line_number - 4):line_number + 3]).lower()
            for rule in patterns:
                scan_line = line if rule.include_strings and not is_test_file(path) else code_surface
                if rule.code == "SEC-007" and "try" in context:
                    continue
                if rule.pattern.search(scan_line):
                    findings.append({
                        "id": f"{rule.code}-{ordinal:03d}",
                        "severity": rule.severity,
                        "file": rel,
                        "line": line_number,
                        "title": rule.title,
                        "evidence": line.strip()[:240],
                        "source": rule.source,
                    })
                    ordinal += 1
    return annotate_findings(findings)


def syntax_commands(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    commands = []
    node_available = bool(shutil.which("node"))
    for path in files:
        rel = str(path.relative_to(root))
        if path.suffix == ".py":
            commands.append({"name": f"py_compile:{rel}", "kind": "syntax", "command": [sys.executable, "-m", "py_compile", rel]})
        elif node_available and path.suffix in {".js", ".mjs"}:
            commands.append({"name": f"node-check:{rel}", "kind": "syntax", "command": ["node", "--check", rel]})
    return commands


def run_syntax_checks(root: Path, files: list[Path], timeout: int, jobs: int, progress: bool = False) -> list[dict[str, Any]]:
    commands = syntax_commands(root, files)
    if not commands:
        return []
    max_workers = max(1, min(jobs, len(commands)))
    results = []
    emit_progress(progress, f"running {len(commands)} syntax check(s) with {max_workers} worker(s)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_item = {
            executor.submit(run_command, item["command"], root, timeout): item
            for item in commands
        }
        for future in concurrent.futures.as_completed(future_to_item):
            item = future_to_item[future]
            result = future.result()
            result["name"] = item["name"]
            result["kind"] = item["kind"]
            emit_progress(progress, f"{'PASS' if result.get('ok') else 'FAIL'} {item['name']}")
            results.append(result)
    return sorted(results, key=lambda result: result.get("name", ""))


def python_syntax_checks(root: Path, files: list[Path], timeout: int) -> list[dict[str, Any]]:
    return [
        run_command([sys.executable, "-m", "py_compile", str(path.relative_to(root))], root, timeout)
        for path in files
        if path.suffix == ".py"
    ]


def node_syntax_checks(root: Path, files: list[Path], timeout: int) -> list[dict[str, Any]]:
    if not shutil.which("node"):
        return []
    return [
        run_command(["node", "--check", str(path.relative_to(root))], root, timeout)
        for path in files
        if path.suffix in {".js", ".mjs"}
    ]


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

    local_bin = root / "node_modules" / ".bin"
    if "lint" not in scripts and any((root / name).exists() for name in ["eslint.config.js", "eslint.config.mjs", ".eslintrc", ".eslintrc.json"]):
        eslint = local_bin / ("eslint.cmd" if os.name == "nt" else "eslint")
        if eslint.exists():
            checks.append({"name": "eslint", "command": [str(eslint), "."], "kind": "static-analysis"})
    if "typecheck" not in scripts and (root / "tsconfig.json").exists():
        tsc = local_bin / ("tsc.cmd" if os.name == "nt" else "tsc")
        if tsc.exists():
            checks.append({"name": "tsc", "command": [str(tsc), "--noEmit"], "kind": "typecheck"})

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


def run_project_checks(root: Path, checks: list[dict[str, Any]], timeout: int, progress: bool = False) -> list[dict[str, Any]]:
    results = []
    for item in checks:
        emit_progress(progress, f"running {item['name']}")
        result = run_command(item["command"], root, timeout)
        result["name"] = item["name"]
        result["kind"] = item["kind"]
        emit_progress(progress, f"{'PASS' if result.get('ok') else 'FAIL'} {item['name']}")
        results.append(result)
    return results


def analyze_plan_cross_reference(root: Path, files: list[Path], plan_path: str | None) -> list[dict[str, Any]]:
    if not plan_path:
        return []
    plan = (root / plan_path).resolve()
    try:
        plan.relative_to(root.resolve())
    except ValueError:
        return annotate_findings([{"id": "PLAN-001", "severity": "blocked", "title": "Plan path is outside the repo", "source": "plan-cross-reference"}])
    if not plan.exists():
        return annotate_findings([{"id": "PLAN-002", "severity": "blocked", "title": f"Plan file not found: {plan_path}", "source": "plan-cross-reference"}])

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
    return annotate_findings(findings)


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


def score_session(
    files: list[Path],
    findings: list[dict[str, Any]],
    check_results: list[dict[str, Any]],
    test_files: int,
    code_files: int,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = config or DEFAULT_CONFIG
    thresholds = config.get("thresholds", {})
    weights = thresholds.get("severity_weights", DEFAULT_CONFIG["thresholds"]["severity_weights"])
    severity_counts = {"blocked": 0, "blocker": 0, "warning": 0, "question": 0, "nit": 0}
    for finding in findings:
        severity = finding.get("severity", "question")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    failed_checks = [result for result in check_results if not result.get("ok")]
    passed_checks = [result for result in check_results if result.get("ok")]
    risk = sum(severity_counts.get(sev, 0) * int(weight) for sev, weight in weights.items() if sev != "blocked")
    risk += len(failed_checks) * int(thresholds.get("failed_check_risk", 20))
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

    ship_score = max(0, min(100, round((proof * 0.65) + ((100 - risk) * 0.35))))
    code_blockers = severity_counts.get("blocker", 0)
    blocked = severity_counts.get("blocked", 0)
    if not files:
        verdict = "BLOCKED"
    elif code_blockers > 0 or failed_checks:
        verdict = "DO NOT SHIP"
    elif blocked > 0:
        verdict = "BLOCKED"
    elif risk >= int(thresholds.get("ship_with_risks_risk", 35)) or proof < int(thresholds.get("min_proof_ship", 60)):
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
    suppressed = session.get("suppressed_findings", [])
    checks = session["checks"]["results"]
    score = session["score"]
    material_findings = any(finding.get("severity") in {"blocked", "blocker", "warning"} for finding in findings)
    marker = "## ISSUES FOUND" if material_findings or score["verdict"] in {"DO NOT SHIP", "BLOCKED"} else "## GRILLING COMPLETE"
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
        "## Configuration",
        "",
        f"Config: `{session.get('config_path') or 'default'}`",
        f"Baseline: `{session.get('baseline', {}).get('path') or 'disabled'}`",
        f"Suppressed findings: {len(suppressed)}",
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

    if suppressed:
        lines.extend(["## Suppressed Findings", ""])
        for finding in suppressed:
            location = f"`{finding.get('file')}:{finding.get('line')}`" if finding.get("file") and finding.get("line") else f"`{finding.get('file', '')}`"
            lines.extend([
                f"- `{finding.get('id')}` {finding.get('title')} ({finding.get('suppressed_by')}) at {location}",
            ])
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
        marker,
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
    parser.add_argument("--config", help="Optional .grill-me-code YAML/JSON config file.")
    parser.add_argument("--baseline", default=".grill-me-code/baseline.json", help="Baseline file used to suppress known findings.")
    parser.add_argument("--no-baseline", action="store_true", help="Do not read the baseline file even if it exists.")
    parser.add_argument("--write-baseline", action="store_true", help="Write or update the baseline with current findings.")
    parser.add_argument("--learning-store", default=".grill-me-code/learnings.json", help="Learning outcomes file used for suppression.")
    parser.add_argument("--gsd-phase", help="Optional GSD phase prefix to include from .planning/phases.")
    parser.add_argument("--run-checks", action="store_true", help="Run discovered project lint/type/test/security checks.")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout per command in seconds.")
    parser.add_argument("--jobs", type=int, default=max(1, min(8, os.cpu_count() or 1)), help="Parallel syntax-check worker count.")
    parser.add_argument("--progress", action="store_true", help="Print incremental progress to stderr while checks run.")
    parser.add_argument("--output-dir", default=".grill-me-code")
    parser.add_argument("--session-id", help="Stable session id for resume/re-run.")
    parser.add_argument("--fail-on-do-not-ship", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.mode == "scope" and not args.scope:
        print("--mode scope requires at least one --scope value.", file=sys.stderr)
        return 2
    if args.max_files < 1:
        print("--max-files must be a positive integer.", file=sys.stderr)
        return 2
    if args.timeout < 1:
        print("--timeout must be a positive integer.", file=sys.stderr)
        return 2
    if args.jobs < 1:
        print("--jobs must be a positive integer.", file=sys.stderr)
        return 2

    root = repo_root(Path.cwd())
    config, config_findings, config_path = load_config(root, args.config)
    static_patterns, pattern_config_findings = compile_static_patterns(config)
    mode, files = resolve_files(root, args)
    emit_progress(args.progress, f"resolved {len(files)} file(s) in {mode} mode")
    generated = utc_now()
    session_id = args.session_id or generated.replace(":", "").replace("-", "").split("+")[0]
    out_dir = (root / args.output_dir).resolve()
    sessions_dir = out_dir / "sessions"
    packet_path = out_dir / "CODE-GRILL-PACKET.md"
    report_path = out_dir / "CODE-GRILL-REPORT.md"
    baseline_path = (root / args.baseline).resolve()
    learning_path = (root / args.learning_store).resolve()

    packet_path.parent.mkdir(parents=True, exist_ok=True)
    packet_path.write_text(build_packet(root, files, mode, args.depth, "CODE-GRILL-PACKET"), encoding="utf-8")
    emit_progress(args.progress, f"wrote packet to {display_path(packet_path, root)}")

    raw_findings = []
    raw_findings.extend(config_findings)
    raw_findings.extend(pattern_config_findings)
    raw_findings.extend(static_findings(root, files, static_patterns))
    raw_findings.extend(analyze_plan_cross_reference(root, files, args.plan))
    test_files = sum(1 for path in files if is_test_file(path))
    code_files = sum(1 for path in files if is_code_file(path))
    test_relevant_files = sum(1 for path in files if is_test_relevant_file(path))
    if needs_test_proof(files, config) and test_relevant_files and test_files == 0:
        raw_findings.append({
            "id": "TEST-PROOF-001",
            "severity": "warning",
            "title": "No test files are included in the reviewed scope",
            "source": "test-aware-verification",
        })
    raw_findings = apply_severity_overrides(annotate_findings(raw_findings), config)

    baseline_findings = []
    baseline_was_read = False
    if not args.no_baseline:
        try:
            baseline_path.relative_to(root.resolve())
        except ValueError:
            raw_findings.append(config_finding("BASELINE-001", "Baseline path is outside the repo", args.baseline))
            baseline = {"version": 1, "findings": []}
        else:
            baseline_was_read = baseline_path.exists()
            baseline = load_baseline(baseline_path, True)
            baseline_findings = baseline.get("findings", [])
    else:
        baseline = {"version": 1, "findings": []}
    learnings = load_learnings(learning_path)
    findings, suppressed_findings = split_suppressed_findings(annotate_findings(raw_findings), config, baseline, learnings)
    if args.write_baseline and not args.no_baseline:
        write_baseline(baseline_path, raw_findings, baseline)
        emit_progress(args.progress, f"updated baseline at {display_path(baseline_path, root)}")

    syntax_results = run_syntax_checks(root, files, min(args.timeout, 30), args.jobs, args.progress)
    discovered_checks = discover_project_checks(root)
    project_results = run_project_checks(root, discovered_checks, args.timeout, args.progress) if args.run_checks else []
    check_results = syntax_results + project_results

    gsd = detect_gsd(root, args.gsd_phase)
    score = score_session(files, findings, check_results, test_files, code_files, config)
    session = {
        "session_id": session_id,
        "generated": generated,
        "root": str(root),
        "mode": mode,
        "depth": args.depth,
        "config_path": config_path,
        "files": [str(path.relative_to(root)) for path in files],
        "code_files": code_files,
        "test_files": test_files,
        "test_relevant_files": test_relevant_files,
        "packet": display_path(packet_path, root),
        "report": display_path(report_path, root),
        "raw_findings": raw_findings,
        "findings": findings,
        "suppressed_findings": suppressed_findings,
        "checks": {
            "discovered": discovered_checks,
            "results": check_results,
            "run_project_checks": args.run_checks,
        },
        "baseline": {
            "path": "" if args.no_baseline else display_path(baseline_path, root),
            "read": baseline_was_read,
            "written": bool(args.write_baseline and not args.no_baseline),
            "findings": len(baseline_findings),
        },
        "learning_store": display_path(learning_path, root),
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
