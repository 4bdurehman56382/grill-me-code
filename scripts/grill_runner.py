#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
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


SEVERITY_RANK = {"nit": 1, "question": 2, "warning": 3, "blocker": 4, "blocked": 5}

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
    re.compile(r"(^|/)test_[^/]+\.py$", re.I),
    re.compile(r"(^|/)[^/]+_test\.go$", re.I),
    re.compile(r"(^|/)[^/]+_(test|spec)\.rb$", re.I),
    re.compile(r"\.feature$", re.I),
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
    StaticPattern("blocker", "SEC-012", re.compile(r"\bos\.system\s*\(|child_process\.(?:exec|execSync)\s*\(|require\(['\"]child_process['\"]\)\.(?:exec|execSync)\s*\(", re.I), "Command execution with dynamic input needs containment proof."),
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
    "analysis_plugins": [],
    "check_plugins": [],
    "reasoning_plugins": [],
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


def read_structured_config(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        value = json.loads(text)
    else:
        try:
            import yaml  # type: ignore
        except ImportError as error:
            raise ValueError("YAML config requires PyYAML. Install PyYAML or use .grill-me-code.json.") from error
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

    analysis_plugins = config.get("analysis_plugins")
    config["analysis_plugins"] = analysis_plugins if isinstance(analysis_plugins, list) else []

    check_plugins = config.get("check_plugins")
    config["check_plugins"] = check_plugins if isinstance(check_plugins, list) else []

    reasoning_plugins = config.get("reasoning_plugins")
    config["reasoning_plugins"] = reasoning_plugins if isinstance(reasoning_plugins, list) else []
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


def is_trivial_assert_text(text: str) -> bool:
    normalized = re.sub(r"\s+", "", text.lower()).rstrip(";")
    trivial_patterns = [
        r"asserttrue",
        r"assert\(true\)",
        r"(?:self\.)?asserttrue\(true\)",
        r"expect\(true\)\.tobe\(true\)",
        r"expect\(1\)\.tobe\(1\)",
        r"(?:assert\.equal|assertequal)\(1,1\)",
        r"assert_eq!\(1,1\)",
    ]
    return any(re.fullmatch(pattern, normalized) for pattern in trivial_patterns)


def python_test_assertions(path: Path) -> tuple[int, int]:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError):
        return 0, 0
    assertions = 0
    trivial = 0
    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            assertions += 1
            if isinstance(node.test, ast.Constant) and node.test.value is True:
                trivial += 1
        elif isinstance(node, ast.Call):
            name = ast_call_name(node.func).lower()
            if "assert" in name or name in {"pytest.raises"}:
                assertions += 1
                line_number = getattr(node, "lineno", 0) or 0
                evidence = lines[line_number - 1] if 0 < line_number <= len(lines) else ""
                if is_trivial_assert_text(evidence):
                    trivial += 1
    return assertions, trivial


def test_assertion_metrics(root: Path, files: list[Path]) -> dict[str, Any]:
    assertion_patterns = [
        re.compile(r"\bexpect\s*\(", re.I),
        re.compile(r"\bassert(?:\.\w+)?\s*\(", re.I),
        re.compile(r"\b(?:strictEqual|deepEqual|equal)\s*\(", re.I),
        re.compile(r"\b(?:t\.Fatal|t\.Error|assert_eq!|assert!)\s*\(", re.I),
    ]
    metrics = {
        "test_files": 0,
        "assertions": 0,
        "trivial_assertions": 0,
        "files_without_assertions": [],
    }
    for path in files:
        if not is_test_file(path):
            continue
        metrics["test_files"] += 1
        if path.suffix == ".py":
            assertions, trivial = python_test_assertions(path)
        else:
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                lines = []
            assertions = 0
            trivial = 0
            for line in lines:
                surface = comment_stripped_surface(path, line)
                if not surface:
                    continue
                if any(pattern.search(surface) for pattern in assertion_patterns):
                    assertions += 1
                    if is_trivial_assert_text(surface):
                        trivial += 1
        metrics["assertions"] += assertions
        metrics["trivial_assertions"] += trivial
        if assertions == 0:
            metrics["files_without_assertions"].append(str(path.relative_to(root)))
    return metrics


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


def git_changed_lines(root: Path, base: str | None) -> dict[str, set[int]]:
    command = ["git", "-C", str(root), "diff", "--unified=0"]
    if base:
        command.append(base)
    try:
        raw = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return {}

    changed: dict[str, set[int]] = {}
    current_file = ""
    for line in raw.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            current_file = ""
            if target.startswith("b/"):
                current_file = target[2:]
                changed.setdefault(current_file, set())
            continue
        if not current_file or not line.startswith("@@"):
            continue
        match = re.search(r"\+(\d+)(?:,(\d+))?", line)
        if not match:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        if count == 0:
            continue
        changed[current_file].update(range(start, start + count))
    return {path: lines for path, lines in changed.items() if lines}


def annotate_diff_status(findings: list[dict[str, Any]], changed_lines: dict[str, set[int]]) -> list[dict[str, Any]]:
    for finding in findings:
        file_path = finding.get("file")
        line = finding.get("line")
        if not changed_lines:
            finding["diff_status"] = "scope"
        elif not file_path or not line:
            finding["diff_status"] = "scope"
        elif file_path in changed_lines:
            finding["diff_status"] = "introduced" if int(line) in changed_lines[file_path] else "legacy"
        else:
            finding["diff_status"] = "scope"
    return findings


def finding_code(finding: dict[str, Any]) -> str:
    identifier = str(finding.get("id", ""))
    return re.sub(r"(?:-(?:AST|JS|COMPILED))?-\d{3}$", "", identifier)


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


def highest_severity(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_rank = SEVERITY_RANK.get(str(left.get("severity", "question")), 2)
    right_rank = SEVERITY_RANK.get(str(right.get("severity", "question")), 2)
    if right_rank == left_rank and right.get("source") == "python-ast":
        return right
    return right if right_rank > left_rank else left


def combine_same_line_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, int, str], dict[str, Any]] = {}
    for finding in findings:
        if not finding.get("file") or not finding.get("line"):
            key = (f"__id__:{finding.get('id')}", 0, "")
        else:
            key = (
                str(finding.get("file", "")),
                int(finding.get("line") or 0),
                str(finding.get("evidence", "")).strip(),
            )
        if key not in grouped:
            item = dict(finding)
            item["matched_codes"] = [finding.get("code") or finding_code(finding)]
            item["related_ids"] = [finding.get("id")]
            grouped[key] = item
            continue

        current = grouped[key]
        selected = highest_severity(current, finding)
        winner = dict(selected)
        codes = list(dict.fromkeys(list_value(current.get("matched_codes")) + [finding.get("code") or finding_code(finding)]))
        related_ids = list(dict.fromkeys(list_value(current.get("related_ids")) + [finding.get("id")]))
        winner["matched_codes"] = codes
        winner["related_ids"] = related_ids
        if selected is not current:
            winner["combined_with"] = current.get("id")
        grouped[key] = winner
    return annotate_findings(sorted(grouped.values(), key=lambda item: (str(item.get("file", "")), int(item.get("line") or 0), str(item.get("id", "")))))


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


def comment_stripped_surface(path: Path, line: str) -> str:
    stripped = line.lstrip()
    suffix = path.suffix.lower()
    if suffix in {".py", ".sh", ".rb"} and stripped.startswith("#"):
        return ""
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".java", ".go", ".rs", ".c", ".cc", ".cpp", ".cs", ".php"}:
        if stripped.startswith(("//", "/*", "*")):
            return ""
    return line


def todo_comment_surface(path: Path, line: str) -> str:
    stripped = line.lstrip()
    suffix = path.suffix.lower()
    if suffix in {".py", ".sh", ".rb", ".yaml", ".yml"} and stripped.startswith("#"):
        return stripped
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".java", ".go", ".rs", ".c", ".cc", ".cpp", ".cs", ".php", ".css"}:
        if stripped.startswith(("//", "/*", "*")):
            return stripped
    return ""


def ast_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = ast_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def python_ast_findings(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    findings = []
    ordinal = 1
    ast_rules = {
        "eval": ("blocker", "SEC-001", "Dynamic code execution can become injection."),
        "exec": ("blocker", "SEC-001", "Dynamic code execution can become injection."),
        "os.system": ("blocker", "SEC-012", "Command execution with dynamic input needs containment proof."),
        "pickle.load": ("blocker", "SEC-006", "Unsafe deserialization can execute or hydrate attacker-controlled data."),
        "pickle.loads": ("blocker", "SEC-006", "Unsafe deserialization can execute or hydrate attacker-controlled data."),
        "marshal.loads": ("blocker", "SEC-006", "Unsafe deserialization can execute or hydrate attacker-controlled data."),
        "yaml.load": ("blocker", "SEC-006", "Unsafe deserialization can execute or hydrate attacker-controlled data."),
    }
    for path in files:
        if path.suffix != ".py":
            continue
        rel = str(path.relative_to(root))
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=rel)
            lines = source.splitlines()
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ast_call_name(node.func)
            if name.startswith("subprocess.") and any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                severity, code, title = ("blocker", "SEC-003", "Shell execution with interpolation risk.")
            elif name in ast_rules:
                severity, code, title = ast_rules[name]
            else:
                continue
            line_number = getattr(node, "lineno", 0) or 0
            evidence = lines[line_number - 1].strip()[:240] if 0 < line_number <= len(lines) else ""
            findings.append({
                "id": f"{code}-AST-{ordinal:03d}",
                "severity": severity,
                "file": rel,
                "line": line_number,
                "title": title,
                "evidence": evidence,
                "source": "python-ast",
            })
            ordinal += 1
    return annotate_findings(findings)


def javascript_semantic_findings(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    findings = []
    ordinal = 1
    js_extensions = {".js", ".jsx", ".mjs", ".ts", ".tsx"}
    for path in files:
        if path.suffix not in js_extensions:
            continue
        rel = str(path.relative_to(root))
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        eval_aliases: set[str] = set()
        child_process_aliases: set[str] = set()
        child_process_exec_aliases: set[str] = set()
        for line_number, line in enumerate(lines, start=1):
            surface = comment_stripped_surface(path, line)
            if not surface:
                continue

            for match in re.finditer(r"\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*eval\b", surface):
                eval_aliases.add(match.group(1))

            cp_alias = re.search(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['\"]child_process['\"]\s*\)", surface)
            if cp_alias:
                child_process_aliases.add(cp_alias.group(1))

            destructured = re.search(r"\{\s*([^}]+)\s*\}\s*=\s*require\(\s*['\"]child_process['\"]\s*\)", surface)
            if destructured:
                for part in destructured.group(1).split(","):
                    name = part.strip()
                    if not name:
                        continue
                    if ":" in name:
                        imported, local = [piece.strip() for piece in name.split(":", 1)]
                    elif " as " in name:
                        imported, local = [piece.strip() for piece in name.split(" as ", 1)]
                    else:
                        imported = local = name
                    if imported in {"exec", "execSync"}:
                        child_process_exec_aliases.add(local)

            import_match = re.search(r"import\s+\{\s*([^}]+)\s*\}\s+from\s+['\"]child_process['\"]", surface)
            if import_match:
                for part in import_match.group(1).split(","):
                    name = part.strip()
                    if not name:
                        continue
                    if " as " in name:
                        imported, local = [piece.strip() for piece in name.split(" as ", 1)]
                    else:
                        imported = local = name
                    if imported in {"exec", "execSync"}:
                        child_process_exec_aliases.add(local)

            for alias in sorted(eval_aliases):
                if re.search(rf"\b{re.escape(alias)}\s*\(", surface):
                    findings.append({
                        "id": f"SEC-001-JS-{ordinal:03d}",
                        "severity": "blocker",
                        "file": rel,
                        "line": line_number,
                        "title": "Eval alias invocation can become injection.",
                        "evidence": line.strip()[:240],
                        "source": "js-semantic",
                    })
                    ordinal += 1
                    break

            child_process_call = any(re.search(rf"\b{re.escape(alias)}\.(?:exec|execSync)\s*\(", surface) for alias in child_process_aliases)
            child_process_call = child_process_call or any(re.search(rf"\b{re.escape(alias)}\s*\(", surface) for alias in child_process_exec_aliases)
            if child_process_call:
                findings.append({
                    "id": f"SEC-012-JS-{ordinal:03d}",
                    "severity": "blocker",
                    "file": rel,
                    "line": line_number,
                    "title": "child_process command execution needs containment proof.",
                    "evidence": line.strip()[:240],
                    "source": "js-semantic",
                })
                ordinal += 1
    return annotate_findings(findings)


def compiled_language_semantic_findings(root: Path, files: list[Path]) -> list[dict[str, Any]]:
    findings = []
    ordinal = 1
    for path in files:
        if path.suffix not in {".go", ".rs"}:
            continue
        rel = str(path.relative_to(root))
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            surface = comment_stripped_surface(path, line)
            if not surface:
                continue
            if path.suffix == ".go" and re.search(r"\bexec\.Command\s*\(", surface):
                title = "Go exec.Command usage needs argument containment proof."
            elif path.suffix == ".rs" and re.search(r"\b(?:Command::new|std::process::Command::new)\s*\(", surface):
                title = "Rust process Command usage needs argument containment proof."
            else:
                continue
            findings.append({
                "id": f"SEC-012-COMPILED-{ordinal:03d}",
                "severity": "warning",
                "file": rel,
                "line": line_number,
                "title": title,
                "evidence": line.strip()[:240],
                "source": "compiled-semantic",
            })
            ordinal += 1
    return annotate_findings(findings)


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
            surface = comment_stripped_surface(path, line)
            code_surface = STRING_LITERAL_RE.sub('""', surface) if surface else ""
            context = "\n".join(lines[max(0, line_number - 4):line_number + 3]).lower()
            for rule in patterns:
                if not surface and rule.code != "BUG-002":
                    continue
                if rule.code == "BUG-002":
                    scan_line = todo_comment_surface(path, line)
                    if not scan_line:
                        continue
                else:
                    scan_line = surface if rule.include_strings and not is_test_file(path) else code_surface
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
    findings.extend(python_ast_findings(root, files))
    findings.extend(javascript_semantic_findings(root, files))
    findings.extend(compiled_language_semantic_findings(root, files))
    return combine_same_line_findings(annotate_findings(findings))


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


def command_available(root: Path, command: list[str]) -> bool:
    if not command:
        return False
    executable = command[0]
    executable_path = Path(executable)
    if executable_path.is_absolute():
        return executable_path.exists()
    if "/" in executable or "\\" in executable:
        return (root / executable).exists()
    return bool(shutil.which(executable))


def make_check(name: str, command: list[str], kind: str, source: str = "discovered", missing_reason: str = "") -> dict[str, Any]:
    available = not missing_reason
    return {
        "name": name,
        "command": command,
        "kind": kind,
        "source": source,
        "available": available,
        "missing_reason": missing_reason,
    }


def configured_check_plugins(config: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks = []
    findings = []
    for index, item in enumerate(config.get("check_plugins", []), start=1):
        if not isinstance(item, dict):
            findings.append(config_finding(f"CONFIG-CHECK-{index:03d}", "Check plugin must be an object"))
            continue
        name = str(item.get("name") or f"custom-check-{index}")
        raw_command = item.get("command")
        kind = str(item.get("kind") or "custom")
        if isinstance(raw_command, list):
            command = [str(part) for part in raw_command]
        elif isinstance(raw_command, str):
            command = shlex.split(raw_command)
        else:
            findings.append(config_finding(f"CONFIG-CHECK-{index:03d}", f"Check plugin {name} is missing command"))
            continue
        if not command:
            findings.append(config_finding(f"CONFIG-CHECK-{index:03d}", f"Check plugin {name} command is empty"))
            continue
        checks.append(make_check(name, command, kind, "config"))
    return checks, findings


def configured_command_plugins(config: dict[str, Any], key: str, default_kind: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    plugins = []
    findings = []
    for index, item in enumerate(config.get(key, []), start=1):
        if not isinstance(item, dict):
            findings.append(config_finding(f"CONFIG-{key.upper()}-{index:03d}", f"{key} entry must be an object"))
            continue
        name = str(item.get("name") or f"{key}-{index}")
        raw_command = item.get("command")
        kind = str(item.get("kind") or default_kind)
        if isinstance(raw_command, list):
            command = [str(part) for part in raw_command]
        elif isinstance(raw_command, str):
            command = shlex.split(raw_command)
        else:
            findings.append(config_finding(f"CONFIG-{key.upper()}-{index:03d}", f"{key} plugin {name} is missing command"))
            continue
        if not command:
            findings.append(config_finding(f"CONFIG-{key.upper()}-{index:03d}", f"{key} plugin {name} command is empty"))
            continue
        plugins.append({"name": name, "command": command, "kind": kind, "source": "config"})
    return plugins, findings


def plugin_unavailable_finding(plugin: dict[str, Any], prefix: str, ordinal: int) -> dict[str, Any]:
    return {
        "id": f"{prefix}-MISSING-{ordinal:03d}",
        "severity": "question",
        "title": f"Configured {plugin.get('kind', 'plugin')} plugin is unavailable: {plugin.get('name')}",
        "source": "plugin-discovery",
        "evidence": " ".join(plugin.get("command", []))[:240],
    }


def run_analysis_plugins(root: Path, plugins: list[dict[str, Any]], payload: dict[str, Any], timeout: int, progress: bool = False) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings = []
    plugin_results = []
    for index, plugin in enumerate(plugins, start=1):
        command = plugin["command"]
        if not command_available(root, command):
            findings.append(plugin_unavailable_finding(plugin, "ANALYSIS", index))
            plugin_results.append({"name": plugin["name"], "ok": False, "missing": True})
            continue
        emit_progress(progress, f"running analysis plugin {plugin['name']}")
        started = utc_now()
        try:
            proc = subprocess.run(
                command,
                cwd=str(root),
                input=json.dumps(payload),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            findings.append({
                "id": f"ANALYSIS-TIMEOUT-{index:03d}",
                "severity": "question",
                "title": f"Analysis plugin timed out: {plugin['name']}",
                "source": "analysis-plugin",
            })
            plugin_results.append({"name": plugin["name"], "ok": False, "timed_out": True})
            continue
        plugin_results.append({"name": plugin["name"], "ok": proc.returncode == 0, "returncode": proc.returncode, "started": started})
        if proc.returncode != 0:
            findings.append({
                "id": f"ANALYSIS-FAILED-{index:03d}",
                "severity": "question",
                "title": f"Analysis plugin failed: {plugin['name']}",
                "source": "analysis-plugin",
                "evidence": proc.stdout[-240:],
            })
            continue
        try:
            parsed = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            findings.append({
                "id": f"ANALYSIS-BADJSON-{index:03d}",
                "severity": "question",
                "title": f"Analysis plugin did not return JSON: {plugin['name']}",
                "source": "analysis-plugin",
                "evidence": proc.stdout[-240:],
            })
            continue
        plugin_findings = parsed.get("findings", parsed) if isinstance(parsed, dict) else parsed
        if not isinstance(plugin_findings, list):
            continue
        for item in plugin_findings:
            if not isinstance(item, dict):
                continue
            item.setdefault("id", f"PLUGIN-{index:03d}-{len(findings) + 1:03d}")
            item.setdefault("severity", "question")
            item.setdefault("title", f"Analysis plugin finding from {plugin['name']}")
            item.setdefault("source", f"analysis-plugin:{plugin['name']}")
            findings.append(item)
    return annotate_findings(findings), plugin_results


def run_reasoning_plugins(root: Path, plugins: list[dict[str, Any]], session: dict[str, Any], timeout: int, progress: bool = False) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    outputs = []
    findings = []
    for index, plugin in enumerate(plugins, start=1):
        command = plugin["command"]
        if not command_available(root, command):
            findings.append(plugin_unavailable_finding(plugin, "REASONING", index))
            outputs.append({"name": plugin["name"], "ok": False, "missing": True})
            continue
        emit_progress(progress, f"running reasoning plugin {plugin['name']}")
        try:
            proc = subprocess.run(
                command,
                cwd=str(root),
                input=json.dumps(session),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            findings.append({
                "id": f"REASONING-TIMEOUT-{index:03d}",
                "severity": "question",
                "title": f"Reasoning plugin timed out: {plugin['name']}",
                "source": "reasoning-plugin",
            })
            outputs.append({"name": plugin["name"], "ok": False, "timed_out": True})
            continue
        outputs.append({
            "name": plugin["name"],
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "output": proc.stdout[-8000:],
        })
        if proc.returncode != 0:
            findings.append({
                "id": f"REASONING-FAILED-{index:03d}",
                "severity": "question",
                "title": f"Reasoning plugin failed: {plugin['name']}",
                "source": "reasoning-plugin",
                "evidence": proc.stdout[-240:],
            })
    return outputs, annotate_findings(findings)


def check_health_findings(root: Path, checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for item in checks:
        if item.get("available", True):
            continue
        findings.append({
            "id": f"CHECK-MISSING-{len(findings) + 1:03d}",
            "severity": "question",
            "title": item.get("missing_reason") or f"Check is unavailable: {item.get('name')}",
            "source": "check-discovery",
            "evidence": " ".join(item.get("command", [])),
        })
    return annotate_findings(findings)


def discover_project_checks(root: Path, config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    checks = []
    config = config or DEFAULT_CONFIG
    scripts = package_scripts(root)
    npm_available = bool(shutil.which("npm"))
    for name in ["lint", "typecheck", "check", "test"]:
        if name in scripts:
            missing = "" if npm_available else f"npm script {name} exists but npm is not installed"
            checks.append(make_check(f"npm:{name}", ["npm", "run", name], name, "package.json", missing))

    local_bin = root / "node_modules" / ".bin"
    if "lint" not in scripts and any((root / name).exists() for name in ["eslint.config.js", "eslint.config.mjs", ".eslintrc", ".eslintrc.json"]):
        eslint = local_bin / ("eslint.cmd" if os.name == "nt" else "eslint")
        if eslint.exists():
            checks.append(make_check("eslint", [str(eslint), "."], "static-analysis"))
        else:
            checks.append(make_check("eslint", [str(eslint), "."], "static-analysis", "discovered", "ESLint config found but node_modules/.bin/eslint is missing"))
    if "typecheck" not in scripts and (root / "tsconfig.json").exists():
        tsc = local_bin / ("tsc.cmd" if os.name == "nt" else "tsc")
        if tsc.exists():
            checks.append(make_check("tsc", [str(tsc), "--noEmit"], "typecheck"))
        else:
            checks.append(make_check("tsc", [str(tsc), "--noEmit"], "typecheck", "discovered", "tsconfig.json found but node_modules/.bin/tsc is missing"))

    if (root / "pyproject.toml").exists() or (root / "pytest.ini").exists() or (root / "tests").exists():
        if shutil.which("pytest"):
            checks.append(make_check("pytest", ["pytest", "-q"], "test"))
        elif (root / "tests").exists():
            checks.append(make_check("python-unittest", [sys.executable, "-m", "unittest", "discover", "-s", "tests"], "test"))
        else:
            checks.append(make_check("python-unittest", [sys.executable, "-m", "unittest", "discover"], "test"))

    if (root / "Makefile").exists():
        try:
            makefile = (root / "Makefile").read_text(encoding="utf-8", errors="ignore")
        except OSError:
            makefile = ""
        if re.search(r"^test\s*:", makefile, re.M):
            missing = "" if shutil.which("make") else "Makefile test target found but make is not installed"
            checks.append(make_check("make:test", ["make", "test"], "test", "Makefile", missing))

    if (root / "go.mod").exists():
        missing = "" if shutil.which("go") else "go.mod found but go is not installed"
        checks.append(make_check("go:test", ["go", "test", "./..."], "test", "go.mod", missing))

    if (root / "Cargo.toml").exists():
        missing = "" if shutil.which("cargo") else "Cargo.toml found but cargo is not installed"
        checks.append(make_check("cargo:test", ["cargo", "test"], "test", "Cargo.toml", missing))

    composer = read_json(root / "composer.json")
    composer_scripts = composer.get("scripts") if isinstance(composer, dict) else {}
    if isinstance(composer_scripts, dict) and "test" in composer_scripts:
        missing = "" if shutil.which("composer") else "composer.json test script found but composer is not installed"
        checks.append(make_check("composer:test", ["composer", "test"], "test", "composer.json", missing))

    for tool, command in [
        ("ruff", ["ruff", "check", "."]),
        ("bandit", ["bandit", "-q", "-r", "."]),
        ("semgrep", ["semgrep", "--config=auto", "--error", "."]),
    ]:
        if shutil.which(tool):
            checks.append(make_check(tool, command, "static-analysis"))

    plugin_checks, _ = configured_check_plugins(config)
    for item in plugin_checks:
        if not command_available(root, item["command"]):
            item["available"] = False
            item["missing_reason"] = f"Configured check {item['name']} command is not available: {item['command'][0]}"
        checks.append(item)

    return checks


def run_project_checks(root: Path, checks: list[dict[str, Any]], timeout: int, progress: bool = False) -> list[dict[str, Any]]:
    results = []
    for item in checks:
        if not item.get("available", True):
            emit_progress(progress, f"SKIP {item['name']} ({item.get('missing_reason')})")
            continue
        emit_progress(progress, f"running {item['name']}")
        result = run_command(item["command"], root, timeout)
        result["name"] = item["name"]
        result["kind"] = item["kind"]
        emit_progress(progress, f"{'PASS' if result.get('ok') else 'FAIL'} {item['name']}")
        results.append(result)
    return results


def plan_mentions_file(plan_text: str, rel_path: str, basename: str) -> bool:
    normalized = plan_text.replace("\\", "/")
    rel = rel_path.lower().replace("\\", "/")
    name = basename.lower()
    if rel in normalized:
        return True
    if "." not in name:
        return False
    pattern = rf"(?<![\w./-]){re.escape(name)}(?![\w./-])"
    return bool(re.search(pattern, normalized))


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
        if not plan_mentions_file(text, rel, path.name):
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
    diff_aware: bool = False,
    test_assertions: int | None = None,
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
    if diff_aware:
        introduced_findings = [finding for finding in findings if finding.get("diff_status", "scope") in {"introduced", "scope"}]
        legacy_findings = [finding for finding in findings if finding.get("diff_status") == "legacy"]
    else:
        introduced_findings = findings
        legacy_findings = []

    def weighted_risk(items: list[dict[str, Any]]) -> int:
        return sum(int(weights.get(finding.get("severity", "question"), 5)) for finding in items if finding.get("severity") != "blocked")

    check_risk = len(failed_checks) * int(thresholds.get("failed_check_risk", 20))
    introduced_risk = weighted_risk(introduced_findings)
    legacy_risk = weighted_risk(legacy_findings)
    if legacy_risk == 0:
        legacy_risk_level = "none"
    elif legacy_risk < 30:
        legacy_risk_level = "low"
    elif legacy_risk < 60:
        legacy_risk_level = "medium"
    elif legacy_risk < 90:
        legacy_risk_level = "high"
    else:
        legacy_risk_level = "critical"
    total_risk = min(100, introduced_risk + legacy_risk + check_risk)
    risk = introduced_risk + check_risk if diff_aware else total_risk
    risk = min(100, risk)

    proof = 0
    if files:
        proof += 20
    if test_files and (test_assertions is None or test_assertions > 0):
        proof += 20
    elif test_files:
        proof += 5
    if passed_checks:
        proof += min(40, len(passed_checks) * 15)
    if not failed_checks and check_results:
        proof += 20
    proof = min(100, proof)

    ship_score = max(0, min(100, round((proof * 0.65) + ((100 - risk) * 0.35))))
    introduced_blockers = sum(1 for finding in introduced_findings if finding.get("severity") == "blocker")
    legacy_blockers = sum(1 for finding in legacy_findings if finding.get("severity") == "blocker")
    code_blockers = introduced_blockers if diff_aware else severity_counts.get("blocker", 0)
    blocked = severity_counts.get("blocked", 0)
    if not files:
        verdict = "BLOCKED"
    elif code_blockers > 0 or failed_checks:
        verdict = "DO NOT SHIP"
    elif blocked > 0:
        verdict = "BLOCKED"
    elif diff_aware and legacy_blockers:
        verdict = "SHIP WITH RISKS"
    elif risk >= int(thresholds.get("ship_with_risks_risk", 35)) or proof < int(thresholds.get("min_proof_ship", 60)):
        verdict = "SHIP WITH RISKS"
    else:
        verdict = "SHIP"

    return {
        "risk_score": risk,
        "introduced_risk_score": min(100, introduced_risk + check_risk),
        "legacy_risk_score": min(100, legacy_risk),
        "legacy_risk_level": legacy_risk_level,
        "total_risk_score": total_risk,
        "proof_score": proof,
        "ship_score": ship_score,
        "verdict": verdict,
        "severity_counts": severity_counts,
        "introduced_findings": len(introduced_findings),
        "legacy_findings": len(legacy_findings),
        "introduced_blockers": introduced_blockers,
        "legacy_blockers": legacy_blockers,
        "failed_checks": len(failed_checks),
        "passed_checks": len(passed_checks),
        "diff_aware": diff_aware,
    }


JURY_LENSES = {
    "Breaker": {
        "codes": ("BUG", "SEC-001", "SEC-003", "SEC-012"),
        "sources": ("test-aware-verification",),
        "questions": [
            "Which input, state, timing, or dependency response breaks this?",
            "What failure mode still lacks an executable proof?",
        ],
    },
    "Security": {
        "codes": ("SEC",),
        "sources": ("python-ast",),
        "questions": [
            "Can user input reach shell, path, HTML, eval, redirect, CORS, or deserialization boundaries?",
            "Which finding needs a sanitizer, allow-list, or containment proof?",
        ],
    },
    "Tester": {
        "codes": ("TEST",),
        "sources": ("test-aware-verification",),
        "check_kinds": ("test", "typecheck", "check"),
        "questions": [
            "Which assertion would have failed before the fix?",
            "Which risky branch still has no test proof?",
        ],
    },
    "Refactorer": {
        "codes": ("PLAN", "BUG"),
        "sources": ("plan-cross-reference",),
        "questions": [
            "What public contract might this change accidentally alter?",
            "Which renamed or moved behavior needs parity proof?",
        ],
    },
    "Release Captain": {
        "codes": ("OPS", "PLAN", "CHECK"),
        "sources": ("check-discovery", "configuration"),
        "questions": [
            "What rollback, config, migration, or deploy order is still unproven?",
            "Which missing check blocks release confidence?",
        ],
    },
    "Maintainer": {
        "codes": ("BUG", "OPS", "TEAM"),
        "sources": ("custom-static",),
        "questions": [
            "What will the next engineer misunderstand?",
            "Which warning represents future maintenance drag rather than immediate breakage?",
        ],
    },
}


def lens_matches(lens: dict[str, Any], finding: dict[str, Any]) -> bool:
    code = str(finding.get("code") or finding_code(finding))
    source = str(finding.get("source", ""))
    return any(code.startswith(prefix) for prefix in lens.get("codes", ())) or source in lens.get("sources", ())


def lens_verdict(score: int, counts: dict[str, int], failed_checks: int) -> str:
    if counts.get("blocked", 0):
        return "BLOCKED"
    if counts.get("blocker", 0) or failed_checks:
        return "DO NOT SHIP"
    if score >= 35 or counts.get("warning", 0):
        return "SHIP WITH RISKS"
    return "SHIP"


def jury_scores(findings: list[dict[str, Any]], check_results: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    weights = config.get("thresholds", {}).get("severity_weights", DEFAULT_CONFIG["thresholds"]["severity_weights"])
    failed_by_kind: dict[str, int] = {}
    for result in check_results:
        if result.get("ok"):
            continue
        kind = str(result.get("kind", "check"))
        failed_by_kind[kind] = failed_by_kind.get(kind, 0) + 1

    output = {}
    for name, lens in JURY_LENSES.items():
        relevant = [finding for finding in findings if lens_matches(lens, finding)]
        counts = {"blocked": 0, "blocker": 0, "warning": 0, "question": 0, "nit": 0}
        for finding in relevant:
            severity = str(finding.get("severity", "question"))
            counts[severity] = counts.get(severity, 0) + 1
        failed_checks = sum(failed_by_kind.get(kind, 0) for kind in lens.get("check_kinds", ()))
        risk = min(100, sum(counts.get(sev, 0) * int(weights.get(sev, 5)) for sev in counts if sev != "blocked") + failed_checks * int(config.get("thresholds", {}).get("failed_check_risk", 20)))
        output[name] = {
            "risk_score": risk,
            "verdict": lens_verdict(risk, counts, failed_checks),
            "findings": len(relevant),
            "failed_checks": failed_checks,
            "severity_counts": counts,
            "questions": lens.get("questions", []),
        }
    return output


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
        f"Introduced risk: **{score.get('introduced_risk_score', score['risk_score'])}/100**",
        f"Legacy risk: **{score.get('legacy_risk_score', 0)}/100**",
        f"Legacy risk level: **{score.get('legacy_risk_level', 'none')}**",
        f"Total risk: **{score.get('total_risk_score', score['risk_score'])}/100**",
        f"Proof score: **{score['proof_score']}/100**",
        f"Ship score: **{score['ship_score']}/100**",
        "",
        "## Scope",
        "",
        f"Files reviewed: {len(session['files'])}",
        *[f"- `{path}`" for path in session["files"]],
        "",
        "## Diff Awareness",
        "",
        f"Diff-aware scoring: `{score.get('diff_aware', False)}`",
        f"Changed-line files: {len(session.get('changed_lines', {}))}",
        f"Introduced findings: {score.get('introduced_findings', 0)}",
        f"Legacy findings: {score.get('legacy_findings', 0)}",
        "",
        "## Configuration",
        "",
        f"Config: `{session.get('config_path') or 'default'}`",
        f"Baseline: `{session.get('baseline', {}).get('path') or 'disabled'}`",
        f"Suppressed findings: {len(suppressed)}",
        "",
        "## Test Proof",
        "",
        f"Test files: {session.get('test_assertions', {}).get('test_files', session.get('test_files', 0))}",
        f"Assertions found: {session.get('test_assertions', {}).get('assertions', 0)}",
        f"Trivial assertions: {session.get('test_assertions', {}).get('trivial_assertions', 0)}",
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
                f"Diff status: `{finding.get('diff_status', 'scope')}`",
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

    jury = session.get("jury_scores", {})
    if jury:
        lines.extend(["## Jury Scores", ""])
        for name, item in jury.items():
            lines.extend([
                f"### {name}",
                "",
                f"Verdict: **{item.get('verdict')}**",
                f"Risk score: **{item.get('risk_score')}/100**",
                f"Findings: {item.get('findings', 0)}",
                f"Failed checks: {item.get('failed_checks', 0)}",
                "",
            ])
        lines.append("")

    reasoning = session.get("reasoning", [])
    if reasoning:
        lines.extend(["## Reasoning Plugins", ""])
        for item in reasoning:
            status = "PASS" if item.get("ok") else "FAIL"
            lines.extend([
                f"### {item.get('name', 'reasoning')}",
                "",
                f"Status: **{status}**",
            ])
            if item.get("output"):
                lines.extend(["", "```text", str(item.get("output", "")).strip(), "```"])
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


def session_finding_map(session: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output = {}
    for finding in session.get("findings", []):
        if not isinstance(finding, dict):
            continue
        fingerprint = finding.get("fingerprint") or finding_fingerprint(finding)
        output[fingerprint] = finding
    return output


def diff_sessions(old_session: dict[str, Any], new_session: dict[str, Any]) -> dict[str, Any]:
    old_findings = session_finding_map(old_session)
    new_findings = session_finding_map(new_session)
    old_keys = set(old_findings)
    new_keys = set(new_findings)
    return {
        "old_session_id": old_session.get("session_id", ""),
        "new_session_id": new_session.get("session_id", ""),
        "old_verdict": old_session.get("score", {}).get("verdict", ""),
        "new_verdict": new_session.get("score", {}).get("verdict", ""),
        "old_score": old_session.get("score", {}),
        "new_score": new_session.get("score", {}),
        "added": [new_findings[key] for key in sorted(new_keys - old_keys)],
        "resolved": [old_findings[key] for key in sorted(old_keys - new_keys)],
        "persisting": [new_findings[key] for key in sorted(old_keys & new_keys)],
    }


def markdown_session_diff(diff: dict[str, Any]) -> str:
    lines = [
        "# CODE-GRILL-SESSION-DIFF",
        "",
        "## Verdict Change",
        "",
        f"Old: **{diff.get('old_verdict') or 'unknown'}**",
        f"New: **{diff.get('new_verdict') or 'unknown'}**",
        "",
        "## Finding Delta",
        "",
        f"Added: {len(diff['added'])}",
        f"Resolved: {len(diff['resolved'])}",
        f"Persisting: {len(diff['persisting'])}",
        "",
    ]
    for title, key in [("Added Findings", "added"), ("Resolved Findings", "resolved"), ("Persisting Findings", "persisting")]:
        lines.extend([f"## {title}", ""])
        if not diff[key]:
            lines.extend(["None.", ""])
            continue
        for finding in diff[key]:
            location = f"{finding.get('file', '')}:{finding.get('line', '')}".strip(":") or "n/a"
            lines.append(f"- `{finding.get('id')}` {finding.get('severity')} {finding.get('title')} at `{location}`")
        lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a CODE-GRILL engine pass with packet, checks, scoring, state, and verdict.")
    parser.add_argument("--diff-sessions", nargs=2, metavar=("OLD", "NEW"), help="Compare two saved session JSON files and exit.")
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
    parser.add_argument("--reasoning-command", action="append", default=[], help="Command that receives session JSON on stdin and returns reasoning text. Can be repeated.")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout per command in seconds.")
    parser.add_argument("--jobs", type=int, default=max(1, min(8, os.cpu_count() or 1)), help="Parallel syntax-check worker count.")
    parser.add_argument("--progress", action="store_true", help="Print incremental progress to stderr while checks run.")
    parser.add_argument("--output-dir", default=".grill-me-code")
    parser.add_argument("--session-id", help="Stable session id for resume/re-run.")
    parser.add_argument("--fail-on-do-not-ship", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.diff_sessions:
        old_path = Path(args.diff_sessions[0])
        new_path = Path(args.diff_sessions[1])
        old_session = read_json(old_path)
        new_session = read_json(new_path)
        if not old_session or not new_session:
            print("--diff-sessions requires two readable session JSON files.", file=sys.stderr)
            return 2
        diff = diff_sessions(old_session, new_session)
        report = markdown_session_diff(diff)
        root = repo_root(Path.cwd())
        out_dir = (root / args.output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "CODE-GRILL-SESSION-DIFF.md").write_text(report, encoding="utf-8")
        print(report)
        return 0

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
    _, check_config_findings = configured_check_plugins(config)
    analysis_plugins, analysis_config_findings = configured_command_plugins(config, "analysis_plugins", "analysis")
    reasoning_plugins, reasoning_config_findings = configured_command_plugins(config, "reasoning_plugins", "reasoning")
    for index, command_text in enumerate(args.reasoning_command, start=1):
        reasoning_plugins.append({"name": f"cli-reasoning-{index}", "command": shlex.split(command_text), "kind": "reasoning", "source": "cli"})
    mode, files = resolve_files(root, args)
    changed_lines = git_changed_lines(root, args.base) if mode == "diff" else {}
    diff_aware = bool(changed_lines)
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
    raw_findings.extend(check_config_findings)
    raw_findings.extend(analysis_config_findings)
    raw_findings.extend(reasoning_config_findings)
    raw_findings.extend(static_findings(root, files, static_patterns))
    plugin_payload = {
        "root": str(root),
        "mode": mode,
        "depth": args.depth,
        "files": [str(path.relative_to(root)) for path in files],
        "changed_lines": {path: sorted(lines) for path, lines in changed_lines.items()},
    }
    analysis_plugin_findings, analysis_plugin_results = run_analysis_plugins(root, analysis_plugins, plugin_payload, min(args.timeout, 60), args.progress)
    raw_findings.extend(analysis_plugin_findings)
    raw_findings.extend(analyze_plan_cross_reference(root, files, args.plan))
    test_files = sum(1 for path in files if is_test_file(path))
    code_files = sum(1 for path in files if is_code_file(path))
    test_relevant_files = sum(1 for path in files if is_test_relevant_file(path))
    assertion_metrics = test_assertion_metrics(root, files)
    if needs_test_proof(files, config) and test_relevant_files and test_files == 0:
        raw_findings.append({
            "id": "TEST-PROOF-001",
            "severity": "warning",
            "title": "No test files are included in the reviewed scope",
            "source": "test-aware-verification",
        })
    elif test_files and assertion_metrics["assertions"] == 0:
        raw_findings.append({
            "id": "TEST-PROOF-002",
            "severity": "warning",
            "title": "Scoped test files contain no detectable assertions",
            "source": "test-aware-verification",
            "evidence": ", ".join(assertion_metrics["files_without_assertions"])[:240],
        })
    elif test_files and assertion_metrics["assertions"] == assertion_metrics["trivial_assertions"]:
        raw_findings.append({
            "id": "TEST-PROOF-003",
            "severity": "warning",
            "title": "Scoped test assertions appear trivial",
            "source": "test-aware-verification",
        })
    discovered_checks = discover_project_checks(root, config)
    raw_findings.extend(check_health_findings(root, discovered_checks))
    raw_findings = annotate_diff_status(combine_same_line_findings(apply_severity_overrides(annotate_findings(raw_findings), config)), changed_lines)

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
    project_results = run_project_checks(root, discovered_checks, args.timeout, args.progress) if args.run_checks else []
    check_results = syntax_results + project_results

    gsd = detect_gsd(root, args.gsd_phase)
    score = score_session(files, findings, check_results, test_files, code_files, config, diff_aware, int(assertion_metrics["assertions"] - assertion_metrics["trivial_assertions"]))
    jury = jury_scores(findings, check_results, config)
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
        "test_assertions": assertion_metrics,
        "changed_lines": {path: sorted(lines) for path, lines in changed_lines.items()},
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
        "analysis_plugins": analysis_plugin_results,
        "reasoning": [],
        "baseline": {
            "path": "" if args.no_baseline else display_path(baseline_path, root),
            "read": baseline_was_read,
            "written": bool(args.write_baseline and not args.no_baseline),
            "findings": len(baseline_findings),
        },
        "learning_store": display_path(learning_path, root),
        "gsd": gsd,
        "score": score,
        "jury_scores": jury,
    }

    reasoning_outputs, reasoning_findings = run_reasoning_plugins(root, reasoning_plugins, session, min(args.timeout, 120), args.progress)
    if reasoning_outputs or reasoning_findings:
        if reasoning_findings:
            raw_findings.extend(annotate_diff_status(reasoning_findings, changed_lines))
            findings, suppressed_findings = split_suppressed_findings(annotate_findings(raw_findings), config, baseline, learnings)
            score = score_session(files, findings, check_results, test_files, code_files, config, diff_aware, int(assertion_metrics["assertions"] - assertion_metrics["trivial_assertions"]))
            jury = jury_scores(findings, check_results, config)
            session["raw_findings"] = raw_findings
            session["findings"] = findings
            session["suppressed_findings"] = suppressed_findings
            session["score"] = score
            session["jury_scores"] = jury
        session["reasoning"] = reasoning_outputs

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
