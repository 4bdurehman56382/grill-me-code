#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path
import subprocess
import sys


GENERATED_DIRS = {
    ".git",
    ".next",
    ".nuxt",
    ".turbo",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "vendor",
}

GENERATED_SUFFIXES = {
    ".bundle.js",
    ".lock",
    ".min.css",
    ".min.js",
}

LOCK_FILES = {
    "Gemfile.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "yarn.lock",
}

RISK_PATTERNS = {
    "security": ["password", "secret", "token", "api_key", "apikey", "eval(", "innerHTML", "exec("],
    "async": ["async ", "await ", "Promise", "setTimeout", "setInterval"],
    "data": ["migration", "schema", "prisma", "sequelize", "sql", "database"],
    "release": ["docker", "deploy", "workflow", "github/workflows", "config", ".env"],
    "tests": ["test(", "it(", "describe(", "assert", "expect("],
}


def run_git(root: Path, *args: str) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), *args], text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return ""


def repo_root(start: Path) -> Path:
    output = run_git(start, "rev-parse", "--show-toplevel").strip()
    return Path(output) if output else start.resolve()


def is_generated(path: Path) -> bool:
    parts = set(path.parts)
    if parts & GENERATED_DIRS:
        return True
    if path.name in LOCK_FILES:
        return True
    return any(path.name.endswith(suffix) for suffix in GENERATED_SUFFIXES)


def git_diff_files(root: Path, base: str | None) -> list[Path]:
    args = ["diff", "--name-only"]
    if base:
        args.append(base)
    raw = run_git(root, *args)
    files = [root / line.strip() for line in raw.splitlines() if line.strip()]
    return [p for p in files if p.exists() and p.is_file() and not is_generated(p.relative_to(root))]


def git_repo_files(root: Path, limit: int) -> list[Path]:
    raw = run_git(root, "ls-files")
    files = []
    for line in raw.splitlines():
        path = root / line.strip()
        if path.exists() and path.is_file() and not is_generated(path.relative_to(root)):
            files.append(path)
        if len(files) >= limit:
            break
    return files


def scoped_files(root: Path, values: list[str]) -> list[Path]:
    files = []
    for value in values:
        for piece in value.split(","):
            if not piece.strip():
                continue
            path = (root / piece.strip()).resolve()
            try:
                path.relative_to(root.resolve())
            except ValueError:
                continue
            if path.exists() and path.is_file() and not is_generated(path.relative_to(root)):
                files.append(path)
    return sorted(set(files))


def file_summary(root: Path, path: Path) -> dict[str, object]:
    rel = path.relative_to(root)
    text = ""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        pass
    lower = text.lower()
    tags = []
    for tag, patterns in RISK_PATTERNS.items():
        if any(pattern.lower() in lower or pattern.lower() in str(rel).lower() for pattern in patterns):
            tags.append(tag)
    return {
        "path": str(rel),
        "lines": text.count("\n") + (1 if text else 0),
        "bytes": path.stat().st_size,
        "tags": tags or ["general"],
    }


def build_packet(root: Path, files: list[Path], mode: str, depth: str, title: str) -> str:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    summaries = [file_summary(root, path) for path in files]
    tag_counts = {}
    for item in summaries:
        for tag in item["tags"]:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    file_rows = [
        f"| `{item['path']}` | {item['lines']} | {', '.join(item['tags'])} |"
        for item in summaries
    ]
    if not file_rows:
        file_rows = ["| _No files resolved_ | 0 | blocked |"]

    return "\n".join([
        "---",
        f"title: {title}",
        f"generated: {now}",
        f"mode: {mode}",
        f"depth: {depth}",
        f"files: {len(summaries)}",
        "---",
        "",
        f"# {title}",
        "",
        "## Hot Seat Brief",
        "",
        f"Mode: `{mode}`",
        f"Depth: `{depth}`",
        f"Repo: `{root}`",
        "",
        "Put the scoped work under pressure before it reaches users. The goal is not to sound harsh; the goal is to make weak proof impossible to hide.",
        "",
        "## Files In Scope",
        "",
        "| File | Lines | Risk Tags |",
        "|------|-------|-----------|",
        *file_rows,
        "",
        "## Risk Heat",
        "",
        *(f"- `{tag}`: {count}" for tag, count in sorted(tag_counts.items())),
        "",
        "## Jury Mode",
        "",
        "Run these lenses in order:",
        "",
        "1. **Breaker:** Find the input, state, timing, or dependency failure that breaks behavior.",
        "2. **Security:** Check injection, secret exposure, path/shell use, auth, and unsafe rendering.",
        "3. **Tester:** Name the assertion that would fail before the fix.",
        "4. **Refactorer:** Protect contracts and prove behavior did not change accidentally.",
        "5. **Release Captain:** Demand rollback, config, migration, log, and metric proof.",
        "6. **Maintainer:** Reduce future confusion, not just today's diff.",
        "",
        "## Questions That Must Hurt A Little",
        "",
        "- What invariant must never break here?",
        "- What bad input makes this code lie?",
        "- What dependency failure did we not simulate?",
        "- What proves this is wired into the real user path?",
        "- Which test would have failed yesterday?",
        "- What is the rollback if this ships wrong?",
        "- What would a second reviewer still block?",
        "",
        "## Proof Ladder",
        "",
        "- [ ] Syntax/type check touched files",
        "- [ ] Focused test for changed behavior",
        "- [ ] Integration or wiring proof",
        "- [ ] Security/abuse case considered",
        "- [ ] Release/rollback check when production-sensitive",
        "- [ ] Re-grill after fixes",
        "",
        "## Verdict Contract",
        "",
        "```markdown",
        "## VERDICT",
        "",
        "Decision: SHIP | SHIP WITH RISKS | DO NOT SHIP | BLOCKED",
        "Why:",
        "- ...",
        "Proof:",
        "- ...",
        "Remaining risks:",
        "- ...",
        "```",
        "",
    ])


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a CODE-GRILL-PACKET for a repo, diff, or explicit file scope.")
    parser.add_argument("--mode", choices=["plan", "diff", "repo", "release", "fix", "scope"], default="diff")
    parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard")
    parser.add_argument("--base", help="Optional git diff base, such as origin/main")
    parser.add_argument("--scope", action="append", default=[], help="Comma-separated file paths to include. Can be repeated.")
    parser.add_argument("--max-files", type=int, default=60, help="Maximum repo files to include when mode=repo.")
    parser.add_argument("--output", default="CODE-GRILL-PACKET.md")
    parser.add_argument("--title", default="CODE-GRILL-PACKET")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.max_files < 1:
        print("--max-files must be a positive integer.", file=sys.stderr)
        return 2

    root = repo_root(Path.cwd())
    packet_mode = args.mode
    if args.scope:
        files = scoped_files(root, args.scope)
        if packet_mode == "diff":
            packet_mode = "scope"
    elif args.mode == "repo":
        files = git_repo_files(root, args.max_files)
    else:
        files = git_diff_files(root, args.base)

    packet = build_packet(root, files, packet_mode, args.depth, args.title)
    output = Path(args.output)
    output.write_text(packet, encoding="utf-8")
    print(f"Wrote {output} with {len(files)} file(s).")
    if not files:
        print("No files resolved. Provide --scope, create a git diff, or use --mode repo.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
