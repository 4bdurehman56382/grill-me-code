#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


LEVELS = {
    "blocked": "error",
    "blocker": "error",
    "warning": "warning",
    "question": "notice",
    "nit": "notice",
}


def escape(value: object) -> str:
    text = str(value or "")
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def load_session(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"could not read session: {error}", file=sys.stderr)
        return {}


def annotation_lines(session: dict) -> list[str]:
    lines = []
    for finding in session.get("findings", []):
        if not isinstance(finding, dict):
            continue
        level = LEVELS.get(str(finding.get("severity", "question")), "notice")
        file_path = escape(finding.get("file", ""))
        line = int(finding.get("line") or 1)
        title = escape(f"{finding.get('id', 'CODE-GRILL')} {finding.get('title', '')}".strip())
        message = escape(f"{finding.get('severity', 'question')} {finding.get('source', 'unknown')} {finding.get('diff_status', 'scope')}: {finding.get('evidence', '')}")
        if file_path:
            lines.append(f"::{level} file={file_path},line={line},title={title}::{message}")
        else:
            lines.append(f"::{level} title={title}::{message}")
    return lines


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Emit GitHub Actions annotations from a CODE-GRILL session JSON.")
    parser.add_argument("--session", default=".grill-me-code/latest.json")
    args = parser.parse_args(argv)
    session = load_session(Path(args.session))
    if not session:
        return 2
    for line in annotation_lines(session):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
