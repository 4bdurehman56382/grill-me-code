#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sys


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def load(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "outcomes": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"version": 1, "outcomes": []}


def finding_code(identifier: str) -> str:
    return re.sub(r"(?:-(?:AST|JS|COMPILED))?-\d{3}$", "", identifier)


def finding_fingerprint(finding: dict) -> str:
    parts = [
        str(finding.get("source", "")),
        finding_code(str(finding.get("id", ""))),
        str(finding.get("file", "")),
        str(finding.get("title", "")),
        str(finding.get("evidence", "")).strip(),
    ]
    return "|".join(parts)


def find_session_finding(session: dict, finding_id: str) -> dict | None:
    for key in ["findings", "raw_findings", "suppressed_findings"]:
        for finding in session.get(key, []):
            if isinstance(finding, dict) and finding.get("id") == finding_id:
                return finding
    return None


def dedup_key(entry: dict) -> tuple[str, str]:
    return (str(entry.get("fingerprint") or entry.get("finding")), str(entry.get("outcome")))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Record whether a grill finding was useful, noisy, or accepted risk.")
    parser.add_argument("--finding", required=True, help="Finding id, such as SEC-001-001.")
    parser.add_argument("--outcome", required=True, choices=["real_bug", "false_positive", "accepted_risk", "needs_followup"])
    parser.add_argument("--session", default=".grill-me-code/latest.json")
    parser.add_argument("--store", default=".grill-me-code/learnings.json")
    parser.add_argument("--note", default="")
    parser.add_argument("--require-session", action="store_true", help="Fail when --session is missing instead of recording an unverified outcome.")
    args = parser.parse_args(argv)

    store = Path(args.store)
    data = load(store)
    session_path = Path(args.session)
    session_verified = False
    session_finding = None
    if session_path.exists():
        session = load(session_path)
        session_finding = find_session_finding(session, args.finding)
        if not session_finding:
            print(f"finding {args.finding} was not found in {session_path}", file=sys.stderr)
            return 2
        session_verified = True
    elif args.require_session:
        print(f"session file not found: {session_path}", file=sys.stderr)
        return 2

    entry = {
        "finding": args.finding,
        "outcome": args.outcome,
        "session": args.session,
        "session_verified": session_verified,
        "note": args.note,
        "recorded": utc_now(),
    }
    if session_finding:
        entry["fingerprint"] = session_finding.get("fingerprint") or finding_fingerprint(session_finding)
        entry["finding_snapshot"] = {
            "id": session_finding.get("id"),
            "code": session_finding.get("code") or finding_code(str(session_finding.get("id", ""))),
            "severity": session_finding.get("severity"),
            "file": session_finding.get("file", ""),
            "line": session_finding.get("line"),
            "title": session_finding.get("title", ""),
            "source": session_finding.get("source", ""),
        }
    outcomes = data.setdefault("outcomes", [])
    key = dedup_key(entry)
    for existing in outcomes:
        if isinstance(existing, dict) and dedup_key(existing) == key:
            existing["count"] = int(existing.get("count", 1)) + 1
            existing["last_recorded"] = entry["recorded"]
            existing["session"] = entry["session"]
            existing["session_verified"] = entry["session_verified"]
            if entry.get("fingerprint"):
                existing["fingerprint"] = entry["fingerprint"]
            if entry.get("finding_snapshot"):
                existing["finding_snapshot"] = entry["finding_snapshot"]
            if args.note:
                notes = existing.setdefault("notes", [])
                if isinstance(notes, list) and args.note not in notes:
                    notes.append(args.note)
            break
    else:
        entry["count"] = 1
        if args.note:
            entry["notes"] = [args.note]
        outcomes.append(entry)
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    suffix = " with session fingerprint" if session_verified else " without session verification"
    print(f"Recorded {args.finding} as {args.outcome} in {store}{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
