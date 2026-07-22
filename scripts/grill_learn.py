#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Record whether a grill finding was useful, noisy, or accepted risk.")
    parser.add_argument("--finding", required=True, help="Finding id, such as SEC-001-001.")
    parser.add_argument("--outcome", required=True, choices=["real_bug", "false_positive", "accepted_risk", "needs_followup"])
    parser.add_argument("--session", default=".grill-me-code/latest.json")
    parser.add_argument("--store", default=".grill-me-code/learnings.json")
    parser.add_argument("--note", default="")
    args = parser.parse_args(argv)

    store = Path(args.store)
    data = load(store)
    entry = {
        "finding": args.finding,
        "outcome": args.outcome,
        "session": args.session,
        "note": args.note,
        "recorded": utc_now(),
    }
    data.setdefault("outcomes", []).append(entry)
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Recorded {args.finding} as {args.outcome} in {store}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
