#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys

from grill_runner import DEFAULT_CONFIG, merge_dicts, normalize_config, score_session


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str]) -> int:
    cases_path = Path(argv[0]) if argv else ROOT / "calibration" / "cases.json"
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    config = normalize_config(merge_dicts(DEFAULT_CONFIG, {}))
    failures = []
    for case in cases:
        score = score_session(
            [Path("subject.py")],
            case.get("findings", []),
            case.get("checks", []),
            test_files=int(case.get("test_files", 0)),
            code_files=int(case.get("code_files", 1)),
            config=config,
            diff_aware=bool(case.get("diff_aware", False)),
        )
        if score["verdict"] != case["expected_verdict"]:
            failures.append(f"{case['name']}: expected {case['expected_verdict']}, got {score['verdict']}")
        else:
            print(f"ok {case['name']}: {score['verdict']} risk={score['risk_score']} proof={score['proof_score']}")
    if failures:
        for failure in failures:
            print(f"calibration failed: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
