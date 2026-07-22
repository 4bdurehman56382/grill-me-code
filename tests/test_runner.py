import tempfile
from pathlib import Path
import sys
import contextlib
import io
import json
import os
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import grill_packet
import grill_learn
import grill_runner


class GrillRunnerTests(unittest.TestCase):
    def test_repo_priority_prefers_scripts_before_docs(self):
        docs = Path("README.md")
        script = Path("scripts/grill_runner.py")
        self.assertLess(grill_packet.repo_priority(script), grill_packet.repo_priority(docs))

    def test_scoped_files_rejects_paths_outside_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inside = root / "src.py"
            inside.write_text("print('ok')\n", encoding="utf-8")
            files = grill_packet.scoped_files(root, ["src.py,../outside.py"])
            self.assertEqual(files, [inside.resolve()])

    def test_static_findings_ignore_keywords_inside_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "rules.py"
            source.write_text('pattern = "eval("\\nhtml = "innerHTML"\\n', encoding="utf-8")
            self.assertEqual(grill_runner.static_findings(root, [source]), [])

    def test_static_findings_detect_executable_eval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "danger.py"
            source.write_text("eval(user_input)\n", encoding="utf-8")
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(findings[0]["severity"], "blocker")

    def test_static_findings_detect_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "download.py"
            source.write_text("open(request.args['path'])\n", encoding="utf-8")
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(findings[0]["code"], "SEC-005")

    def test_python_ast_detects_os_system_and_ignores_comment_eval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "danger.py"
            source.write_text("# eval(user_input)\nimport os\nos.system(user_input)\n", encoding="utf-8")
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["code"], "SEC-012")
            self.assertEqual(findings[0]["source"], "python-ast")

    def test_rule_priority_combines_same_line_highest_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "danger.py"
            source.write_text("eval(user_input)\n", encoding="utf-8")
            custom = grill_runner.StaticPattern("warning", "TEAM-001", re.compile(r"eval\("), "Team eval rule")
            findings = grill_runner.static_findings(root, [source], [custom, *grill_runner.BUILTIN_STATIC_PATTERNS])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "blocker")
            self.assertIn("TEAM-001", findings[0]["matched_codes"])

    def test_custom_config_pattern_and_suppression(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / ".grill-me-code.yaml"
            config_path.write_text(
                "\n".join([
                    "ignore_codes:",
                    "  - BUG-002",
                    "static_patterns:",
                    "  - code: TEAM-001",
                    "    severity: warning",
                    "    regex: dangerousCall\\(",
                    "    title: Team-specific dangerous call",
                ]),
                encoding="utf-8",
            )
            config, config_findings, _ = grill_runner.load_config(root, None)
            patterns, pattern_findings = grill_runner.compile_static_patterns(config)
            source = root / "app.js"
            source.write_text("dangerousCall(user)\n// TODO later\n", encoding="utf-8")
            raw = grill_runner.static_findings(root, [source], patterns)
            active, suppressed = grill_runner.split_suppressed_findings(raw, config, {"findings": []}, {"outcomes": []})
            self.assertEqual(config_findings + pattern_findings, [])
            self.assertEqual([finding["code"] for finding in active], ["TEAM-001"])
            self.assertEqual([finding["code"] for finding in suppressed], ["BUG-002"])

    def test_json_config_loading(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".grill-me-code.json").write_text(json.dumps({"thresholds": {"ship_with_risks_risk": 45}}), encoding="utf-8")
            config, findings, path = grill_runner.load_config(root, None)
            self.assertEqual(findings, [])
            self.assertEqual(path, ".grill-me-code.json")
            self.assertEqual(config["thresholds"]["ship_with_risks_risk"], 45)

    def test_baseline_suppresses_fingerprint(self):
        finding = {
            "id": "SEC-001-001",
            "severity": "blocker",
            "file": "danger.py",
            "title": "Dynamic code execution can become injection.",
            "evidence": "eval(user_input)",
            "source": "builtin-static",
        }
        grill_runner.annotate_findings([finding])
        baseline = {"findings": [{"fingerprint": finding["fingerprint"]}]}
        active, suppressed = grill_runner.split_suppressed_findings([finding], grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {})), baseline, {"outcomes": []})
        self.assertEqual(active, [])
        self.assertEqual(suppressed[0]["suppressed_by"], "baseline")

    def test_score_uses_blockers_for_do_not_ship(self):
        score = grill_runner.score_session(
            [Path("danger.py")],
            [{"severity": "blocker"}],
            [],
            test_files=0,
            code_files=1,
        )
        self.assertEqual(score["verdict"], "DO NOT SHIP")

    def test_plan_config_error_is_blocked_not_do_not_ship(self):
        score = grill_runner.score_session(
            [Path("app.py")],
            [{"severity": "blocked"}],
            [],
            test_files=0,
            code_files=1,
        )
        self.assertEqual(score["verdict"], "BLOCKED")
        self.assertEqual(score["risk_score"], 0)

    def test_non_code_scope_does_not_require_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dockerfile = root / "Dockerfile"
            dockerfile.write_text("FROM python:3.12\n", encoding="utf-8")
            config = grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {}))
            self.assertFalse(grill_runner.needs_test_proof([dockerfile], config))

    def test_markdown_report_includes_suppressed_summary(self):
        session = {
            "session_id": "sample",
            "generated": "2026-01-01T00:00:00+00:00",
            "mode": "scope",
            "depth": "standard",
            "files": ["app.py"],
            "config_path": ".grill-me-code.yaml",
            "baseline": {"path": ".grill-me-code/baseline.json"},
            "findings": [],
            "suppressed_findings": [{"id": "BUG-002-001", "title": "TODO", "file": "app.py", "line": 1, "suppressed_by": "baseline"}],
            "checks": {"results": [], "discovered": [], "run_project_checks": False},
            "gsd": {"detected": False},
            "score": {"verdict": "SHIP", "risk_score": 0, "proof_score": 80, "ship_score": 100},
        }
        report = grill_runner.markdown_report(session)
        self.assertIn("Suppressed findings: 1", report)
        self.assertIn("## Suppressed Findings", report)

    def test_discover_project_checks_reads_package_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"scripts":{"lint":"eslint .","test":"node test.js"}}', encoding="utf-8")
            names = [item["name"] for item in grill_runner.discover_project_checks(root)]
            self.assertIn("npm:lint", names)
            self.assertIn("npm:test", names)

    def test_discover_project_checks_makefile_and_plugin_missing_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Makefile").write_text("test:\n\ttrue\n", encoding="utf-8")
            config = grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {
                "check_plugins": [{"name": "missing-tool", "command": ["definitely-missing-grill-tool"], "kind": "test"}],
            }))
            checks = grill_runner.discover_project_checks(root, config)
            names = [item["name"] for item in checks]
            self.assertIn("make:test", names)
            self.assertIn("missing-tool", names)
            health = grill_runner.check_health_findings(root, checks)
            self.assertEqual(health[0]["severity"], "question")
            self.assertIn("missing-tool", health[0]["title"])

    def test_run_project_checks_records_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checks = [{"name": "fail", "kind": "test", "command": [sys.executable, "-c", "raise SystemExit(7)"]}]
            result = grill_runner.run_project_checks(root, checks, timeout=5)
            self.assertFalse(result[0]["ok"])
            self.assertEqual(result[0]["returncode"], 7)

    def test_run_command_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = grill_runner.run_command([sys.executable, "-c", "import time; time.sleep(2)"], root, timeout=1)
            self.assertTrue(result["timed_out"])

    def test_run_syntax_checks_parallel_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = root / "good.py"
            bad = root / "bad.py"
            good.write_text("print('ok')\n", encoding="utf-8")
            bad.write_text("def broken(:\n", encoding="utf-8")
            results = grill_runner.run_syntax_checks(root, [good, bad], timeout=5, jobs=2)
            self.assertEqual(len(results), 2)
            self.assertEqual(sum(1 for result in results if not result["ok"]), 1)

    def test_build_packet_output_contains_scope_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text("print('ok')\n", encoding="utf-8")
            packet = grill_packet.build_packet(root, [source], "scope", "standard", "CODE-GRILL-PACKET")
            self.assertIn("| `app.py` | 1 | general |", packet)
            self.assertIn("## Verdict Contract", packet)

    def test_runner_scope_without_scope_exits_loudly(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = grill_runner.main(["--mode", "scope"])
        self.assertEqual(code, 2)
        self.assertIn("requires at least one --scope", stderr.getvalue())

    def test_runner_fail_on_do_not_ship_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "danger.py").write_text("eval(user_input)\n", encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = grill_runner.main(["--scope", "danger.py", "--output-dir", ".out", "--fail-on-do-not-ship"])
            finally:
                os.chdir(old_cwd)
            session = json.loads((root / ".out" / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 1)
            self.assertEqual(session["score"]["verdict"], "DO NOT SHIP")

    def test_runner_missing_plan_file_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = grill_runner.main(["--scope", "app.py", "--plan", "missing-plan.md", "--output-dir", ".out", "--fail-on-do-not-ship"])
            finally:
                os.chdir(old_cwd)
            session = json.loads((root / ".out" / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 1)
            self.assertEqual(session["score"]["verdict"], "BLOCKED")
            self.assertEqual(session["findings"][0]["severity"], "blocked")

    def test_runner_write_baseline_suppresses_next_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "danger.py").write_text("eval(user_input)\n", encoding="utf-8")
            (root / ".grill-me-code.yaml").write_text("test_proof:\n  mode: off\n", encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    first_code = grill_runner.main(["--scope", "danger.py", "--output-dir", ".out", "--write-baseline"])
                    second_code = grill_runner.main(["--scope", "danger.py", "--output-dir", ".out"])
            finally:
                os.chdir(old_cwd)
            session = json.loads((root / ".out" / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual(first_code, 0)
            self.assertEqual(second_code, 0)
            self.assertEqual(session["findings"], [])
            self.assertEqual(len(session["suppressed_findings"]), 1)
            self.assertEqual(session["suppressed_findings"][0]["suppressed_by"], "baseline")

    def test_git_changed_lines_and_diff_aware_scoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.check_call(["git", "init", "-b", "main"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.check_call(["git", "config", "user.email", "test@example.com"], cwd=root)
            subprocess.check_call(["git", "config", "user.name", "Test"], cwd=root)
            source = root / "app.py"
            source.write_text("eval(old_input)\nprint('safe')\n", encoding="utf-8")
            subprocess.check_call(["git", "add", "app.py"], cwd=root)
            subprocess.check_call(["git", "commit", "-m", "base"], cwd=root, stdout=subprocess.DEVNULL)
            source.write_text("eval(old_input)\nos.system(user_input)\n", encoding="utf-8")
            changed = grill_runner.git_changed_lines(root, None)
            findings = grill_runner.annotate_diff_status(grill_runner.static_findings(root, [source]), changed)
            score = grill_runner.score_session([source], findings, [], test_files=1, code_files=1, diff_aware=True)
            statuses = {finding["line"]: finding["diff_status"] for finding in findings}
            self.assertEqual(statuses[1], "legacy")
            self.assertEqual(statuses[2], "introduced")
            self.assertEqual(score["introduced_blockers"], 1)
            self.assertEqual(score["legacy_blockers"], 1)
            self.assertEqual(score["verdict"], "DO NOT SHIP")

    def test_diff_aware_legacy_blocker_is_ship_with_risks(self):
        finding = {"id": "SEC-001-001", "severity": "blocker", "diff_status": "legacy"}
        score = grill_runner.score_session([Path("app.py")], [finding], [], test_files=1, code_files=1, diff_aware=True)
        self.assertEqual(score["legacy_blockers"], 1)
        self.assertEqual(score["introduced_blockers"], 0)
        self.assertEqual(score["verdict"], "SHIP WITH RISKS")

    def test_jury_scores_security_lens(self):
        findings = [{"id": "SEC-001-001", "code": "SEC-001", "severity": "blocker", "source": "python-ast"}]
        jury = grill_runner.jury_scores(findings, [], grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {})))
        self.assertEqual(jury["Security"]["verdict"], "DO NOT SHIP")
        self.assertEqual(jury["Security"]["findings"], 1)

    def test_session_diff_added_and_resolved(self):
        old = {"session_id": "old", "score": {"verdict": "DO NOT SHIP"}, "findings": [{"id": "A-001", "fingerprint": "old", "title": "old"}]}
        new = {"session_id": "new", "score": {"verdict": "SHIP"}, "findings": [{"id": "B-001", "fingerprint": "new", "title": "new"}]}
        diff = grill_runner.diff_sessions(old, new)
        self.assertEqual(len(diff["added"]), 1)
        self.assertEqual(len(diff["resolved"]), 1)
        self.assertIn("CODE-GRILL-SESSION-DIFF", grill_runner.markdown_session_diff(diff))

    def test_plan_mentions_file_requires_bounded_filename_match(self):
        self.assertFalse(grill_runner.plan_mentions_file("we need to test this", "src/test.py", "test.py"))
        self.assertTrue(grill_runner.plan_mentions_file("touch `src/test.py`", "src/test.py", "test.py"))

    def test_grill_learn_verifies_session_finding_and_stores_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "latest.json"
            store = root / "learnings.json"
            finding = {
                "id": "SEC-001-001",
                "severity": "blocker",
                "file": "danger.py",
                "title": "Dynamic code execution can become injection.",
                "evidence": "eval(user_input)",
                "source": "builtin-static",
            }
            grill_runner.annotate_findings([finding])
            session.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = grill_learn.main(["--finding", "SEC-001-001", "--outcome", "false_positive", "--session", str(session), "--store", str(store)])
            data = json.loads(store.read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertTrue(data["outcomes"][0]["session_verified"])
            self.assertEqual(data["outcomes"][0]["fingerprint"], finding["fingerprint"])

    def test_grill_learn_rejects_unknown_session_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "latest.json"
            store = root / "learnings.json"
            session.write_text(json.dumps({"findings": []}), encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = grill_learn.main(["--finding", "SEC-001-001", "--outcome", "false_positive", "--session", str(session), "--store", str(store)])
            self.assertEqual(code, 2)
            self.assertIn("was not found", stderr.getvalue())

    def test_detect_gsd_planning_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            phase = root / ".planning" / "phases" / "01-foundation"
            phase.mkdir(parents=True)
            (root / ".planning" / "STATE.md").write_text("# State\n", encoding="utf-8")
            (root / ".planning" / "ROADMAP.md").write_text("# Roadmap\n", encoding="utf-8")
            (phase / "01-01-PLAN.md").write_text("# Plan\n", encoding="utf-8")
            result = grill_runner.detect_gsd(root, "01")
            self.assertTrue(result["detected"])
            self.assertEqual(result["state"], ".planning/STATE.md")
            self.assertEqual(result["phase_dir"], ".planning/phases/01-foundation")
            self.assertIn(".planning/phases/01-foundation/01-01-PLAN.md", result["phase_files"])


if __name__ == "__main__":
    unittest.main()
