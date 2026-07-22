import tempfile
from pathlib import Path
import sys
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import grill_packet
import grill_learn
import github_annotations
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

    def test_non_git_repo_mode_falls_back_to_directory_walk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text("print('ok')\n", encoding="utf-8")
            self.assertEqual(grill_packet.git_repo_files(root, 10), [source])

    def test_staged_diff_files_are_distinct_from_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.check_call(["git", "init", "-b", "main"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.check_call(["git", "config", "user.email", "test@example.com"], cwd=root)
            subprocess.check_call(["git", "config", "user.name", "Test"], cwd=root)
            staged = root / "staged.py"
            worktree = root / "worktree.py"
            staged.write_text("print('base')\n", encoding="utf-8")
            worktree.write_text("print('base')\n", encoding="utf-8")
            subprocess.check_call(["git", "add", "staged.py", "worktree.py"], cwd=root)
            subprocess.check_call(["git", "commit", "-m", "base"], cwd=root, stdout=subprocess.DEVNULL)
            staged.write_text("print('staged')\n", encoding="utf-8")
            subprocess.check_call(["git", "add", "staged.py"], cwd=root)
            worktree.write_text("print('unstaged')\n", encoding="utf-8")
            staged_only = [path.name for path in grill_packet.git_diff_files(root, None, "staged")]
            all_diff = [path.name for path in grill_packet.git_diff_files(root, None, "all")]
            self.assertEqual(staged_only, ["staged.py"])
            self.assertEqual(sorted(all_diff), ["staged.py", "worktree.py"])

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

    def test_static_findings_do_not_flag_cache_signature_compare(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "cache.py"
            source.write_text('if cached.get("sha256") == digest and cached.get("signature") == signature:\n    pass\n', encoding="utf-8")
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(findings, [])

    def test_large_file_limit_records_skipped_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            huge = root / "huge.js"
            huge.write_text("x" * 128, encoding="utf-8")
            config = grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {"scan": {"max_file_bytes": 10}}))
            files, findings, skipped = grill_runner.filter_scan_files(root, [huge], config)
            self.assertEqual(files, [])
            self.assertEqual(skipped[0]["path"], "huge.js")
            self.assertEqual(findings[0]["code"], "SCAN-SKIP")

    def test_python_ast_detects_os_system_and_ignores_comment_eval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "danger.py"
            source.write_text("# eval(user_input)\nimport os\nos.system(user_input)\n", encoding="utf-8")
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["code"], "SEC-012")
            self.assertEqual(findings[0]["source"], "python-ast")

    def test_python_taint_detects_indirect_path_sink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text(
                "def view(request):\n"
                "    target = request.args['file']\n"
                "    return open(target).read()\n",
                encoding="utf-8",
            )
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(findings[0]["code"], "SEC-005")
            self.assertEqual(findings[0]["source"], "python-taint")

    def test_js_semantic_detects_eval_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.js"
            source.write_text("const run = eval;\nrun(userInput);\n", encoding="utf-8")
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(findings[0]["code"], "SEC-001")
            self.assertEqual(findings[0]["source"], "js-semantic")

    def test_js_semantic_detects_child_process_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.js"
            source.write_text("const { exec: run } = require('child_process');\nrun(userInput);\n", encoding="utf-8")
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(findings[0]["code"], "SEC-012")
            self.assertEqual(findings[0]["source"], "js-semantic")

    def test_js_taint_detects_indirect_filesystem_sink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.js"
            source.write_text(
                "const fs = require('fs');\n"
                "const target = req.query.file;\n"
                "fs.readFileSync(target);\n",
                encoding="utf-8",
            )
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(findings[0]["code"], "SEC-005")
            self.assertEqual(findings[0]["source"], "js-taint")

    def test_test_assertion_metrics_flags_empty_and_trivial_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "empty.test.js"
            trivial = root / "test_app.py"
            empty.write_text("describe('x', () => {});\n", encoding="utf-8")
            trivial.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
            metrics = grill_runner.test_assertion_metrics(root, [empty, trivial])
            self.assertEqual(metrics["test_files"], 2)
            self.assertEqual(metrics["assertions"], 1)
            self.assertEqual(metrics["trivial_assertions"], 1)
            self.assertEqual(metrics["files_without_assertions"], ["empty.test.js"])

    def test_test_assertion_metrics_detects_common_js_frameworks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_file = root / "app.test.js"
            test_file.write_text(
                "t.is(actual, expected);\n"
                "value.should.equal(1);\n"
                "await expect(promise).rejects.toThrow();\n",
                encoding="utf-8",
            )
            metrics = grill_runner.test_assertion_metrics(root, [test_file])
            self.assertEqual(metrics["assertions"], 3)
            self.assertEqual(metrics["trivial_assertions"], 0)

    def test_truthiness_assertion_with_value_is_not_trivial(self):
        self.assertTrue(grill_runner.is_trivial_assert_text("assert True"))
        self.assertFalse(grill_runner.is_trivial_assert_text("self.assertTrue(result.ok)"))
        self.assertFalse(grill_runner.is_trivial_assert_text("expect(result.ok).toBe(true)"))

    def test_compiled_semantic_detects_go_exec_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "main.go"
            source.write_text("package main\nfunc run(user string) { exec.Command(user) }\n", encoding="utf-8")
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(findings[0]["code"], "SEC-012")
            self.assertEqual(findings[0]["source"], "compiled-semantic")

    def test_compiled_semantic_detects_dart_process_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "main.dart"
            source.write_text("void run(user) { Process.run(user, []); }\n", encoding="utf-8")
            findings = grill_runner.static_findings(root, [source])
            self.assertEqual(findings[0]["code"], "SEC-012")
            self.assertEqual(findings[0]["source"], "compiled-semantic")

    def test_compiled_semantic_detects_java_runtime_exec(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "App.java"
            source.write_text('class App { void run(String user) { Runtime.getRuntime().exec(user); } }\n', encoding="utf-8")
            findings = grill_runner.compiled_language_semantic_findings(root, [source])
            self.assertEqual(findings[0]["code"], "SEC-012")
            self.assertEqual(findings[0]["source"], "compiled-semantic")

    def test_cross_file_flow_detects_imported_sink_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sink = root / "exec.js"
            app = root / "app.js"
            sink.write_text("export function runCommand(cmd) { exec(cmd); }\n", encoding="utf-8")
            app.write_text("import { runCommand } from './exec';\nrunCommand(req.query.cmd);\n", encoding="utf-8")
            findings = grill_runner.static_findings(root, [sink, app])
            self.assertTrue(any(finding["source"] == "cross-file-flow" for finding in findings))

    def test_minimalism_lite_detects_scoped_dependency_bloat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "package.json"
            package.write_text('{"dependencies":{"moment":"^2.0.0"}}\n', encoding="utf-8")
            config = grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {}))
            findings = grill_runner.minimalism_findings(root, [package], config)
            self.assertEqual(findings[0]["code"], "MIN-001")
            self.assertEqual(findings[0]["source"], "minimalism")
            self.assertIn("Intl.DateTimeFormat", findings[0]["evidence"])

    def test_minimalism_ignores_unscoped_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text("print('ok')\n", encoding="utf-8")
            (root / "package.json").write_text('{"dependencies":{"lodash":"^4.0.0"}}\n', encoding="utf-8")
            config = grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {}))
            self.assertEqual(grill_runner.minimalism_findings(root, [source], config), [])

    def test_minimalism_full_detects_wrapper_and_speculative_interface(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text(
                "from abc import ABC\n"
                "class PaymentGateway(ABC):\n"
                "    pass\n"
                "def send_payment(order):\n"
                "    return charge(order)\n",
                encoding="utf-8",
            )
            config = grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {"minimalism": {"mode": "full"}}))
            findings = grill_runner.minimalism_findings(root, [source], config)
            codes = {finding["code"] for finding in findings}
            self.assertIn("MIN-002", codes)
            self.assertIn("MIN-003", codes)

    def test_minimalism_off_suppresses_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "package.json"
            package.write_text('{"dependencies":{"moment":"^2.0.0"}}\n', encoding="utf-8")
            config = grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {"minimalism": {"mode": "off"}}))
            self.assertEqual(grill_runner.minimalism_findings(root, [package], config), [])

    def test_cached_static_findings_reuses_unchanged_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text("eval(user_input)\n", encoding="utf-8")
            patterns = list(grill_runner.BUILTIN_STATIC_PATTERNS)
            signature = grill_runner.scanner_signature(patterns)
            cache = {"version": grill_runner.SCANNER_CACHE_VERSION, "files": {}}
            first, cache, first_stats = grill_runner.cached_static_findings(root, [source], patterns, cache, True, signature)
            second, cache, second_stats = grill_runner.cached_static_findings(root, [source], patterns, cache, True, signature)
            self.assertEqual(first[0]["code"], "SEC-001")
            self.assertEqual(second[0]["code"], "SEC-001")
            self.assertEqual(first_stats["misses"], 1)
            self.assertEqual(second_stats["hits"], 1)

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

    def test_preset_loading_adds_framework_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config, findings, path = grill_runner.load_config(root, None, ["django"])
            patterns, pattern_findings = grill_runner.compile_static_patterns(config)
            self.assertEqual(findings + pattern_findings, [])
            self.assertEqual(path, "django")
            self.assertTrue(any(pattern.code == "DJANGO-001" for pattern in patterns))

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
            "skipped_files": [],
            "config_path": ".grill-me-code.yaml",
            "baseline": {"path": ".grill-me-code/baseline.json"},
            "findings": [],
            "suppressed_findings": [{"id": "BUG-002-001", "title": "TODO", "file": "app.py", "line": 1, "suppressed_by": "baseline"}],
            "checks": {"results": [], "discovered": [], "run_project_checks": False},
            "test_assertions": {"test_files": 1, "assertions": 1, "trivial_assertions": 0},
            "reasoning": [{"name": "reason", "ok": True, "output": "looks good"}],
            "cache": {"enabled": True, "path": ".grill-me-code/cache.json", "hits": 1, "misses": 0},
            "gsd": {"detected": False},
            "score": {"verdict": "SHIP", "risk_score": 0, "risk_band": "none", "proof_score": 80, "proof_band": "strong", "ship_score": 100, "verdict_reasons": ["clean"]},
        }
        report = grill_runner.markdown_report(session)
        self.assertIn("Suppressed findings: 1", report)
        self.assertIn("## Suppressed Findings", report)
        self.assertIn("## Test Proof", report)
        self.assertIn("## Reasoning Plugins", report)
        self.assertIn("## Cache", report)

    def test_discover_project_checks_reads_package_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"scripts":{"lint":"eslint .","test":"node test.js"}}', encoding="utf-8")
            names = [item["name"] for item in grill_runner.discover_project_checks(root)]
            self.assertIn("npm:lint", names)
            self.assertIn("npm:test", names)

    def test_discover_project_checks_adds_npm_audit_for_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package-lock.json").write_text("{}", encoding="utf-8")
            checks = grill_runner.discover_project_checks(root)
            npm_audit = next(item for item in checks if item["name"] == "npm:audit")
            self.assertEqual(npm_audit["kind"], "security")

    def test_discover_project_checks_adds_broader_dependency_audits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.lock").write_text("", encoding="utf-8")
            (root / "composer.lock").write_text("{}", encoding="utf-8")
            names = [item["name"] for item in grill_runner.discover_project_checks(root)]
            self.assertIn("cargo:audit", names)
            self.assertIn("composer:audit", names)

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

    def test_discover_project_checks_mobile_toolchains_and_npx_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Package.swift").write_text("// swift package\n", encoding="utf-8")
            (root / "pubspec.yaml").write_text("name: app\n", encoding="utf-8")
            (root / "build.gradle.kts").write_text("plugins {}\n", encoding="utf-8")
            config = grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {
                "check_plugins": [{"name": "eslint-npx", "command": ["npx", "eslint", "."], "kind": "static-analysis"}],
            }))
            checks = grill_runner.discover_project_checks(root, config)
            names = [item["name"] for item in checks]
            self.assertIn("swift:test", names)
            self.assertTrue("dart:test" in names or "flutter:test" in names)
            self.assertIn("gradle:test", names)
            npx_check = next(item for item in checks if item["name"] == "eslint-npx")
            if shutil.which("npx"):
                self.assertIn("eslint", npx_check.get("missing_reason", ""))

    def test_analysis_plugin_findings_are_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin = root / "plugin.py"
            plugin.write_text(
                "import json, sys\n"
                "json.load(sys.stdin)\n"
                "print(json.dumps({'findings':[{'id':'PLUGIN-001','severity':'warning','title':'plugin finding','file':'app.py','line':1,'source':'plugin'}]}))\n",
                encoding="utf-8",
            )
            plugins = [{"name": "plugin", "command": [sys.executable, str(plugin)], "kind": "analysis"}]
            findings, results = grill_runner.run_analysis_plugins(root, plugins, {"files": []}, timeout=5)
            self.assertTrue(results[0]["ok"])
            self.assertEqual(findings[0]["id"], "PLUGIN-001")

    def test_analysis_plugin_jsonl_and_schema_warnings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin = root / "plugin.py"
            plugin.write_text(
                "print('{\"progress\":\"half\"}')\n"
                "print('{\"finding\":{\"id\":\"PLUGIN-001\",\"severity\":\"wild\",\"title\":\"bad severity\",\"file\":\"../outside.py\"}}')\n",
                encoding="utf-8",
            )
            plugins = [{"name": "plugin", "command": [sys.executable, str(plugin)], "kind": "analysis"}]
            findings, results = grill_runner.run_analysis_plugins(root, plugins, {"files": []}, timeout=5)
            self.assertEqual(results[0]["events"], 1)
            self.assertTrue(any(finding["code"] == "ANALYSIS-SCHEMA" for finding in findings))
            self.assertTrue(any(finding["code"] == "ANALYSIS-SCHEMA-PATH" for finding in findings))
            self.assertTrue(any(finding["id"] == "PLUGIN-001" and finding["severity"] == "question" for finding in findings))

    def test_reasoning_plugin_output_is_captured(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin = root / "reason.py"
            plugin.write_text("import sys, json\njson.load(sys.stdin)\nprint('reasoned')\n", encoding="utf-8")
            plugins = [{"name": "reason", "command": [sys.executable, str(plugin)], "kind": "reasoning"}]
            outputs, findings = grill_runner.run_reasoning_plugins(root, plugins, {"score": {}}, timeout=5)
            self.assertEqual(findings, [])
            self.assertEqual(outputs[0]["output"].strip(), "reasoned")

    def test_reasoning_plugin_structured_output_adds_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin = root / "reason.py"
            plugin.write_text(
                "import sys, json\n"
                "json.load(sys.stdin)\n"
                "print(json.dumps({'summary':'reviewed','verdict':'SHIP WITH RISKS','questions':['what proof is missing?'],'findings':[{'severity':'warning','title':'reasoned risk','file':'app.py','line':2}]}))\n",
                encoding="utf-8",
            )
            plugins = [{"name": "reason", "command": [sys.executable, str(plugin)], "kind": "reasoning"}]
            outputs, findings = grill_runner.run_reasoning_plugins(root, plugins, {"score": {}}, timeout=5)
            self.assertEqual(outputs[0]["structured"]["verdict"], "SHIP WITH RISKS")
            self.assertEqual(findings[0]["source"], "reasoning-plugin:reason")
            self.assertEqual(findings[0]["severity"], "warning")
            self.assertEqual(findings[0]["code"], "REASONING")

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

    def test_runner_init_writes_config_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    first = grill_runner.main(["--init"])
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    second = grill_runner.main(["--init"])
            finally:
                os.chdir(old_cwd)
            config_text = (root / ".grill-me-code.yaml").read_text(encoding="utf-8")
            self.assertEqual(first, 0)
            self.assertEqual(second, 2)
            self.assertIn("detected_languages: Python", config_text)
            self.assertIn("force-init", stderr.getvalue())

    def test_runner_minimalism_cli_persists_mode_and_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"dependencies":{"moment":"^2.0.0"}}\n', encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = grill_runner.main(["--scope", "package.json", "--minimalism", "lite", "--output-dir", ".out"])
            finally:
                os.chdir(old_cwd)
            session = json.loads((root / ".out" / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(session["minimalism"]["mode"], "lite")
            self.assertTrue(any(finding["code"] == "MIN-001" for finding in session["findings"]))

    def test_runner_writes_sarif_and_trend_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = grill_runner.main(["--scope", "app.py", "--output-dir", ".out"])
            finally:
                os.chdir(old_cwd)
            session = json.loads((root / ".out" / "latest.json").read_text(encoding="utf-8"))
            sarif = json.loads((root / ".out" / "CODE-GRILL.sarif").read_text(encoding="utf-8"))
            trends = json.loads((root / ".out" / "trends.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(trends["entries"][0]["session_id"], session["session_id"])
            self.assertEqual(session["trend"]["entries"], 1)

    def test_runner_auto_baseline_on_ship(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "test_app.py").write_text("def test_ok():\n    assert 1 == 1\n", encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = grill_runner.main(["--scope", "app.py,test_app.py", "--output-dir", ".out", "--auto-baseline-on-ship"])
            finally:
                os.chdir(old_cwd)
            session = json.loads((root / ".out" / "latest.json").read_text(encoding="utf-8"))
            baseline = json.loads((root / ".grill-me-code" / "baseline.json").read_text(encoding="utf-8"))
            self.assertEqual(code, 0)
            self.assertTrue(session["baseline"]["auto_written"])
            self.assertEqual(baseline["version"], 1)

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

    def test_resolve_diff_base_auto_uses_merge_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.check_call(["git", "init", "-b", "main"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.check_call(["git", "config", "user.email", "test@example.com"], cwd=root)
            subprocess.check_call(["git", "config", "user.name", "Test"], cwd=root)
            (root / "app.py").write_text("print('base')\n", encoding="utf-8")
            subprocess.check_call(["git", "add", "app.py"], cwd=root)
            subprocess.check_call(["git", "commit", "-m", "base"], cwd=root, stdout=subprocess.DEVNULL)
            expected = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            subprocess.check_call(["git", "checkout", "-b", "feature"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (root / "app.py").write_text("print('feature')\n", encoding="utf-8")
            subprocess.check_call(["git", "commit", "-am", "feature"], cwd=root, stdout=subprocess.DEVNULL)
            resolved, info = grill_runner.resolve_diff_base(root, "auto")
            self.assertEqual(resolved, expected)
            self.assertEqual(info["strategy"], "merge-base")

    def test_diff_aware_legacy_blocker_is_ship_with_risks(self):
        finding = {"id": "SEC-001-001", "severity": "blocker", "diff_status": "legacy"}
        score = grill_runner.score_session([Path("app.py")], [finding], [], test_files=1, code_files=1, diff_aware=True)
        self.assertEqual(score["legacy_blockers"], 1)
        self.assertEqual(score["introduced_blockers"], 0)
        self.assertEqual(score["legacy_risk_level"], "medium")
        self.assertEqual(score["verdict"], "SHIP WITH RISKS")

    def test_jury_scores_security_lens(self):
        findings = [{"id": "SEC-001-001", "code": "SEC-001", "severity": "blocker", "source": "python-ast"}]
        jury = grill_runner.jury_scores(findings, [], grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {})))
        self.assertEqual(jury["Security"]["verdict"], "DO NOT SHIP")
        self.assertEqual(jury["Security"]["findings"], 1)

    def test_jury_scores_minimalist_lens(self):
        findings = [{"id": "MIN-001-001", "code": "MIN-001", "severity": "question", "source": "minimalism"}]
        jury = grill_runner.jury_scores(findings, [], grill_runner.normalize_config(grill_runner.merge_dicts(grill_runner.DEFAULT_CONFIG, {})))
        self.assertEqual(jury["Minimalist"]["findings"], 1)
        self.assertEqual(jury["Minimalist"]["risk_score"], 5)

    def test_session_diff_added_and_resolved(self):
        old = {"session_id": "old", "score": {"verdict": "DO NOT SHIP"}, "findings": [{"id": "A-001", "fingerprint": "old", "title": "old"}]}
        new = {"session_id": "new", "score": {"verdict": "SHIP"}, "findings": [{"id": "B-001", "fingerprint": "new", "title": "new"}]}
        diff = grill_runner.diff_sessions(old, new)
        self.assertEqual(len(diff["added"]), 1)
        self.assertEqual(len(diff["resolved"]), 1)
        self.assertIn("CODE-GRILL-SESSION-DIFF", grill_runner.markdown_session_diff(diff))

    def test_sarif_report_maps_findings_to_results(self):
        finding = {"id": "SEC-001-001", "code": "SEC-001", "severity": "blocker", "file": "app.py", "line": 3, "title": "Danger", "source": "test"}
        session = {"session_id": "s", "score": {"verdict": "DO NOT SHIP"}, "findings": [finding]}
        sarif = grill_runner.sarif_report(session)
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")
        self.assertEqual(sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app.py")

    def test_runner_since_session_attaches_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            previous = root / "old.json"
            previous.write_text(json.dumps({"session_id": "old", "score": {"verdict": "DO NOT SHIP"}, "findings": [{"id": "OLD-001", "fingerprint": "old-risk", "title": "old"}]}), encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = grill_runner.main(["--scope", "app.py", "--output-dir", ".out", "--since-session", "old.json"])
            finally:
                os.chdir(old_cwd)
            session = json.loads((root / ".out" / "latest.json").read_text(encoding="utf-8"))
            report = (root / ".out" / "CODE-GRILL-REPORT.md").read_text(encoding="utf-8")
            self.assertEqual(code, 0)
            self.assertEqual(session["session_delta"]["old_session_id"], "old")
            self.assertIn("## Session Delta", report)

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

    def test_grill_learn_deduplicates_same_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "latest.json"
            store = root / "learnings.json"
            finding = {"id": "SEC-001-001", "severity": "blocker", "file": "danger.py", "title": "Danger", "evidence": "eval(x)", "source": "builtin-static"}
            grill_runner.annotate_findings([finding])
            session.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
            args = ["--finding", "SEC-001-001", "--outcome", "false_positive", "--session", str(session), "--store", str(store)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(grill_learn.main(args), 0)
                self.assertEqual(grill_learn.main(args), 0)
            data = json.loads(store.read_text(encoding="utf-8"))
            self.assertEqual(len(data["outcomes"]), 1)
            self.assertEqual(data["outcomes"][0]["count"], 2)

    def test_github_annotations_emit_file_line(self):
        session = {
            "findings": [{
                "id": "SEC-001-001",
                "severity": "blocker",
                "file": "app.py",
                "line": 7,
                "title": "Danger",
                "source": "test",
                "diff_status": "introduced",
                "evidence": "eval(x)",
            }]
        }
        lines = github_annotations.annotation_lines(session)
        self.assertIn("::error file=app.py,line=7", lines[0])
        self.assertIn("SEC-001-001", lines[0])

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
