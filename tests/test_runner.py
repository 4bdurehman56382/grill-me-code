import tempfile
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import grill_packet
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

    def test_score_uses_blockers_for_do_not_ship(self):
        score = grill_runner.score_session(
            [Path("danger.py")],
            [{"severity": "blocker"}],
            [],
            test_files=0,
            code_files=1,
        )
        self.assertEqual(score["verdict"], "DO NOT SHIP")

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
