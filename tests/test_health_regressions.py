"""Health Checker must report regression failures without blocking its workflow."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_health_regressions as health


class HealthRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.output = self.folder / "result.json"
        self.log = self.folder / "tests.log"

    def fixture(self, mode="pass", required=True):
        class Example(unittest.TestCase):
            def runTest(self):
                if mode == "fail":
                    self.fail("deliberate regression")
                if mode == "error":
                    raise RuntimeError("deliberate execution error")
                if mode == "skip":
                    self.skipTest("missing dependency")
        case = Example()
        with contextlib.redirect_stderr(io.StringIO()):
            return health.run_suite(unittest.TestSuite([case]), "abc",
                                    {case.id()} if required else set())

    def save(self, result):
        self.output.write_text(json.dumps(result), encoding="utf-8")

    def test_success_is_reported_for_the_checked_commit(self):
        self.save(self.fixture())
        result = health.read_summary(self.output, "abc")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["tests_run"], 1)
        self.assertEqual(result["sha"], "abc")

    def test_failed_errored_and_skipped_required_tests_warn(self):
        for mode in ("fail", "error", "skip"):
            with self.subTest(mode=mode):
                self.save(self.fixture(mode))
                result = health.read_summary(self.output, "abc")
                self.assertEqual(result["status"], "warning")
                self.assertTrue(result["required_not_passed"])

    def test_future_additional_test_failure_is_also_reported(self):
        self.save(self.fixture("fail", required=False))
        result = health.read_summary(self.output, "abc")
        self.assertEqual(result["status"], "warning")
        self.assertEqual(len(result["failures"]), 1)

    def test_empty_suite_and_missing_known_regressions_cannot_pass(self):
        with contextlib.redirect_stderr(io.StringIO()):
            result = health.run_suite(unittest.TestSuite(), "abc", {"required.test"})
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["tests_run"], 0)
        self.assertEqual(result["missing_required"], ["required.test"])
        self.assertEqual(len(health.REQUIRED_TESTS), 27)

    def test_unverified_results_warn_instead_of_reusing_a_pass(self):
        result = self.fixture()
        for changes in ({"sha": "older"}, {"tests_run": 0}, {"status": "unknown"},
                        {"failures": ["broken.test"]}, {"failures": None},
                        {"status": "warning", "detail": 123}):
            with self.subTest(changes=changes):
                self.save(result | changes)
                self.assertEqual(health.read_summary(self.output, "abc")["status"], "warning")
        self.save(result)
        self.assertEqual(health.read_summary(self.output, "abc", "failure")["status"], "warning")
        self.output.write_text("{bad JSON", encoding="utf-8")
        self.assertEqual(health.read_summary(self.output, "abc")["status"], "warning")
        self.output.unlink()
        self.assertEqual(health.read_summary(self.output, "abc")["status"], "warning")

    def test_timeout_crash_and_start_failure_replace_old_success(self):
        passing = self.fixture()
        for mode in ("timeout", "crash", "start_error"):
            with self.subTest(mode=mode):
                self.save(passing)
                def fake_process(*args, **kwargs):
                    self.assertEqual(json.loads(self.output.read_text())["status"], "warning")
                    if mode == "timeout":
                        raise subprocess.TimeoutExpired(args[0], 180)
                    if mode == "start_error":
                        raise OSError("cannot start")
                    return subprocess.CompletedProcess(args[0], 1)
                with patch.object(health.subprocess, "run", side_effect=fake_process):
                    result = health.run_check(self.folder, self.output, self.log, "abc")
                self.assertEqual(result["status"], "warning")
                self.assertEqual(json.loads(self.output.read_text())["status"], "warning")

    def test_successful_child_result_is_used(self):
        passing = self.fixture()
        def fake_process(*args, **kwargs):
            self.save(passing)
            return subprocess.CompletedProcess(args[0], 0)
        with patch.object(health.subprocess, "run", side_effect=fake_process):
            result = health.run_check(self.folder, self.output, self.log, "abc")
        self.assertEqual(result["status"], "passed")

    def test_warning_cli_always_returns_success(self):
        stream = io.StringIO()
        with patch.object(health, "run_check", return_value=health.warning_result("abc", "test failed")), \
                contextlib.redirect_stdout(stream):
            status = health.main(["--root", str(self.folder), "--sha", "abc"])
        self.assertEqual(status, 0)
        self.assertIn("::warning", stream.getvalue())

    def test_worker_supports_repository_package_imports(self):
        scripts = self.folder / "scripts"
        tests = self.folder / "tests"
        scripts.mkdir()
        tests.mkdir()
        (scripts / "__init__.py").write_text("", encoding="utf-8")
        (scripts / "fixture.py").write_text("VALUE = 42\n", encoding="utf-8")
        (tests / "test_fixture.py").write_text(
            "import unittest\nfrom scripts.fixture import VALUE\n"
            "class FixtureTest(unittest.TestCase):\n"
            "    def test_value(self):\n        self.assertEqual(VALUE, 42)\n", encoding="utf-8")
        process = subprocess.run([sys.executable, str(Path(health.__file__).resolve()),
                                  "--worker", "--root", str(self.folder),
                                  "--output", str(self.output), "--sha", "abc"],
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(result["tests_run"], 1)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["failures"], [])
        self.assertEqual(len(result["missing_required"]), 27)

    def test_workflow_only_adds_warnings_and_preserves_commit_step(self):
        path = ROOT / ".github/workflows/workflow_health_checker.yml"
        source = path.read_text(encoding="utf-8")
        workflow = yaml.safe_load(source)
        steps = workflow["jobs"]["check-python-code"]["steps"]
        test_step = next(s for s in steps if s.get("id") == "regression_tests")
        self.assertTrue(test_step["continue-on-error"])
        self.assertIn("check_health_regressions.py", test_step["run"])
        check_step = next(s for s in steps if s.get("name") == "Check Python Code in all Workflow Files")
        self.assertLess(steps.index(test_step), steps.index(check_step))
        commit = next(s for s in steps if s.get("name") == "Commit")
        self.assertEqual(commit["if"], "always()")
        start = source.index("          _regression_sha =")
        end = source.index("          # ── Check 1:", start)
        code = textwrap.dedent(source[start:end])
        env = {"os": os, "warnings": [], "errors": []}
        with patch.dict(os.environ, {"GITHUB_SHA": "abc", "REGRESSION_STEP_OUTCOME": "failure"}), \
                patch.object(health, "read_summary", return_value=health.warning_result("abc", "failed test")), \
                contextlib.redirect_stdout(io.StringIO()):
            exec(compile(code, str(path), "exec"), env)
        self.assertEqual(len(env["warnings"]), 1)
        self.assertEqual(env["errors"], [])
        self.assertIn('"regression_tests":  _regression_health', source)

    def test_existing_report_and_status_record_warning_without_error(self):
        path = ROOT / ".github/workflows/workflow_health_checker.yml"
        source = path.read_text(encoding="utf-8")
        start = source.index("          # ── Zusammenfassung")
        end = source.index("\n          EOF", start)
        code = textwrap.dedent(source[start:end])
        result = health.warning_result("abc", "Bekannter Regressionstest fehlgeschlagen")
        env = {
            "errors": [], "warnings": [{"file": "Regressionstests", "check": "Testsuite", "detail": result["detail"]}],
            "results": {}, "files": [], "now_str": "2026-09-12", "prod_health": [],
            "_ph_critical": [], "_ph_warn": [], "_sanity_checks": [], "_current_parts": {},
            "_regression_health": result, "_regression_sha": "abc",
            "write_text_atomic": health.write_text_atomic, "write_json_atomic": health.write_json_atomic,
        }
        previous = Path.cwd()
        try:
            os.chdir(self.folder)
            Path("reports").mkdir()
            Path("state").mkdir()
            with contextlib.redirect_stdout(io.StringIO()):
                exec(compile(code, str(path), "exec"), env)
            status = json.loads(Path("state/workflow_health_status.json").read_text(encoding="utf-8"))
            report = Path("reports/workflow_health_report.md").read_text(encoding="utf-8")
        finally:
            os.chdir(previous)
        self.assertEqual(status["error"], 0)
        self.assertEqual(status["warn"], 1)
        self.assertEqual(status["regression_tests"]["status"], "warning")
        self.assertIn("Bekannter Regressionstest fehlgeschlagen", report)
        self.assertIn("Commit: `abc`", report)


if __name__ == "__main__":
    unittest.main()
