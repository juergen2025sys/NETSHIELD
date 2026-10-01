"""Regression tests for the Confidence Blacklist idempotency gate.

The production filter lives in update_confidence_blacklist.yml as a gh --jq
expression. These tests extract that exact expression and run it with jq against
representative GitHub Actions run metadata so cancelled/failed runs can never
suppress a fresh Combined-triggered Confidence run.
"""
from pathlib import Path
import json
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/update_confidence_blacklist.yml"
SELF_RUN_ID = 9000


def successful_run_jq():
    text = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        r'LAST_SUCCESSFUL=\$\(gh run list.*?--jq "((?:\\.|[^"\\])*)"\)',
        text,
        re.DOTALL,
    )
    if not match:
        raise AssertionError("LAST_SUCCESSFUL gh --jq expression not found")
    # Undo the shell escaping used inside the YAML block. ${SELF_RUN_ID} is
    # expanded by the shell in production; substitute the same value here.
    expr = match.group(1).replace(r'\"', '"').replace("${SELF_RUN_ID}", str(SELF_RUN_ID))
    return expr


def run_filter(runs):
    result = subprocess.run(
        ["jq", "-r", successful_run_jq()],
        input=json.dumps(runs),
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


class ConfidenceIdempotencyGateTests(unittest.TestCase):
    def test_cancelled_failed_and_timed_out_runs_do_not_block(self):
        runs = [
            {"databaseId": 1001, "updatedAt": "2026-09-15T06:52:45Z", "conclusion": "cancelled"},
            {"databaseId": 1002, "updatedAt": "2026-09-15T06:51:00Z", "conclusion": "failure"},
            {"databaseId": 1003, "updatedAt": "2026-09-15T06:50:00Z", "conclusion": "timed_out"},
        ]
        self.assertEqual(run_filter(runs), "")

    def test_most_recent_success_is_used_even_if_newer_cancelled_exists(self):
        runs = [
            {"databaseId": 2001, "updatedAt": "2026-09-15T06:52:45Z", "conclusion": "cancelled"},
            {"databaseId": 2002, "updatedAt": "2026-09-15T06:40:00Z", "conclusion": "success"},
            {"databaseId": 2003, "updatedAt": "2026-09-15T06:30:00Z", "conclusion": "success"},
        ]
        self.assertEqual(run_filter(runs), "2026-09-15T06:40:00Z")

    def test_current_run_is_excluded_even_if_marked_success(self):
        runs = [
            {"databaseId": SELF_RUN_ID, "updatedAt": "2026-09-15T06:59:00Z", "conclusion": "success"},
            {"databaseId": 3002, "updatedAt": "2026-09-15T06:40:00Z", "conclusion": "success"},
        ]
        self.assertEqual(run_filter(runs), "2026-09-15T06:40:00Z")

    def test_workflow_requests_conclusion_field_and_filters_success(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("--json databaseId,updatedAt,conclusion", text)
        self.assertIn('select(.conclusion == \\"success\\")', text)
        self.assertNotIn("LAST_FINISHED=", text)


if __name__ == "__main__":
    unittest.main()
