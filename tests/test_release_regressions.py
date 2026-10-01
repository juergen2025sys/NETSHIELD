"""Release regression tests for workflow-level security invariants."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from netshield_common import is_valid_public_ipv4


WORKFLOW_DIR = ROOT / ".github" / "workflows"


def _workflow_text(name: str) -> str:
    return (WORKFLOW_DIR / name).read_text(encoding="utf-8")


class TestReleaseRegressions(unittest.TestCase):
    """Regression tests that must be collected by unittest discover and pytest."""

    def test_cgnat_is_not_public_in_central_policy(self):
        """CGNAT must never be accepted as a public threat IPv4."""
        self.assertFalse(is_valid_public_ipv4("100.64.0.1"))
        self.assertFalse(is_valid_public_ipv4("100.127.255.254"))
        self.assertTrue(is_valid_public_ipv4("8.8.8.8"))

    def test_tweetfeed_uses_central_public_ipv4_policy(self):
        text = _workflow_text("tweetfeed_monitor.yml")
        self.assertIn("is_valid_public_ipv4", text)
        self.assertIsNone(re.search(r"^\s*def\s+is_(?:private|valid_ipv4)\s*\(", text, re.MULTILINE))
        self.assertNotIn("is_valid_ipv4(ip) and not is_private(ip)", text)

    def test_honigtopf_uses_central_public_ipv4_policy(self):
        text = _workflow_text("honigtopf.yml")
        self.assertIn("is_valid_public_ipv4", text)
        self.assertIsNone(re.search(r"^\s*def\s+is_(?:private|valid_ipv4)\s*\(", text, re.MULTILINE))
        self.assertNotIn("is_valid_ipv4(ip) and not is_private(ip)", text)
        self.assertNotIn("and not is_private(ip)", text)

    def test_cache_save_steps_keep_safety_guards_and_always(self):
        checks = {
            "auto_feed_refresh.yml": ["steps.refresh.outcome == 'success'"],
            "update_combined_blacklist.yml": [
                "steps.build_combined.outcome == 'success' && steps.shrink_guard.outputs.ok == 'true' && hashFiles('seen_db.json') != ''",
                "steps.build_combined.outcome == 'success' && hashFiles('state/watchlist_daily_cap_state.json') != ''",
                "steps.build_combined.outcome == 'success' && steps.shrink_guard.outputs.ok == 'true' && hashFiles('seen_db.sqlite3') != ''",
            ],
        }
        for name, conditions in checks.items():
            text = _workflow_text(name)
            for condition in conditions:
                self.assertIn(f"if: always() && {condition}", text)

    def test_release_commit_steps_have_always_guards(self):
        expected = {
            "feed_overlap_report.yml": "Commit overlap report",
            "auto_feed_refresh.yml": "Commit Report und Kompatibilitaetsliste",
            "workflow_health_dashboard.yml": "Commit and Push",
        }
        for name, step_name in expected.items():
            text = _workflow_text(name)
            pattern = rf"- name: {re.escape(step_name)}\n\s+if: always\(\)"
            self.assertIsNotNone(re.search(pattern, text), f"{name}: {step_name} lacks if: always()")
