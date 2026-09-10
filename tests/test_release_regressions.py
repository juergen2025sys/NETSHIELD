"""Release regression tests for workflow-level security invariants."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from netshield_common import is_valid_public_ipv4


WORKFLOW_DIR = ROOT / ".github" / "workflows"


def _workflow_text(name: str) -> str:
    return (WORKFLOW_DIR / name).read_text(encoding="utf-8")


def test_cgnat_is_not_public_in_central_policy():
    """CGNAT must never be accepted as a public threat IPv4."""
    assert not is_valid_public_ipv4("100.64.0.1")
    assert not is_valid_public_ipv4("100.127.255.254")
    assert is_valid_public_ipv4("8.8.8.8")


def test_tweetfeed_uses_central_public_ipv4_policy():
    text = _workflow_text("tweetfeed_monitor.yml")
    assert "is_valid_public_ipv4" in text
    assert not re.search(r"^\s*def\s+is_(?:private|valid_ipv4)\s*\(", text, re.MULTILINE)
    assert "is_valid_ipv4(ip) and not is_private(ip)" not in text


def test_honigtopf_uses_central_public_ipv4_policy():
    text = _workflow_text("honigtopf.yml")
    assert "is_valid_public_ipv4" in text
    assert not re.search(r"^\s*def\s+is_(?:private|valid_ipv4)\s*\(", text, re.MULTILINE)
    assert "is_valid_ipv4(ip) and not is_private(ip)" not in text
    assert "and not is_private(ip)" not in text


def test_cache_save_steps_keep_safety_guards_and_always():
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
            assert f"if: always() && {condition}" in text


def test_release_commit_steps_have_always_guards():
    expected = {
        "feed_overlap_report.yml": "Commit overlap report",
        "auto_feed_refresh.yml": "Commit Report und Kompatibilitaetsliste",
        "workflow_health_dashboard.yml": "Commit and Push",
    }
    for name, step_name in expected.items():
        text = _workflow_text(name)
        pattern = rf"- name: {re.escape(step_name)}\n\s+if: always\(\)"
        assert re.search(pattern, text), f"{name}: {step_name} lacks if: always()"
