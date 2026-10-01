#!/usr/bin/env python3
"""Run the repository tests for Health Checker reporting; findings only warn."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from netshield_common import write_json_atomic, write_text_atomic

ROOT = Path(__file__).resolve().parents[1]
# REQUIRED_REGRESSIONS: maintained with the known Combined bug regressions.
REQUIRED_TESTS = frozenset({
    'test_combined_fixes_20260912.CombinedFixTests.test_batched_export_has_identical_bytes_and_does_not_mutate_db',
    'test_combined_fixes_20260912.CombinedFixTests.test_confirmation_ack_requires_all_feeds_in_restored_db',
    'test_combined_fixes_20260912.CombinedFixTests.test_confirmation_survives_partial_upload_and_next_run',
    'test_combined_fixes_20260912.CombinedFixTests.test_confirmed_recovery_survives_seven_day_boundary_and_long_interruption',
    'test_combined_fixes_20260912.CombinedFixTests.test_cross_confirmation_still_obeys_active_expiry',
    'test_combined_fixes_20260912.CombinedFixTests.test_cross_confirmation_survives_commit_reopen_and_next_run',
    'test_combined_fixes_20260912.CombinedFixTests.test_every_new_state_publication_waits_for_both_history_backups',
    'test_combined_fixes_20260912.CombinedFixTests.test_existing_frozen_ip_gets_five_feed_reentry_after_daily_cap',
    'test_combined_fixes_20260912.CombinedFixTests.test_export_cache_eviction_and_database_updates_keep_correct_values',
    'test_combined_fixes_20260912.CombinedFixTests.test_export_failure_keeps_previous_file_and_removes_tempfile',
    'test_combined_fixes_20260912.CombinedFixTests.test_five_feeds_with_one_hq_family_cannot_promote_frozen_ip_to_active',
    'test_combined_fixes_20260912.CombinedFixTests.test_four_feeds_cannot_reset_a_frozen_watchlist_anchor',
    'test_combined_fixes_20260912.CombinedFixTests.test_history_upload_errors_block_the_step_and_all_new_state_outputs',
    'test_combined_fixes_20260912.CombinedFixTests.test_invalid_backups_abort_instead_of_replacing_history',
    'test_combined_fixes_20260912.CombinedFixTests.test_invalid_feed_json_during_export_does_not_replace_old_output',
    'test_combined_fixes_20260912.CombinedFixTests.test_missing_backups_allow_first_run',
    'test_combined_fixes_20260912.CombinedFixTests.test_missing_hits_clear_only_current_counters_and_survive_reopen',
    'test_combined_fixes_20260912.CombinedFixTests.test_mixed_quarantine_counts_only_remaining_live_feeds',
    'test_combined_fixes_20260912.CombinedFixTests.test_quarantined_hits_clear_counters_but_keep_historical_quality',
    'test_combined_fixes_20260912.CombinedFixTests.test_restore_distinguishes_absent_release_from_api_and_download_errors',
    'test_combined_fixes_20260912.CombinedFixTests.test_seven_day_boundary_and_same_feed_do_not_change',
    'test_combined_fixes_20260912.CombinedFixTests.test_split_backups_and_legacy_ledger_entries_load',
    'test_combined_fixes_20260912.CombinedFixTests.test_successful_or_unchanged_history_does_not_block_publication',
    'test_combined_fixes_20260912.CombinedFixTests.test_two_hq_families_remove_both_old_ledgers_for_existing_ip',
    'test_combined_fixes_20260912.CombinedFixTests.test_unconfirmed_old_feed_still_expires',
    'test_combined_fixes_20260912.CombinedFixTests.test_unfrozen_existing_watchlist_does_not_reset_first',
    'test_combined_fixes_20260912.CombinedFixTests.test_waitlist_cap_keeps_unacknowledged_confirmations',
})


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = set()

    def addSuccess(self, test):
        self.passed.add(test.id())
        super().addSuccess(test)


def run_suite(suite, sha, required=REQUIRED_TESTS):
    discovered = set(test_ids(suite))
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    missing = sorted(required - discovered)
    not_passed = sorted((required & discovered) - result.passed)
    problems = bool(not result.wasSuccessful() or not result.testsRun or missing or not_passed)
    return {
        "schema": 1, "sha": sha,
        "status": "warning" if problems else "passed",
        "tests_run": result.testsRun,
        "failures": [test.id() for test, _ in result.failures],
        "errors": [test.id() for test, _ in result.errors],
        "skipped": [{"test": test.id(), "reason": str(reason)} for test, reason in result.skipped],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        "missing_required": missing, "required_not_passed": not_passed,
    }


def warning_result(sha, detail):
    return {"schema": 1, "sha": sha, "status": "warning", "detail": detail, "tests_run": 0}


def read_summary(path, expected_sha, step_outcome="success"):
    try:
        result = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(result, dict) or result.get("schema") != 1:
            raise ValueError("ungueltiges Ergebnisformat")
        if result.get("sha") != expected_sha:
            raise ValueError("Testergebnis gehoert zu einem anderen Commit")
        if step_outcome != "success":
            raise ValueError("Testschritt wurde nicht erfolgreich abgeschlossen")
        count = result.get("tests_run")
        if type(count) is not int or count < 0:
            raise ValueError("ungueltige Testanzahl")
        if result.get("status") == "passed":
            fields = ("failures", "errors", "skipped", "unexpected_successes",
                      "missing_required", "required_not_passed")
            if not count or any(not isinstance(result.get(key), list) for key in fields):
                raise ValueError("unvollstaendiger Testnachweis")
            if any(result[key] for key in fields if key != "skipped"):
                raise ValueError("Testergebnis enthaelt fehlgeschlagene oder fehlende Pruefungen")
        elif result.get("status") != "warning":
            raise ValueError("unbekannter Teststatus")
        for key in ("failures", "errors", "skipped", "unexpected_successes",
                    "missing_required", "required_not_passed"):
            if key in result and not isinstance(result[key], list):
                raise ValueError("ungueltige Ergebnisliste")
        if "detail" in result and not isinstance(result["detail"], str):
            raise ValueError("ungueltige Ergebnisbeschreibung")
    except (OSError, ValueError, TypeError) as exc:
        return warning_result(expected_sha, f"Regressionstests nicht verifiziert: {exc}")
    if result.get("status") == "passed" and result.get("skipped"):
        result["status"] = "warning"
        result["detail"] = f"{count} Tests ausgefuehrt, {len(result['skipped'])} Pruefung(en) uebersprungen."
    if "detail" not in result:
        result["detail"] = (
            f"{count} Tests; {len(result.get('failures', []))} Fehlschlaege, "
            f"{len(result.get('errors', []))} Ausfuehrungsfehler, "
            f"{len(result.get('skipped', []))} uebersprungen, "
            f"{len(result.get('unexpected_successes', []))} unerwartete Testerfolge, "
            f"{len(result.get('missing_required', []))} fehlende Pflichtpruefungen, "
            f"{len(result.get('required_not_passed', []))} Pflichtpruefungen nicht bestanden."
        )
        names = list(dict.fromkeys(result.get("failures", []) + result.get("errors", [])
                    + result.get("missing_required", []) + result.get("required_not_passed", [])
                    + result.get("unexpected_successes", [])))
        if names:
            result["detail"] += " Betroffen: " + ", ".join(names[:10])
    return result


def run_check(root, output, log_path, sha, timeout=180):
    output, log_path = Path(output).resolve(), Path(log_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # Invalidate any older result before starting; crashes must not reuse a pass.
    write_json_atomic(str(output), warning_result(sha, "Testlauf noch nicht abgeschlossen"))
    try:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as log:
            try:
                process = subprocess.run(
                    [sys.executable, str(Path(__file__).resolve()), "--worker", "--root", str(root),
                     "--output", str(output), "--sha", sha], cwd=root,
                    stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
            finally:
                log.seek(0)
                write_text_atomic(str(log_path), log.read())
        if process.returncode:
            result = warning_result(sha, f"Testprozess abgebrochen (Exit {process.returncode}); siehe Testlog.")
        else:
            result = read_summary(output, sha)
    except subprocess.TimeoutExpired:
        result = warning_result(sha, f"Regressionstests nach {timeout} Sekunden abgebrochen (Zeitlimit).")
    except OSError as exc:
        result = warning_result(sha, f"Regressionstests konnten nicht gestartet werden: {exc}")
    write_json_atomic(str(output), result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=Path("health_regressions.json"))
    parser.add_argument("--log", type=Path, default=Path("health_regressions.log"))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", "local"))
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker:
        # Match `python -m unittest` import paths, including `scripts.*` imports.
        sys.path.insert(0, str(args.root.resolve()))
        suite = unittest.defaultTestLoader.discover(str(args.root / "tests"), pattern="test*.py")
        write_json_atomic(str(args.output), run_suite(suite, args.sha))
        return 0
    result = run_check(args.root.resolve(), args.output, args.log, args.sha)
    if args.log.is_file():
        print("::group::Regressionstests - vollstaendiges Testlog")
        print(args.log.read_text(encoding="utf-8", errors="replace"))
        print("::endgroup::")
    detail = result["detail"].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    prefix = "::warning title=Regressionstests::" if result["status"] != "passed" else "Regressionstests: "
    print(f"{prefix}{detail} Commit: {args.sha}")
    return 0  # Health Checker is advisory; the separate Run Tests CI still fails normally.


if __name__ == "__main__":
    raise SystemExit(main())
