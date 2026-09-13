"""Exercise the actual Combined restore/cleanup code and bounded JSON export.

No GitHub requests: the restore tests replace gh with a local shell function.
"""
import ast
import contextlib
from datetime import datetime, timedelta, timezone
import glob
import gzip
import io
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import netshield_common as nc

WORKFLOW = ROOT / ".github/workflows/update_combined_blacklist.yml"


def workflow_section(start, end):
    source = WORKFLOW.read_text(encoding="utf-8")
    begin = source.index("          " + start)
    finish = source.index("          " + end, begin)
    return textwrap.dedent(source[begin:finish])


class CombinedFixTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        previous = Path.cwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(temp.name)
        self.directory = Path(temp.name)
        Path("state").mkdir()

    def db(self):
        db = nc.SqliteSeenDB(str(self.directory / "seen.sqlite3"))
        self.addCleanup(db.close)
        return db

    def load_state(self):
        env = {"json": json, "glob": glob}
        code = workflow_section("import glob as _glob_ledger", "# jeweils über")
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile(code, str(WORKFLOW), "exec"), env)
        return env

    def test_invalid_backups_abort_instead_of_replacing_history(self):
        for name, message in [
            ("watchlist_expired_history", "Watchlist-Ledger"),
            ("active_expired_history", "Active-Ledger"),
            ("aufnahme_warteliste", "Aufnahme-Warteliste"),
        ]:
            valid = gzip.compress(b'{"entries":{"45.1.0.1":"2026-09-01"}}')
            for payload in [b"broken gzip", valid[:-8], gzip.compress(b"{broken"),
                            gzip.compress(b"{}"), gzip.compress(b'{"entries":[]}')]:
                with self.subTest(name=name, payload=payload[:20]):
                    path = Path(f"state/{name}.json.gz.part000")
                    path.write_bytes(payload)
                    try:
                        with self.assertRaisesRegex(RuntimeError, message):
                            self.load_state()
                        self.assertEqual(path.read_bytes(), payload)
                        self.assertEqual(list(Path("state").glob("*_upload.json")), [])
                    finally:
                        path.unlink()

    def test_split_backups_and_legacy_ledger_entries_load(self):
        for name in ("watchlist_expired_history", "active_expired_history", "aufnahme_warteliste"):
            entry = {"feed_a": "2026-09-11"} if name == "aufnahme_warteliste" else "2026-08-01"
            payload = gzip.compress(json.dumps({"entries": {"45.1.0.1": entry}}).encode())
            middle = len(payload) // 2
            for index, part in enumerate((payload[:middle], payload[middle:])):
                Path(f"state/{name}.json.gz.part{index:03}").write_bytes(part)
        env = self.load_state()
        self.assertEqual(env["_wl_expired_first"]["45.1.0.1"]["first"], "2026-08-01")
        self.assertEqual(env["_active_expired_last"]["45.1.0.1"]["last"], "2026-08-01")
        self.assertEqual(env["_aufnahme_wartend"], {"45.1.0.1": {"feed_a": "2026-09-11"}})

    def test_missing_backups_allow_first_run(self):
        env = self.load_state()
        for name in ("_wl_expired_first", "_active_expired_last", "_aufnahme_wartend"):
            self.assertEqual(env[name], {})

    def cleanup(self, db, waiting, day="2026-09-12", *, ledger=None, active=None, cap_used=True,
                waiting_dirty=False):
        now = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        env = dict(
            db=db, now=now, now_day=day, datetime=datetime, timedelta=timedelta,
            json=json, sys=sys, _time=time, coerce_bool=nc.coerce_bool,
            AUFNAHME_WARTEN_TAGE=7, WATCHLIST_DAILY_CAP=2000,
            _aufnahme_wartend=waiting, _aufnahme_wartend_dirty=waiting_dirty,
            _active_expired_last=active if active is not None else {}, _active_expired_last_dirty=False,
            _wl_expired_first=ledger if ledger is not None else {}, _wl_expired_first_dirty=False,
            _wl_cap_heute_bereits_gelaufen=cap_used, _wl_kandidaten=[],
            WATCHLIST_CAP_STATE_FILE="state/watchlist_daily_cap_state.json",
            _wl_cap_day=day, write_json_atomic=nc.write_json_atomic,
            _wl_aeltestes_first="9999-12-31", _ac_aeltestes_last="9999-12-31",
            _cln_total=len(db), _cln_processed=0, _cln_last_report=time.monotonic(),
            _cln_loop_t0=time.monotonic(), _UPD_PROGRESS_INTERVAL_S=15,
            _fast_is_wl_or_fp=lambda ip: False, _fast_is_protected=lambda ip: False,
            cutoff_wl_str=(now - timedelta(days=30)).strftime("%Y-%m-%d"),
            cutoff_str=(now - timedelta(days=180)).strftime("%Y-%m-%d"),
            _to_drop=[], expired=[], expired_active_count=0, expired_watchlist_count=0,
            aufnahme_cross_bestaetigt=0, aufnahme_removed=0, _corrupt_dropped=0,
            cidr_aggr_removed=0, wl_cleanup_count=0, protected_removed_runtime=0,
        )
        code = workflow_section("_datum_cache = {}", '_phase_mark("Cleanup-Pass')
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile(code, str(WORKFLOW), "exec"), env)
        self.assertEqual(env["_corrupt_dropped"], 0)
        return env

    def ingest(self, db, hits, *, day="2026-09-12", ledger=None, active=None,
               hq_names=frozenset(), quarantine=frozenset(), families=None, waiting=None):
        """Run the real SQL preparation and update loop with a local hit table."""
        conn = db._conn
        conn.execute("CREATE TEMP TABLE IF NOT EXISTS run_feed_hits("
                     "ip TEXT, feed TEXT, is_hq INTEGER, PRIMARY KEY(ip,feed))")
        conn.execute("DELETE FROM temp.run_feed_hits")
        conn.executemany("INSERT INTO temp.run_feed_hits VALUES(?,?,?)",
                         [(ip, feed, int(feed in hq_names))
                          for ip, feeds in hits.items() for feed in feeds])
        db.commit()
        now = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        env = dict(db=db, sys=sys, json=json, _time=time, _itertools=itertools, _run_conn=conn,
                   _aufnahme_wartend=waiting if waiting is not None else {},
                   _aufnahme_wartend_dirty=False,
                   now=now, now_day=day, _upd_processed=0, _upd_last_report=time.monotonic(),
                   _UPD_PROGRESS_INTERVAL_S=15, _upd_loop_t0=time.monotonic(), _upd_total=len(hits),
                   _fast_is_wl_or_fp=lambda _: False, _QUARANTINE=set(quarantine),
                   _HQ_AND_LOCAL=set(hq_names), HQ_FEED_FAMILIES=families or {},
                   _wl_expired_first=ledger if ledger is not None else {},
                   _active_expired_last=active if active is not None else {},
                   _wl_expired_first_dirty=False, _active_expired_last_dirty=False,
                   _upd_diag_sql_s=0, _upd_diag_sql_n=0, neu_angelegt_ohne_ledger=0)
        iterator = ast.parse(workflow_section("def _iter_today_feed_groups():",
                            "# FIX BUG-NAMEERROR-NEUANGELEGT")).body[0]
        family = ast.parse(workflow_section("def _hq_families_of(hq_feed_names):",
                          "# ══════════════════════════════════════════════════════════════")).body[0]
        nodes = ast.parse(workflow_section("_UPD_COMMIT_EVERY =", "WATCHLIST_DAILY_CAP =")).body
        end = next(i for i, node in enumerate(nodes) if isinstance(node, ast.For)
                   and isinstance(node.iter, ast.Call)
                   and isinstance(node.iter.func, ast.Name)
                   and node.iter.func.id == "_iter_today_feed_groups")
        code = ast.Module(body=[iterator, family, *nodes[:end + 1]], type_ignores=[])
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile(code, str(WORKFLOW), "exec"), env)
        db.commit()
        return env

    def test_existing_frozen_ip_gets_five_feed_reentry_after_daily_cap(self):
        db = self.db()
        ip = "45.1.0.1"
        ledger = {ip: {"first": "2026-08-01", "eingefroren_am": "2026-09-10"}}
        self.ingest(db, {ip: {"a", "b"}}, day="2026-09-11", ledger=ledger)
        self.cleanup(db, {}, "2026-09-11", ledger=ledger, cap_used=True)
        self.assertIn(ip, db)
        self.assertEqual(db[ip]["first"], "2026-08-01")
        result = self.ingest(db, {ip: {"a", "b", "c", "d", "e"}}, ledger=ledger)
        self.assertEqual(db[ip]["first"], "2026-09-12")
        self.assertEqual(db[ip]["last"], "2000-01-01")
        self.assertEqual(ledger, {})
        self.assertTrue(result["_wl_expired_first_dirty"])
        result = self.cleanup(db, {}, ledger=ledger, cap_used=False)
        self.assertIn(ip, db)
        self.assertEqual(result["expired_watchlist_count"], 0)

    def test_four_feeds_cannot_reset_a_frozen_watchlist_anchor(self):
        db = self.db()
        ip = "45.1.0.1"
        db[ip] = self.entry(first="2026-08-01")
        ledger = {ip: {"first": "2026-08-01", "eingefroren_am": "2026-09-10"}}
        self.ingest(db, {ip: {"a", "b", "c", "d"}}, ledger=ledger)
        self.assertEqual(db[ip]["first"], "2026-08-01")
        self.assertIn(ip, ledger)
        self.cleanup(db, {}, ledger=ledger, cap_used=False)
        self.assertNotIn(ip, db)

    def test_five_feeds_with_one_hq_family_cannot_promote_frozen_ip_to_active(self):
        db = self.db()
        ip = "45.1.0.1"
        db[ip] = self.entry(first="2026-08-01")
        ledger = {ip: {"first": "2026-08-01", "eingefroren_am": "2026-09-10"}}
        self.ingest(db, {ip: {"a", "b", "c", "hq_a1", "hq_a2"}}, ledger=ledger,
                    hq_names={"hq_a1", "hq_a2"}, families={"hq_a1": "a", "hq_a2": "a"})
        self.assertEqual(db[ip]["first"], "2026-09-12")
        self.assertEqual(db[ip]["last"], "2000-01-01")
        self.assertEqual(ledger, {})

    def test_two_hq_families_remove_both_old_ledgers_for_existing_ip(self):
        db = self.db()
        ip = "45.1.0.1"
        db[ip] = self.entry(first="2026-08-01")
        ledger = {ip: {"first": "2026-08-01", "eingefroren_am": "2026-09-10"}}
        active = {ip: {"last": "2026-01-01", "eingefroren_am": "2026-09-10"}}
        self.ingest(db, {ip: {"hq_a", "hq_b"}}, ledger=ledger, active=active,
                    hq_names={"hq_a", "hq_b"})
        self.assertEqual(db[ip]["last"], "2026-09-12")
        self.assertEqual(db[ip]["first"], "2026-08-01")
        self.assertEqual(ledger, {})
        self.assertEqual(active, {})

    def test_unfrozen_existing_watchlist_does_not_reset_first(self):
        db = self.db()
        ip = "45.1.0.1"
        db[ip] = self.entry(first="2026-08-20")
        self.ingest(db, {ip: {"a", "b", "c", "d", "e"}})
        self.assertEqual(db[ip]["first"], "2026-08-20")

    def test_missing_hits_clear_only_current_counters_and_survive_reopen(self):
        db = self.db()
        ip = "45.1.0.1"
        self.ingest(db, {ip: {"hq_a", "b", "c", "d", "e"}},
                    day="2026-09-11", hq_names={"hq_a"})
        previous = db[ip]
        self.ingest(db, {})
        self.assertEqual(db[ip], previous | {"today_count": 0, "today_hq": False})
        db.close()
        self.assertEqual(self.db()[ip], previous | {"today_count": 0, "today_hq": False})

    def test_quarantined_hits_clear_counters_but_keep_historical_quality(self):
        db = self.db()
        ip = "45.1.0.1"
        self.ingest(db, {ip: {"hq_a"}}, day="2026-09-11", hq_names={"hq_a"})
        previous = db[ip]
        self.ingest(db, {ip: {"hq_a"}}, hq_names={"hq_a"}, quarantine={"hq_a"})
        self.assertEqual(db[ip], previous | {"today_count": 0, "today_hq": False})

    def test_mixed_quarantine_counts_only_remaining_live_feeds(self):
        db = self.db()
        ip = "45.1.0.1"
        self.ingest(db, {ip: {"hq_a", "b"}}, day="2026-09-11", hq_names={"hq_a"})
        self.ingest(db, {ip: {"hq_a", "b"}}, hq_names={"hq_a"}, quarantine={"hq_a"})
        self.assertEqual(db[ip]["today_count"], 1)
        self.assertFalse(db[ip]["today_hq"])
        self.assertTrue(db[ip]["hq"])

    @staticmethod
    def publication_allowed(condition, outcomes, guard="true"):
        """Evaluate the real workflow's conjunctions with simulated outcomes."""
        allowed = True
        for clause in condition.split("&&"):
            clause = clause.strip()
            if clause == "always()":
                continue
            match = re.fullmatch(r"steps\.([a-z_]+)\.outcome == 'success'", clause)
            if match:
                allowed &= outcomes.get(match[1]) == "success"
            elif clause == "steps.shrink_guard.outputs.ok == 'true'":
                allowed &= guard == "true"
            elif re.fullmatch(r"hashFiles\('[^']+'\) != ''", clause):
                # Model a complete local build: every output exists.
                continue
            else:
                raise AssertionError(f"Unrecognised publication condition: {clause}")
        return allowed

    def test_every_new_state_publication_waits_for_both_history_backups(self):
        steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["update"]["steps"]
        history_names = ("Aufnahme-Warteliste zu Release sichern (komprimiert)",
                         "Anti-Churn-Ledger zu Release sichern (komprimiert)")
        publishers = {"Save seen_db JSON Compatibility Cache", "Save seen_db SQLite Cache",
                      "Backup seen_db SQLite to GitHub Release", "Save Watchlist Daily Cap State Cache",
                      "Commit and Push"}
        history = [(i, s) for i, s in enumerate(steps) if s.get("name") in history_names]
        self.assertEqual(len(history), 2)
        history_ids = [s.get("id") for _, s in history]
        self.assertEqual(set(history_ids), {"persist_waitlist", "persist_ledgers"})
        found = set()
        for index, step in enumerate(steps):
            if step.get("name") not in publishers:
                continue
            found.add(step["name"])
            self.assertGreater(index, max(i for i, _ in history), step["name"])
            ready = {"build_combined": "success", **dict.fromkeys(history_ids, "success")}
            self.assertTrue(self.publication_allowed(step["if"], ready), step["name"])
            self.assertFalse(self.publication_allowed(step["if"], ready, guard="false"))
            for failed_id in ("build_combined", *history_ids):
                for outcome in ("failure", "skipped", "cancelled"):
                    with self.subTest(step=step["name"], failed_id=failed_id, outcome=outcome):
                        self.assertFalse(self.publication_allowed(step["if"], ready | {failed_id: outcome}))
        self.assertEqual(found, publishers)

    def history_upload(self, step, prefix, mode, *, changed=True, payload=None):
        shell = os.environ.get("NETSHIELD_TEST_BASH") or shutil.which("bash")
        if not shell:
            self.skipTest("Bash required for workflow shell regression")
        if changed:
            Path(f"state/{prefix}_upload.json").write_text(
                json.dumps(payload if payload is not None else {"entries": {}}), encoding="utf-8")
            Path(f"state/{prefix}.json.gz.part000").write_bytes(b"fixture")
        # Exercise the actual shell branching; compression, file deletion and
        # GitHub are replaced. No system command or remote mutation is performed.
        mock = r'''
rm() { :; }
gzip() { printf 'compressed-fixture'; }
split() { :; }
ls() { for p in "$@"; do if [ -f "$p" ]; then printf '%s\n' "$p"; fi; done; }
wc() { printf '1\n'; }
tr() { printf '1\n'; }
du() { printf '1K total\n'; }
tail() { printf '1K total\n'; }
awk() { printf '1K\n'; }
xargs() { while IFS= read -r p; do printf '%s\n' "${p##*/}"; done; }
grep() {
  if [ "$1" = -qxF ]; then
    while IFS= read -r line; do if [ "$line" = "$2" ]; then return 0; fi; done
    return 1
  fi
  while IFS= read -r line; do printf '%s\n' "$line"; done
}
gh() {
  case "$2" in
    view)
      if [ "$MODE" = create_error ]; then return 1; fi
      if [[ "$*" == *"--json assets"* ]]; then
        printf '%s.json.gz.part000\n' "$PREFIX"
        if [ "$MODE" = delete_error ]; then printf '%s.json.gz.part001\n' "$PREFIX"; fi
      fi ;;
    upload)
      printf 'UPLOAD_ATTEMPT\n' >&2
      if [ "$MODE" = upload_error ]; then return 1; fi ;;
    create) printf 'CREATE_ATTEMPT\n' >&2; return 1 ;;
    delete-asset) printf 'DELETE_ATTEMPT\n' >&2; return 1 ;;
  esac
  return 0
}
'''
        if "scripts/netshield_history.py" in step["run"]:
            # These tests exercise the real shell gates; the helper's durable
            # commit and every interrupted upload/rename are covered separately
            # with an immutable local asset store in test_combined_state_safety.
            mock += r'''
python3() {
  printf 'UPLOAD_ATTEMPT\n' >&2
  if [ "$MODE" = upload_error ] || [ "$MODE" = create_error ]; then return 1; fi
  return 0
}
'''
        try:
            code = step["run"].replace("${{ github.repository }}", "fixture/repo")
            return subprocess.run([shell, "-e", "-o", "pipefail", "-c",
                                   mock + code + "\nprintf 'STEP_FINISHED\\n'"],
                                  capture_output=True, text=True, cwd=self.directory,
                                  env=os.environ | {"MODE": mode, "PREFIX": prefix})
        finally:
            for p in Path("state").glob(prefix + "*"):
                p.unlink()

    def test_history_upload_errors_block_the_step_and_all_new_state_outputs(self):
        steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["update"]["steps"]
        cases = [("Aufnahme-Warteliste zu Release sichern (komprimiert)", "aufnahme_warteliste"),
                 ("Anti-Churn-Ledger zu Release sichern (komprimiert)", "watchlist_expired_history")]
        for name, prefix in cases:
            step = next(s for s in steps if s.get("name") == name)
            modes = (("upload_error", "create_error") if "netshield_history.py" in step["run"]
                     else ("upload_error", "create_error", "delete_error"))
            for mode in modes:
                with self.subTest(step=name, mode=mode):
                    result = self.history_upload(step, prefix, mode)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn("STEP_FINISHED", result.stdout)
                    self.assertIn("ATTEMPT", result.stderr)
                    outcomes = {"build_combined": "success", "persist_waitlist": "success",
                                "persist_ledgers": "success", step.get("id"): "failure"}
                    for publisher in steps:
                        if publisher.get("name") in ("Save seen_db JSON Compatibility Cache",
                                "Save seen_db SQLite Cache", "Save Watchlist Daily Cap State Cache",
                                "Backup seen_db SQLite to GitHub Release", "Commit and Push"):
                            self.assertFalse(self.publication_allowed(publisher["if"], outcomes))

    def test_successful_or_unchanged_history_does_not_block_publication(self):
        steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["update"]["steps"]
        cases = [("Aufnahme-Warteliste zu Release sichern (komprimiert)", "aufnahme_warteliste"),
                 ("Anti-Churn-Ledger zu Release sichern (komprimiert)", "active_expired_history")]
        for name, prefix in cases:
            step = next(s for s in steps if s.get("name") == name)
            for changed in (False, True):
                with self.subTest(step=name, changed=changed):
                    result = self.history_upload(step, prefix, "success", changed=changed)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("STEP_FINISHED", result.stdout)
                    self.assertEqual("UPLOAD_ATTEMPT" in result.stderr, changed)

    @staticmethod
    def entry(**overrides):
        return dict(first="2026-09-11", last="2000-01-01", hq=False,
                    feeds=["feed_b"], hq_feed_names=[], hq_feeds=0,
                    today_count=1, today_hq=False, days_seen=0) | overrides

    def test_cross_confirmation_survives_commit_reopen_and_next_run(self):
        db = self.db()
        ip = "45.1.0.1"
        db[ip] = self.entry()
        before = db[ip]
        waiting = {ip: {"feed_a": "2026-09-11"}}
        result = self.cleanup(db, waiting)
        self.assertEqual(result["aufnahme_cross_bestaetigt"], 1)
        self.assertEqual(waiting, {ip: {"feed_a": "2026-09-11", "feed_b": "2026-09-12"}})
        self.assertEqual(db[ip], before | {"feeds": ["feed_a", "feed_b"]})
        db.close()
        reopened = self.db()
        # The next ingest unions today's feed with the stored history.
        entry = reopened[ip]
        entry["feeds"] = list(set(entry["feeds"]) | {"feed_b"})
        reopened[ip] = entry
        result = self.cleanup(reopened, waiting, "2026-09-13")
        self.assertIn(ip, reopened)
        self.assertEqual(set(reopened[ip]["feeds"]), {"feed_a", "feed_b"})
        self.assertEqual(result["aufnahme_cross_bestaetigt"], 0)

    def serialize_waiting(self, waiting, *, day="2026-09-12", dirty=True, limit=20_000_000):
        """Execute real final pruning, safety cap and atomic upload-file writing."""
        env = dict(_aufnahme_wartend=waiting, _aufnahme_wartend_dirty=dirty,
                   now=datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc),
                   now_stamp=day, timedelta=timedelta, AUFNAHME_WARTEN_TAGE=7,
                   AUFNAHME_WARTEN_SICHERHEITSGRENZE=limit,
                   write_json_atomic=nc.write_json_atomic, aufnahme_cross_bestaetigt=0)
        code = workflow_section("if _aufnahme_wartend:", "# ── seen_db speichern")
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile(code, str(WORKFLOW), "exec"), env)
        return json.loads(Path("state/aufnahme_warteliste_upload.json").read_text(encoding="utf-8"))

    def test_confirmation_survives_partial_upload_and_next_run(self):
        steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["update"]["steps"]
        wait_step = next(s for s in steps if s.get("id") == "persist_waitlist")
        ledger_step = next(s for s in steps if s.get("id") == "persist_ledgers")
        self.assertLess(steps.index(wait_step), steps.index(ledger_step))
        for failure in ("ledger_upload", "before_database_upload", "none"):
            with self.subTest(failure=failure):
                case = CombinedFixTests()
                case.setUp()
                try:
                    db = case.db()
                    ip, expiring = "45.1.0.1", "45.1.0.2"
                    first_day = "2026-09-10"
                    old_last = (datetime.strptime(first_day, "%Y-%m-%d")
                                - timedelta(days=180)).strftime("%Y-%m-%d")
                    db[expiring] = case.entry(first=old_last, last=old_last, feeds=["x", "y"])
                    waiting = {}
                    case.ingest(db, {ip: {"feed_a"}}, day=first_day, waiting=waiting)
                    case.cleanup(db, waiting, first_day)
                    self.assertNotIn(ip, db)
                    self.assertIn(expiring, db)
                    durable = sqlite3.connect("durable.sqlite3")
                    case.addCleanup(durable.close)
                    db._conn.backup(durable)

                    case.ingest(db, {ip: {"feed_b"}}, day="2026-09-11", waiting=waiting)
                    result = case.cleanup(db, waiting, "2026-09-11")
                    self.assertEqual(result["aufnahme_cross_bestaetigt"], 1)
                    self.assertTrue(result["_active_expired_last_dirty"])
                    self.assertEqual(set(db[ip]["feeds"]), {"feed_a", "feed_b"})
                    uploaded = case.serialize_waiting(waiting, day="2026-09-11")
                    shell = case.history_upload(wait_step, "aufnahme_warteliste", "success", payload=uploaded)
                    self.assertEqual(shell.returncode, 0, shell.stderr)
                    shell = case.history_upload(ledger_step, "active_expired_history",
                                "upload_error" if failure == "ledger_upload" else "success")
                    self.assertEqual(shell.returncode != 0, failure == "ledger_upload")
                    outcomes = {"build_combined": "success", "persist_waitlist": "success",
                                "persist_ledgers": "failure" if failure == "ledger_upload" else "success"}
                    for step in steps:
                        if step.get("name") in {"Save seen_db JSON Compatibility Cache",
                                "Save seen_db SQLite Cache", "Backup seen_db SQLite to GitHub Release",
                                "Commit and Push"}:
                            self.assertEqual(case.publication_allowed(step["if"], outcomes),
                                             failure != "ledger_upload")
                    if failure == "none":
                        db._conn.backup(durable)
                    db.close()
                    restored = case.db()
                    durable.backup(restored._conn)
                    Path("state/aufnahme_warteliste.json.gz.part000").write_bytes(
                        gzip.compress(json.dumps(uploaded).encode()))
                    waiting = case.load_state()["_aufnahme_wartend"]
                    ingested = case.ingest(restored, {ip: {"feed_b"}}, waiting=waiting)
                    result = case.cleanup(restored, waiting,
                                          waiting_dirty=ingested["_aufnahme_wartend_dirty"])
                    self.assertIn(ip, restored, "Cross-confirmed IP lost after partial publication")
                    self.assertEqual(set(restored[ip]["feeds"]), {"feed_a", "feed_b"})
                    self.assertEqual(result["aufnahme_removed"], 0)

                    # Publish the recovered DB, then acknowledge it on a later run.
                    recovered_waiting = case.serialize_waiting(waiting)
                    restored._conn.backup(durable)
                    waiting = recovered_waiting["entries"]
                    result = case.ingest(restored, {}, day="2026-09-13", waiting=waiting)
                    self.assertNotIn(ip, waiting)
                    # Even an interruption after this safe deletion keeps the proof
                    # in the already published DB, independent of the new run.
                    restored.close()
                    final_db = case.db()
                    durable.backup(final_db._conn)
                    case.ingest(final_db, {ip: {"feed_b"}}, day="2026-09-14", waiting=waiting)
                    case.cleanup(final_db, waiting, "2026-09-14")
                    self.assertIn(ip, final_db)
                    self.assertEqual(set(final_db[ip]["feeds"]), {"feed_a", "feed_b"})
                finally:
                    case.doCleanups()

    def test_confirmed_recovery_survives_seven_day_boundary_and_long_interruption(self):
        db = self.db()
        ip = "45.1.0.1"
        waiting = {ip: {"feed_a": "2026-09-04"}}
        self.ingest(db, {ip: {"feed_b"}}, day="2026-09-11", waiting=waiting)
        result = self.cleanup(db, waiting, "2026-09-11")
        self.assertEqual(result["aufnahme_cross_bestaetigt"], 1)
        # The first observation expires the following day, but the established
        # confirmation must survive until a durable DB can acknowledge it.
        payload = self.serialize_waiting(waiting, day="2026-09-25")
        db.bulk_delete([ip])  # Model restoring the older DB without the new IP.
        Path("state/aufnahme_warteliste.json.gz.part000").write_bytes(
            gzip.compress(json.dumps(payload).encode()))
        waiting = self.load_state()["_aufnahme_wartend"]
        self.ingest(db, {ip: {"feed_b"}}, day="2026-09-25", waiting=waiting)
        self.cleanup(db, waiting, "2026-09-25")
        self.assertIn(ip, db)
        self.assertEqual(set(db[ip]["feeds"]), {"feed_a", "feed_b"})

    def test_unconfirmed_old_feed_still_expires(self):
        db = self.db()
        ip = "45.1.0.1"
        waiting = {ip: {"feed_a": "2026-09-04"}}
        self.ingest(db, {ip: {"feed_b"}}, waiting=waiting)
        result = self.cleanup(db, waiting)
        self.assertNotIn(ip, db)
        self.assertEqual(result["aufnahme_cross_bestaetigt"], 0)
        self.assertEqual(waiting[ip], {"feed_b": "2026-09-12"})
        self.assertEqual(self.serialize_waiting(waiting, day="2026-09-20")["entries"], {})

    def test_confirmation_ack_requires_all_feeds_in_restored_db(self):
        db = self.db()
        waiting = {f"45.1.0.{i}": {"feed_a": "2026-09-01", "feed_b": "2026-09-02"}
                   for i in range(1, 5)}
        db["45.1.0.1"] = self.entry(feeds=["feed_b"])
        db["45.1.0.2"] = self.entry(feeds=["feed_a", "feed_b", "feed_c"])
        db["45.1.0.3"] = self.entry(feeds=["feed_a", "feed_c"])
        db["45.1.0.4"] = self.entry(feeds=["feed_a", "feed_b"])
        db._conn.execute("UPDATE seen_db SET feeds = '{broken' WHERE ip = '45.1.0.4'")
        queries = []
        db._conn.set_trace_callback(queries.append)
        result = self.ingest(db, {}, waiting=waiting)
        db._conn.set_trace_callback(None)
        self.assertEqual(set(waiting), {"45.1.0.1", "45.1.0.3", "45.1.0.4"})
        self.assertTrue(result["_aufnahme_wartend_dirty"])
        self.assertEqual(sum(q.startswith("SELECT feeds FROM seen_db WHERE ip =") for q in queries), 4)

    def test_waitlist_cap_keeps_unacknowledged_confirmations(self):
        waiting = {"45.1.0.1": {"feed_a": "2026-09-01", "feed_b": "2026-09-02"},
                   "45.1.0.2": {"feed_c": "2026-09-12"},
                   "45.1.0.3": {"feed_d": "2026-09-11"}}
        payload = self.serialize_waiting(waiting, limit=2)
        self.assertEqual(set(payload["entries"]), {"45.1.0.1", "45.1.0.2"})
        payload = self.serialize_waiting(waiting, limit=1)
        self.assertEqual(set(payload["entries"]), {"45.1.0.1"})
        waiting["45.1.0.2"]["feed_e"] = "2026-09-12"
        previous = Path("state/aufnahme_warteliste_upload.json").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "ungesicherte Bestaetigungen"):
            self.serialize_waiting(waiting, limit=1)
        self.assertEqual(Path("state/aufnahme_warteliste_upload.json").read_bytes(), previous)

    def test_seven_day_boundary_and_same_feed_do_not_change(self):
        db = self.db()
        for ip in ("45.1.0.1", "45.1.0.2", "45.1.0.3"):
            db[ip] = self.entry()
        waiting = {
            "45.1.0.1": {"feed_a": "2026-09-05"},
            "45.1.0.2": {"feed_a": "2026-09-04"},
            "45.1.0.3": {"feed_b": "2026-09-11"},
        }
        result = self.cleanup(db, waiting)
        self.assertEqual(set(db), {"45.1.0.1"})
        self.assertEqual(result["aufnahme_removed"], 2)
        self.assertEqual(waiting["45.1.0.2"], {"feed_b": "2026-09-12"})

    def test_cross_confirmation_still_obeys_active_expiry(self):
        db = self.db()
        ip = "45.1.0.1"
        db[ip] = self.entry(last="2025-01-01")
        waiting = {ip: {"feed_a": "2026-09-11"}}
        result = self.cleanup(db, waiting)
        self.assertNotIn(ip, db)
        self.assertNotIn(ip, waiting)
        self.assertEqual(result["expired_active_count"], 1)
        self.assertEqual(result["_active_expired_last"][ip]["last"], "2025-01-01")

    def test_batched_export_has_identical_bytes_and_does_not_mutate_db(self):
        db = self.db()
        for number in range(7):
            db[f"45.1.0.{number}"] = self.entry(
                feeds=["z", "a", 'quote"\\\n', "ä"],
                hq_feed_names=["hq_z", "hq_a"],
                auto_today_count=number if number % 2 else None)
        before = dict(db.items())
        expected = {}
        for ip, entry in before.items():
            expected[ip] = entry | {"feeds": sorted(entry["feeds"]),
                                    "hq_feed_names": sorted(entry["hq_feed_names"])}
        for batch_size in (1, 3, 50_000):
            with self.subTest(batch_size=batch_size):
                db.export_json_atomic("export.json", batch_size=batch_size)
                self.assertEqual(Path("export.json").read_bytes(),
                                 json.dumps(expected, separators=(",", ":")).encode())
                self.assertEqual(dict(db.items()), before)
        db.bulk_delete(list(db))
        db.export_json_atomic("export.json", batch_size=3)
        self.assertEqual(Path("export.json").read_bytes(), b"{}")

    def test_export_failure_keeps_previous_file_and_removes_tempfile(self):
        db = self.db()
        db["45.1.0.1"] = self.entry()
        Path("export.json").write_bytes(b'{"previous":true}')
        with patch.object(nc.os, "replace", side_effect=OSError("simulated failure")):
            with self.assertRaises(OSError):
                db.export_json_atomic("export.json")
        self.assertEqual(Path("export.json").read_bytes(), b'{"previous":true}')
        self.assertEqual(list(Path(".").glob(".export.json.*.tmp")), [])

    def test_export_cache_eviction_and_database_updates_keep_correct_values(self):
        db = self.db()
        # Exceed the 4096-entry cache and reuse an early combination afterwards.
        for number in range(4200):
            db[f"row-{number}"] = self.entry(feeds=[f"z-{number}", "a"])
        db["repeat"] = self.entry(feeds=["z-0", "a"])
        db.export_json_atomic("export.json", batch_size=101)
        exported = json.loads(Path("export.json").read_text(encoding="utf-8"))
        self.assertEqual(len(exported), 4201)
        for number in range(4200):
            self.assertEqual(exported[f"row-{number}"]["feeds"], ["a", f"z-{number}"])
        self.assertEqual(exported["repeat"]["feeds"], ["a", "z-0"])
        # Ordinary reads must still return separate, mutable feed lists.
        first = db["repeat"]
        first["feeds"].append("new")
        self.assertNotIn("new", db["repeat"]["feeds"])
        db["repeat"] = first
        db.export_json_atomic("export.json", batch_size=101)
        exported = json.loads(Path("export.json").read_text(encoding="utf-8"))
        self.assertEqual(exported["repeat"]["feeds"], ["a", "new", "z-0"])

    def test_invalid_feed_json_during_export_does_not_replace_old_output(self):
        db = self.db()
        db["45.1.0.1"] = self.entry()
        db._conn.execute("UPDATE seen_db SET feeds = ?", ("{broken",))
        Path("export.json").write_bytes(b'{"previous":true}')
        with self.assertRaises(ValueError):
            db.export_json_atomic("export.json", batch_size=1)
        self.assertEqual(Path("export.json").read_bytes(), b'{"previous":true}')
        self.assertEqual(list(Path(".").glob(".export.json.*.tmp")), [])

    def test_restore_distinguishes_absent_release_from_api_and_download_errors(self):
        if "scripts/netshield_history.py restore" in WORKFLOW.read_text(encoding="utf-8"):
            from tests.test_combined_state_safety import assert_restore_scenarios
            assert_restore_scenarios(self)
            return
        shell = os.environ.get("NETSHIELD_TEST_BASH") or shutil.which("bash")
        if not shell:
            self.skipTest("Bash required for workflow shell regression")
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        steps = [step for step in workflow["jobs"]["update"]["steps"]
                 if step.get("name", "").startswith(("Restore Aufnahme-Warteliste", "Restore Anti-Churn-Ledger"))]
        self.assertEqual(len(steps), 2)
        for step, tag, pattern in zip(steps,
                ("aufnahme-warteliste-backup", "anti-churn-ledger-backup"),
                ("aufnahme_warteliste.json.gz.part*", "*_expired_history.json.gz.part*")):
            for mode in ("absent", "api_error", "download_error", "success"):
                with self.subTest(step=step["name"], mode=mode):
                    tags = "unrelated\n" + (tag if mode != "absent" else tag + "-other")
                    mock = '''
gh() {
  if [ "$1" = api ]; then
    printf '%s\n' "$FAKE_TAGS"
    [ "$MODE" != api_error ]
  else
    printf 'DOWNLOAD:%s\n' "$@"
    [ "$MODE" != download_error ]
  fi
}
'''
                    # Minimal Git-for-Windows shells may lack mkdir. The test
                    # directory already exists; all meaningful commands are gh.
                    if os.name == "nt":
                        mock += "mkdir() { :; }\n"
                    result = subprocess.run([shell, "-c", mock + step["run"] + "\nprintf 'FINISHED\\n'"],
                        cwd=self.directory, capture_output=True, text=True,
                        env=os.environ | {"GITHUB_REPOSITORY": "fixture/repo", "FAKE_TAGS": tags, "MODE": mode})
                    self.assertEqual(result.returncode == 0, mode in ("absent", "success"), result.stderr)
                    self.assertEqual("FINISHED" in result.stdout, mode in ("absent", "success"))
                    self.assertEqual("DOWNLOAD:" in result.stdout, mode in ("download_error", "success"))
                    if mode == "success":
                        for argument in (tag, pattern, "--clobber", "fixture/repo"):
                            self.assertIn("DOWNLOAD:" + argument, result.stdout)


if __name__ == "__main__":
    unittest.main()
