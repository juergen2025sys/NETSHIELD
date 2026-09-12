"""Exercise the actual Combined restore/cleanup code and bounded JSON export.

No GitHub requests: the restore tests replace gh with a local shell function.
"""
import contextlib
from datetime import datetime, timedelta, timezone
import glob
import gzip
import io
import json
import os
from pathlib import Path
import shutil
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

    def cleanup(self, db, waiting, day="2026-09-12"):
        now = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        env = dict(
            db=db, now=now, now_day=day, datetime=datetime, timedelta=timedelta,
            json=json, sys=sys, _time=time, coerce_bool=nc.coerce_bool,
            AUFNAHME_WARTEN_TAGE=7, WATCHLIST_DAILY_CAP=2000,
            _aufnahme_wartend=waiting, _aufnahme_wartend_dirty=False,
            _active_expired_last={}, _active_expired_last_dirty=False,
            _wl_expired_first={}, _wl_expired_first_dirty=False,
            _wl_cap_heute_bereits_gelaufen=True, _wl_kandidaten=[],
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
        self.assertEqual(waiting, {})
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
        result = self.cleanup(db, {ip: {"feed_a": "2026-09-11"}})
        self.assertNotIn(ip, db)
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
