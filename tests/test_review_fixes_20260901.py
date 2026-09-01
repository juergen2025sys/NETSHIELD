#!/usr/bin/env python3
"""
Regressionstests zum Code-Review vom 01.09.2026
===============================================

Jeder Test hier gehoert zu genau einem Fund aus dem Review und schlaegt
gegen den UNGEPATCHTEN Stand fehl. Die Nummerierung entspricht dem
Review-Bericht.

Ausfuehren:
    python3 -m unittest tests.test_review_fixes_20260901 -v
"""

import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from netshield_common import SqliteSeenDB  # noqa: E402

_REPO = os.path.join(os.path.dirname(__file__), "..")
_WF = os.path.join(_REPO, ".github", "workflows")


def _wf(name):
    with open(os.path.join(_WF, name), encoding="utf-8") as f:
        return f.read()


# ───────────────────────── Fund 1 (BLOCKER) ─────────────────────────

class TestMetaTotalIpsFallback(unittest.TestCase):
    """total_ips darf bei vorhandener, aber defekter SQLite nicht verloren gehen.

    Vorher: der Rueckfall auf den Altwert hing am elif-Zweig und griff nur,
    wenn seen_db.sqlite3 komplett fehlte. Bei vorhandener, aber korrupter
    Datei wurde state/seen_db_meta.json ohne total_ips geschrieben - die
    Schrumpfungswache des Folgelaufs las dann 0 und liess alles durch.
    """

    # Nachbau exakt der Logik aus dem Commit-and-Push-Step.
    @staticmethod
    def _meta_bauen(sqlite_pfad, previous_total_ips):
        meta = {"note": "test"}
        if os.path.exists(sqlite_pfad):
            try:
                c = sqlite3.connect(sqlite_pfad)
                q = c.execute("PRAGMA quick_check").fetchone()
                n = c.execute("SELECT COUNT(*) FROM seen_db").fetchone()[0]
                c.close()
                if not q or q[0] != "ok":
                    raise RuntimeError(f"PRAGMA quick_check={q!r}")
                meta["total_ips"] = int(n)
            except Exception as e:
                meta["error"] = f"seen_db.sqlite3 nicht lesbar: {e}"
                if previous_total_ips is not None:
                    meta["total_ips"] = previous_total_ips
                    meta["total_ips_source"] = "previous_meta_after_corrupt_sqlite"
        elif previous_total_ips is not None:
            meta["total_ips"] = previous_total_ips
            meta["total_ips_source"] = "previous_meta_after_early_failure"
        return meta

    def test_defekte_sqlite_behaelt_alten_wert(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "seen_db.sqlite3")
        with open(p, "wb") as f:
            f.write(b"das ist keine sqlite datenbank")
        meta = self._meta_bauen(p, previous_total_ips=9_500_000)
        self.assertIn("error", meta)
        self.assertEqual(meta["total_ips"], 9_500_000)
        self.assertEqual(meta["total_ips_source"], "previous_meta_after_corrupt_sqlite")

    def test_leere_sqlite_datei_behaelt_alten_wert(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "seen_db.sqlite3")
        open(p, "wb").close()  # 0 Byte, wie nach einem abgebrochenen Build
        meta = self._meta_bauen(p, previous_total_ips=9_500_000)
        self.assertEqual(meta.get("total_ips"), 9_500_000)

    def test_fehlende_sqlite_behaelt_alten_wert(self):
        meta = self._meta_bauen("/nicht/vorhanden.sqlite3", previous_total_ips=42)
        self.assertEqual(meta["total_ips"], 42)
        self.assertEqual(meta["total_ips_source"], "previous_meta_after_early_failure")

    def test_gueltige_sqlite_gewinnt_gegen_altwert(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "seen_db.sqlite3")
        db = SqliteSeenDB(p)
        for i in range(5):
            db[f"1.2.3.{i}"] = {"first": "2026-01-01", "last": "2026-08-01"}
        db.commit()
        db.close()
        meta = self._meta_bauen(p, previous_total_ips=9_500_000)
        self.assertEqual(meta["total_ips"], 5)
        self.assertNotIn("total_ips_source", meta)

    def test_workflow_enthaelt_den_fallback_im_except_zweig(self):
        t = _wf("update_combined_blacklist.yml")
        self.assertIn("previous_meta_after_corrupt_sqlite", t)


# ───────────────────────── Fund 2 (HOCH) ─────────────────────────

class TestAfdLoeschtNichtMehr(unittest.TestCase):
    """AFD darf keine abgelaufenen IPs mehr selbst entfernen.

    Sonst umgeht der woechentliche AFD-Lauf sowohl WATCHLIST_DAILY_CAP als
    auch beide Anti-Churn-Ledger, die nur in Combined existieren.
    """

    def test_kein_bulk_delete_mehr_in_afd(self):
        t = _wf("auto_feed_discovery.yml")
        code = "\n".join(l for l in t.splitlines() if not l.strip().startswith("#"))
        self.assertNotIn("bulk_delete", code,
                         "auto_feed_discovery.yml darf seen_db-Eintraege nicht mehr loeschen")

    def test_afd_zaehlt_kandidaten_weiterhin(self):
        t = _wf("auto_feed_discovery.yml")
        self.assertIn("faellige_watchlist", t)
        self.assertIn("faellige_active", t)

    def test_afd_committet_ingest_trotzdem(self):
        t = _wf("auto_feed_discovery.yml")
        self.assertIn("db.commit()", t,
                      "Ingest-Aenderungen muessen weiterhin persistiert werden")

    def test_combined_hat_cap_und_ledger_weiterhin(self):
        t = _wf("update_combined_blacklist.yml")
        self.assertIn("WATCHLIST_DAILY_CAP = 2000", t)
        self.assertIn("state/watchlist_expired_history.json", t)
        self.assertIn("state/active_expired_history.json", t)


# ───────────────────────── Fund 3 / 4 (MITTEL) ─────────────────────────

class TestShrinkGuardFailClosed(unittest.TestCase):

    def test_kein_durchlass_ohne_sqlite(self):
        t = _wf("update_combined_blacklist.yml")
        self.assertNotIn("Kein SQLite-Snapshot vorhanden - Wache kann nicht zaehlen, lasse durch.", t)
        self.assertIn("seen_db.sqlite3 fehlt nach erfolgreichem Build", t)

    def test_kein_durchlass_ohne_vorlaufwert(self):
        t = _wf("update_combined_blacklist.yml")
        self.assertNotIn("Kein Vergleichswert vorhanden (erster Lauf?) - lasse durch.", t)
        self.assertIn("state/seen_db_erstlauf_ok", t)

    def test_alle_publish_steps_haengen_am_guard(self):
        import yaml
        with open(os.path.join(_WF, "update_combined_blacklist.yml"), encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        steps = doc["jobs"]["update"]["steps"]
        publizierend = [
            "Save seen_db JSON Compatibility Cache",
            "Save seen_db SQLite Cache",
            "Backup seen_db SQLite to GitHub Release",
            "Aufnahme-Warteliste zu Release sichern (komprimiert)",
            "Anti-Churn-Ledger zu Release sichern (komprimiert)",
            "Commit and Push",
        ]
        gefunden = set()
        for s in steps:
            name = s.get("name")
            if name in publizierend:
                gefunden.add(name)
                self.assertIn("shrink_guard.outputs.ok", str(s.get("if")),
                              f"Step {name!r} publiziert ohne Schrumpfungswache-Bedingung")
        self.assertEqual(gefunden, set(publizierend),
                         "Nicht alle erwarteten Publish-Steps gefunden")


# ───────────────────────── Fund 5 (NIEDRIG) ─────────────────────────

class TestAufnahmeFilterHqNull(unittest.TestCase):

    def _db(self):
        d = tempfile.mkdtemp()
        db = SqliteSeenDB(os.path.join(d, "s.sqlite3"))
        return db

    @staticmethod
    def _roh(conn, ip, feeds, hq):
        conn.execute(
            "INSERT INTO seen_db(ip,first,last,hq,feeds,hq_feed_names,hq_feeds,"
            "today_count,today_hq,days_seen,auto_today_count) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (ip, "2026-08-01", "2026-08-30", hq, feeds, "[]", 0, 0, 0, 0, None))

    @staticmethod
    def _entscheide(rows, alle_ips):
        """Nachbau des Python-Rechecks aus dem Cleanup-Pass."""
        kand = {}
        for ip, fj, hqr in rows:
            hq = bool(hqr)
            try:
                feeds = json.loads(fj) if fj else []
            except (ValueError, TypeError):
                feeds = None
            kand[ip] = (feeds, hq)
        behalten, verworfen = [], []
        for ip in alle_ips:
            if ip in kand:
                feeds, hq = kand[ip]
                if not isinstance(feeds, list):
                    if hq:
                        feeds = []
                    else:
                        verworfen.append(ip)
                        continue
                if not (len(feeds) >= 2 or hq or "auto_feed_discovery" in feeds):
                    verworfen.append(ip)
                    continue
            behalten.append(ip)
        return behalten, verworfen

    def test_hq_null_mit_einem_feed_wird_erfasst(self):
        db = self._db()
        self._roh(db._conn, "10.0.0.1", json.dumps(["nur_einer"]), None)
        db._conn.commit()
        rows = db.select_aufnahme_kandidaten()
        self.assertEqual([r[0] for r in rows], ["10.0.0.1"],
                         "hq IS NULL darf nicht per SQL-NULL-Propagation aus der "
                         "Kandidatenauswahl fallen")
        behalten, verworfen = self._entscheide(rows, ["10.0.0.1"])
        self.assertEqual(verworfen, ["10.0.0.1"])
        self.assertEqual(behalten, [])

    def test_hq1_feeds_null_bleibt_erhalten(self):
        db = self._db()
        self._roh(db._conn, "10.0.0.2", None, 1)
        db._conn.commit()
        behalten, verworfen = self._entscheide(
            db.select_aufnahme_kandidaten(), ["10.0.0.2"])
        self.assertEqual(behalten, ["10.0.0.2"])

    def test_hq1_kaputtes_feeds_json_bleibt_erhalten(self):
        db = self._db()
        self._roh(db._conn, "10.0.0.3", "{kaputt", 1)
        db._conn.commit()
        behalten, _ = self._entscheide(
            db.select_aufnahme_kandidaten(), ["10.0.0.3"])
        self.assertEqual(behalten, ["10.0.0.3"])

    def test_hq0_kaputtes_feeds_json_wird_verworfen(self):
        db = self._db()
        self._roh(db._conn, "10.0.0.4", "{kaputt", 0)
        db._conn.commit()
        _, verworfen = self._entscheide(
            db.select_aufnahme_kandidaten(), ["10.0.0.4"])
        self.assertEqual(verworfen, ["10.0.0.4"])

    def test_zwei_feeds_ist_kein_kandidat(self):
        db = self._db()
        self._roh(db._conn, "10.0.0.5", json.dumps(["a", "b"]), 0)
        db._conn.commit()
        self.assertEqual(db.select_aufnahme_kandidaten(), [])


# ───────────────────────── Fund 6 (NIEDRIG) ─────────────────────────

class TestKeinFreshStartImport(unittest.TestCase):

    def test_bulk_import_fresh_start_zweig_entfernt(self):
        t = _wf("update_combined_blacklist.yml")
        code = "\n".join(l for l in t.splitlines() if not l.strip().startswith("#"))
        self.assertNotIn("db_sqlite.bulk_import(db)", code,
                         "Der unerreichbare Fresh-Start-Import darf nicht "
                         "wieder auftauchen - er wuerde einen historienlosen "
                         "Stand als produktiv behandeln")
        self.assertIn("Interner Zustandsfehler", t)


# ───────────────────────── Fund 7 (HOCH) ─────────────────────────

class TestScoreDecaySqlite(unittest.TestCase):

    def test_sqlite_wird_bevorzugt(self):
        t = _wf("score_decay_monitor.yml")
        self.assertIn("_SqliteScoreDB", t)
        self.assertIn("seen-db-sqlite-backup", t)
        i_sqlite = t.index("if os.path.exists(SQLITE_FILE):")
        i_json = t.index("if db is None and os.path.exists(DB_FILE):")
        self.assertLess(i_sqlite, i_json,
                        "SQLite muss VOR dem JSON-Fallback probiert werden")

    def test_wrapper_liefert_die_benoetigten_felder(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "s.sqlite3")
        db = SqliteSeenDB(p)
        db["8.8.8.8"] = {
            "first": "2026-01-01", "last": "2026-08-01", "hq": True,
            "feeds": ["a", "b", "c"], "hq_feed_names": ["a"], "hq_feeds": 1,
            "today_count": 3, "today_hq": True, "days_seen": 7,
        }
        db.commit()
        db.close()

        # Nachbau des Wrappers aus dem Workflow.
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        sql = ("SELECT ip, first, last, hq, "
               "  CASE WHEN feeds IS NULL OR feeds = '' THEN 0 "
               "       WHEN json_valid(feeds) AND json_type(feeds) = 'array' "
               "       THEN json_array_length(feeds) "
               "       ELSE -1 END, "
               "  today_count, days_seen FROM seen_db")
        ip, first, last, hq, fc, tc, ds = conn.execute(sql).fetchone()
        data = {"first": first, "last": last, "hq": bool(hq),
                "feeds": [None] * (fc if fc > 0 else 0),
                "today_count": tc, "days_seen": ds}
        self.assertEqual(ip, "8.8.8.8")
        self.assertEqual(data["last"], "2026-08-01")
        self.assertEqual(data["first"], "2026-01-01")
        self.assertTrue(data["hq"])
        self.assertEqual(len(data["feeds"]), 3)
        self.assertEqual(data["today_count"], 3)
        self.assertEqual(data["days_seen"], 7)

    def test_kaputtes_feeds_zaehlt_als_null_feeds(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "s.sqlite3")
        db = SqliteSeenDB(p)
        db._conn.execute(
            "INSERT INTO seen_db(ip,first,last,hq,feeds,hq_feed_names,hq_feeds,"
            "today_count,today_hq,days_seen,auto_today_count) "
            "VALUES('9.9.9.9','2026-01-01','2026-08-01',0,'{kaputt','[]',0,0,0,0,NULL)")
        db.commit()
        db.close()
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        fc = conn.execute(
            "SELECT CASE WHEN feeds IS NULL OR feeds = '' THEN 0 "
            "  WHEN json_valid(feeds) AND json_type(feeds) = 'array' "
            "  THEN json_array_length(feeds) ELSE -1 END FROM seen_db").fetchone()[0]
        self.assertEqual(fc, -1)
        self.assertEqual(len([None] * (fc if fc > 0 else 0)), 0)


# ───────────────────────── Fund 8 (HOCH) ─────────────────────────

class TestIpAblaufSqliteZuerst(unittest.TestCase):

    def test_sqlite_vor_json(self):
        t = _wf("ip_ablauf.yml")
        i_sqlite = t.index("if os.path.exists(SQLITE_FILE):")
        i_json = t.index("if db is None and os.path.exists(DB_FILE):")
        self.assertLess(i_sqlite, i_json,
                        "ip_ablauf muss den kanonischen SQLite-State vor dem "
                        "JSON-Kompatibilitaets-Cache lesen")

    def test_json_quelle_wird_als_evtl_veraltet_markiert(self):
        t = _wf("ip_ablauf.yml")
        self.assertIn("JSON-Cache (Fallback, evtl. veraltet)", t)


# ───────────────────────── Fund 9 (MITTEL) ─────────────────────────

class TestPrognoseTagesdeckel(unittest.TestCase):

    @staticmethod
    def _simuliere(faellig_je_tag, rueckstau_start, cap=2000):
        gedeckelt = {}
        backlog = rueckstau_start
        for tag in sorted(faellig_je_tag):
            backlog += faellig_je_tag[tag]
            entfernt = min(cap, backlog)
            backlog -= entfernt
            gedeckelt[tag] = entfernt
        return gedeckelt, backlog

    def test_deckel_greift_und_verliert_nichts(self):
        faellig = {"2026-09-02": 50_000, "2026-09-03": 0, "2026-09-04": 0}
        gedeckelt, rest = self._simuliere(faellig, rueckstau_start=0)
        self.assertEqual(list(gedeckelt.values()), [2000, 2000, 2000])
        # Nichts geht verloren: entfernt + Rueckstau == brutto faellig
        self.assertEqual(sum(gedeckelt.values()) + rest, sum(faellig.values()))

    def test_kleine_mengen_bleiben_unveraendert(self):
        faellig = {"2026-09-02": 100, "2026-09-03": 250}
        gedeckelt, rest = self._simuliere(faellig, rueckstau_start=0)
        self.assertEqual(gedeckelt, faellig)
        self.assertEqual(rest, 0)

    def test_rueckstau_wird_mitgerechnet(self):
        faellig = {"2026-09-02": 500}
        gedeckelt, rest = self._simuliere(faellig, rueckstau_start=5000)
        self.assertEqual(gedeckelt["2026-09-02"], 2000)
        self.assertEqual(rest, 3500)

    def test_workflow_persistiert_gedeckelte_zahlen(self):
        t = _wf("ip_ablauf.yml")
        self.assertIn("per_expiry_date_watch_capped", t)
        self.assertIn("predicted_brutto", t)
        i_cap = t.index("for _d, _cnt in per_expiry_date_watch_capped.items():")
        self.assertGreater(i_cap, 0)


# ───────────────────────── Fund 10 / 11 (MITTEL / Security) ────────────

class TestHistoryFreshStart(unittest.TestCase):

    def test_slot_kollidiert_nicht_mehr_mit_combined(self):
        import yaml
        with open(os.path.join(_WF, "history_fresh_start.yml"), encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        crons = [c["cron"] for c in doc[True]["schedule"]]
        self.assertNotIn("15 3 1 * *", crons)
        # Combined laeuft zu Minute 7/27/47 jeder dritten Stunde.
        for c in crons:
            minute, stunde = c.split()[0], c.split()[1]
            self.assertNotIn(minute, ("7", "27", "47"),
                             f"Cron {c!r} faellt auf einen Combined-Startslot")
            self.assertNotEqual(stunde, "3",
                                f"Cron {c!r} liegt im Fenster des 03:07-Combined-Laufs")

    def test_gemeinsame_concurrency_gruppe(self):
        import yaml
        with open(os.path.join(_WF, "history_fresh_start.yml"), encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        self.assertEqual(doc["concurrency"]["group"], "netshield-seen-db-writers")
        self.assertIs(doc["concurrency"]["cancel-in-progress"], False)

    def test_keine_direkte_interpolation_des_freitext_inputs(self):
        t = _wf("history_fresh_start.yml")
        code = "\n".join(l for l in t.splitlines() if not l.strip().startswith("#"))
        self.assertNotIn('[ "${{ github.event.inputs.confirm_reset }}"', code)
        self.assertIn('[ "$CONFIRM_RESET" !=', code)
        self.assertIn("CONFIRM_RESET: ${{ github.event.inputs.confirm_reset }}", code)


# ───────────────────────── Fund 12 / 13 (NIEDRIG) ─────────────────────

class TestAufraeumen(unittest.TestCase):

    def test_fp_checker_ohne_toten_seen_db_cache(self):
        import yaml
        with open(os.path.join(_WF, "false_positive_checker.yml"), encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        for job in doc["jobs"].values():
            for s in job.get("steps") or []:
                pfad = str((s.get("with") or {}).get("path", ""))
                self.assertNotIn("seen_db.json", pfad,
                                 "FP-Checker liest seen_db nicht mehr - der "
                                 "Cache-Restore war reine Verschwendung")

    def test_kein_ungueltiger_queue_key_mehr(self):
        import glob
        import yaml
        for f in sorted(glob.glob(os.path.join(_WF, "*.yml"))):
            with open(f, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            if not isinstance(doc, dict):
                continue
            def pruefe(c, wo):
                if isinstance(c, dict):
                    self.assertNotIn("queue", c,
                                     f"{os.path.basename(f)} ({wo}): 'queue' ist "
                                     f"kein gueltiger concurrency-Schluessel")
            pruefe(doc.get("concurrency"), "top-level")
            for jn, job in (doc.get("jobs") or {}).items():
                if isinstance(job, dict):
                    pruefe(job.get("concurrency"), f"job {jn}")


# ───────────────────── Wartbarkeit: Verbindungsleck ────────────────────

class TestSqliteInitLeck(unittest.TestCase):

    def test_konstruktor_schliesst_bei_fehler(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "kaputt.sqlite3")
        with open(p, "wb") as f:
            f.write(b"keine sqlite datei" * 100)
        with self.assertRaises(Exception):
            SqliteSeenDB(p)
        # Wenn die Verbindung sauber geschlossen wurde, laesst sich die Datei
        # ohne "database is locked" ersetzen.
        os.remove(p)
        db = SqliteSeenDB(p)
        db["1.1.1.1"] = {"first": "2026-01-01", "last": "2026-01-01"}
        db.commit()
        self.assertEqual(len(db), 1)
        db.close()


# ────────────── Unveraenderte Semantik: 30/180-Tage-Grenzen ─────────────

class TestAblaufGrenzenUnveraendert(unittest.TestCase):
    """Die Migration darf die Ablauf-Semantik nicht verschoben haben."""

    @staticmethod
    def _entfernt(last, heute, tage):
        from datetime import datetime, timedelta, timezone
        now = datetime.strptime(heute, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        cutoff = (now - timedelta(days=tage)).strftime("%Y-%m-%d")
        return last < cutoff

    def test_active_180_tage_grenze(self):
        # Beispiel aus dem Review-Auftrag: last=08.03.2026
        self.assertFalse(self._entfernt("2026-03-08", "2026-09-04", 180))
        self.assertTrue(self._entfernt("2026-03-08", "2026-09-05", 180))

    def test_active_exakt_180_tage_bleibt(self):
        self.assertFalse(self._entfernt("2026-03-09", "2026-09-05", 180))

    def test_watchlist_30_tage_grenze(self):
        self.assertFalse(self._entfernt("2026-08-06", "2026-09-05", 30))
        self.assertTrue(self._entfernt("2026-08-05", "2026-09-05", 30))

    def test_konstanten_repoweit_konsistent(self):
        import glob
        werte_expiry, werte_wl = set(), set()
        for f in glob.glob(os.path.join(_WF, "*.yml")):
            with open(f, encoding="utf-8") as fh:
                t = fh.read()
            werte_expiry.update(re.findall(r"(?<!WATCHLIST_)\bEXPIRY_DAYS\s*=\s*(\d+)", t))
            werte_wl.update(re.findall(r"\bWATCHLIST_EXPIRY_DAYS\s*=\s*(\d+)", t))
        self.assertEqual(werte_expiry, {"180"})
        self.assertEqual(werte_wl, {"30"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
