#!/usr/bin/env python3
"""
NETSHIELD Race Condition Simulation Tests
==========================================
Simuliert die dokumentierten Race-Patterns (RACE2, RACE5) der Workflows
community_ip_report.yml und false_positive_checker.yml.

Testet dass die FIX-Patterns (reset --hard → re-apply) keine Daten
verlieren, und demonstriert dass das alte RMW-Pattern Daten verliert.

Ausführen:
    cd NETSHIELD-main
    python3 -m pytest tests/test_race_simulations.py -v
    # oder:
    python3 -m unittest tests.test_race_simulations -v
"""

import os
import sys
import shutil
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


# ═══════════════════════════════════════════════════════════════
# Hilfsfunktionen: simulieren git-Operationen im Dateisystem
# ═══════════════════════════════════════════════════════════════

def read_file(path):
    """Liest eine Datei, gibt leeren String zurück wenn nicht vorhanden."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def write_file(path, content):
    Path(path).write_text(content, encoding="utf-8")


def append_lines(path, new_lines):
    """Hängt Zeilen an eine Datei an (append-only, ohne Dedup)."""
    with open(path, "a", encoding="utf-8") as f:
        for line in new_lines:
            f.write(line + "\n")


def dedup_append_lines(path, new_lines):
    """Hängt Zeilen mit Dedup an (RACE5-Pattern: grep -qxF → append).
    
    Simuliert:
        while IFS= read -r line; do
          grep -qxF "$line" file 2>/dev/null || echo "$line" >> file
        done < /tmp/local_appends.txt
    """
    existing = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            existing = {l.rstrip("\n") for l in f}
    with open(path, "a", encoding="utf-8") as f:
        for line in new_lines:
            if line not in existing:
                f.write(line + "\n")
                existing.add(line)


def overwrite_file(path, content):
    """Überschreibt eine Datei komplett (last-write-wins)."""
    write_file(path, content)


# ═══════════════════════════════════════════════════════════════
# Simuliertes "Remote"-Repository (shared state)
# ═══════════════════════════════════════════════════════════════

class SimulatedRemote:
    """Simuliert ein gemeinsames Git-Remote als Verzeichnis.
    
    fetch() → kopiert Remote-Stand ins lokale Verzeichnis
    push() → schlägt fehl wenn Remote sich geändert hat (simulate conflict)
    force_push() → überschreibt Remote immer
    """
    def __init__(self, base_dir):
        self.remote_dir = os.path.join(base_dir, "remote")
        os.makedirs(self.remote_dir, exist_ok=True)
        self._version = 0

    def init_file(self, filename, content=""):
        write_file(os.path.join(self.remote_dir, filename), content)
        self._version += 1

    def get_file(self, filename):
        return read_file(os.path.join(self.remote_dir, filename))

    def get_version(self):
        return self._version

    def fetch_to(self, local_dir, filename):
        """Simuliert git fetch + reset --hard origin: kopiert Remote → lokal."""
        src = os.path.join(self.remote_dir, filename)
        dst = os.path.join(local_dir, filename)
        if os.path.exists(src):
            shutil.copy2(src, dst)
        elif os.path.exists(dst):
            os.unlink(dst)

    def push_from(self, local_dir, filename, expected_version=None):
        """Simuliert git push. Scheitert wenn Version nicht mehr stimmt."""
        if expected_version is not None and expected_version != self._version:
            return False  # Conflict – Remote hat sich geändert
        src = os.path.join(local_dir, filename)
        dst = os.path.join(self.remote_dir, filename)
        shutil.copy2(src, dst)
        self._version += 1
        return True


# ═══════════════════════════════════════════════════════════════
# Test 1: RACE2 – Append-Only (altes RMW vs neues Pattern)
# ═══════════════════════════════════════════════════════════════

class TestRace2AppendOnly(unittest.TestCase):
    """Zeigt dass Read-Modify-Write bei append-only Dateien Einträge
    verliert, und dass das RACE5-Pattern (reset + dedup-append) alle
    Einträge bewahrt."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.remote = SimulatedRemote(self.tmpdir)
        self.worker_a = os.path.join(self.tmpdir, "worker_a")
        self.worker_b = os.path.join(self.tmpdir, "worker_b")
        os.makedirs(self.worker_a, exist_ok=True)
        os.makedirs(self.worker_b, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_rmw_loses_data(self):
        """Demonstriert: RMW-Pattern verliert Worker-A-Einträge."""
        logfile = "log.txt"
        self.remote.init_file(logfile, "# Log\nbase_entry\n")

        # Worker A und B lesen beide den gleichen Basis-Stand
        self.remote.fetch_to(self.worker_a, logfile)
        self.remote.fetch_to(self.worker_b, logfile)

        # Worker A fügt entry_a hinzu
        base_content_a = read_file(os.path.join(self.worker_a, logfile))
        write_file(os.path.join(self.worker_a, logfile),
                   base_content_a + "entry_a\n")

        # Worker B fügt entry_b hinzu (auf gleichem Basis-Stand!)
        base_content_b = read_file(os.path.join(self.worker_b, logfile))
        write_file(os.path.join(self.worker_b, logfile),
                   base_content_b + "entry_b\n")

        # Worker A pusht erfolgreich
        v = self.remote.get_version()
        self.assertTrue(self.remote.push_from(self.worker_a, logfile, v))

        # Worker B pusht – überschreibt A's Änderungen (last-write-wins)
        # In Git: force-push oder rebase -X theirs (das alte Bug-Pattern)
        self.remote.push_from(self.worker_b, logfile)  # force

        result = self.remote.get_file(logfile)
        self.assertIn("entry_b", result)
        # entry_a ist VERLOREN – das ist der Bug den RACE2/RACE5 fixes beheben
        self.assertNotIn("entry_a", result,
                         "RMW sollte entry_a verlieren (demonstriert den Bug)")

    def test_reset_reapply_preserves_all(self):
        """RACE5-Pattern: reset --hard + dedup-append verliert keine Daten."""
        logfile = "log.txt"
        self.remote.init_file(logfile, "# Log\nbase_entry\n")

        # Worker A: liest Basis, fügt entry_a hinzu, pusht
        self.remote.fetch_to(self.worker_a, logfile)
        append_lines(os.path.join(self.worker_a, logfile), ["entry_a"])
        v = self.remote.get_version()
        self.assertTrue(self.remote.push_from(self.worker_a, logfile, v))

        # Worker B: hatte alten Stand, will entry_b hinzufügen
        # Schritt 1: Eigene Appends sichern (git diff → /tmp)
        local_appends_b = ["entry_b"]

        # Schritt 2: Push scheitert (Remote hat sich geändert)
        v_old = self.remote.get_version() - 1  # B hat alten Stand
        self.assertFalse(self.remote.push_from(self.worker_b, logfile, v_old))

        # Schritt 3: reset --hard origin (fetch Remote-Stand)
        self.remote.fetch_to(self.worker_b, logfile)

        # Schritt 4: Dedup-Append der eigenen Änderungen
        dedup_append_lines(os.path.join(self.worker_b, logfile), local_appends_b)

        # Schritt 5: Push (jetzt mit aktuellem Stand)
        v = self.remote.get_version()
        self.assertTrue(self.remote.push_from(self.worker_b, logfile, v))

        result = self.remote.get_file(logfile)
        self.assertIn("base_entry", result)
        self.assertIn("entry_a", result, "entry_a muss erhalten bleiben")
        self.assertIn("entry_b", result, "entry_b muss hinzugefügt werden")


# ═══════════════════════════════════════════════════════════════
# Test 2: RACE5 – Reset+Reapply für Append-Only (Retry-Loop)
# ═══════════════════════════════════════════════════════════════

class TestRace5ResetReapplyAppendOnly(unittest.TestCase):
    """Simuliert den 5-Versuch-Retry-Loop aus community_ip_report.yml
    und false_positive_checker.yml für append-only Dateien."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.remote = SimulatedRemote(self.tmpdir)
        self.logfile = "community_reports_log.txt"

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _simulate_worker(self, worker_id, appends, max_attempts=5):
        """Simuliert einen Worker mit dem RACE5 reset+reapply Pattern."""
        worker_dir = os.path.join(self.tmpdir, f"worker_{worker_id}")
        os.makedirs(worker_dir, exist_ok=True)

        # Initialer Checkout
        self.remote.fetch_to(worker_dir, self.logfile)
        local_path = os.path.join(worker_dir, self.logfile)

        for attempt in range(1, max_attempts + 1):
            # reset --hard origin
            self.remote.fetch_to(worker_dir, self.logfile)
            # dedup-append
            dedup_append_lines(local_path, appends)
            # try push
            v = self.remote.get_version()
            if self.remote.push_from(worker_dir, self.logfile, v):
                return attempt
        return None  # alle Versuche gescheitert

    def test_single_retry(self):
        """Worker B braucht genau 1 Retry wenn A gleichzeitig pusht."""
        self.remote.init_file(self.logfile, "# Log\n")

        # Worker A pusht zuerst
        a_dir = os.path.join(self.tmpdir, "worker_a")
        os.makedirs(a_dir)
        self.remote.fetch_to(a_dir, self.logfile)
        append_lines(os.path.join(a_dir, self.logfile), ["entry_a"])
        v = self.remote.get_version()
        self.assertTrue(self.remote.push_from(a_dir, self.logfile, v))

        # Worker B Retry-Loop
        attempt = self._simulate_worker("b", ["entry_b"])
        self.assertIsNotNone(attempt)
        self.assertLessEqual(attempt, 2)

        result = self.remote.get_file(self.logfile)
        self.assertIn("entry_a", result)
        self.assertIn("entry_b", result)

    def test_dedup_prevents_duplicates(self):
        """Dedup-Append fügt keine Zeilen doppelt ein."""
        self.remote.init_file(self.logfile, "# Log\nexisting_entry\n")

        attempt = self._simulate_worker("a", ["existing_entry", "new_entry"])
        self.assertIsNotNone(attempt)

        result = self.remote.get_file(self.logfile)
        count = result.count("existing_entry")
        self.assertEqual(count, 1, "existing_entry darf nicht doppelt vorkommen")
        self.assertIn("new_entry", result)

    def test_five_attempt_retry_loop(self):
        """5 Versuche reichen wenn Remote sich pro Versuch ändert."""
        self.remote.init_file(self.logfile, "# Log\n")

        worker_dir = os.path.join(self.tmpdir, "worker_x")
        os.makedirs(worker_dir)
        local_path = os.path.join(worker_dir, self.logfile)
        appends = ["my_entry"]

        success = False
        for attempt in range(1, 6):
            # reset --hard: fetch aktuellen Remote-Stand
            self.remote.fetch_to(worker_dir, self.logfile)
            # dedup-append eigener Änderungen
            dedup_append_lines(local_path, appends)

            # Version JETZT merken (vor dem Fremd-Push)
            v_before = self.remote.get_version()

            # Simuliere: anderer Worker pusht VOR unserem Push (Konflikte 1-4)
            if attempt < 5:
                other_dir = os.path.join(self.tmpdir, f"other_{attempt}")
                os.makedirs(other_dir)
                self.remote.fetch_to(other_dir, self.logfile)
                append_lines(os.path.join(other_dir, self.logfile),
                             [f"other_entry_{attempt}"])
                self.remote.push_from(other_dir, self.logfile)

            # Push mit der Version VON VOR dem Fremd-Push → scheitert bei 1-4
            if self.remote.push_from(worker_dir, self.logfile, v_before):
                success = True
                break

        self.assertTrue(success, "Push muss innerhalb von 5 Versuchen gelingen")
        result = self.remote.get_file(self.logfile)
        self.assertIn("my_entry", result)
        # Alle anderen Einträge müssen auch erhalten sein (durch fetch+dedup)
        for i in range(1, 5):
            self.assertIn(f"other_entry_{i}", result,
                          f"other_entry_{i} darf nicht verloren gehen")


# ═══════════════════════════════════════════════════════════════
# Test 3: RACE5 – Reset+Reapply für Overwrite-Dateien
# ═══════════════════════════════════════════════════════════════

class TestRace5ResetReapplyOverwrite(unittest.TestCase):
    """Simuliert das backup/restore-Pattern für Overwrite-Dateien
    (false_positive_report.md, false_positives_set.json)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.remote = SimulatedRemote(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_overwrite_file_survives_reset(self):
        """Overwrite-Datei wird VOR reset gesichert und danach zurückgeschrieben."""
        report = "false_positive_report.md"
        fp_json = "false_positives_set.json"

        self.remote.init_file(report, "# Old Report\n")
        self.remote.init_file(fp_json, '{"ips": ["1.1.1.1"]}')

        worker_dir = os.path.join(self.tmpdir, "worker")
        os.makedirs(worker_dir)
        backup_dir = os.path.join(self.tmpdir, "backup")
        os.makedirs(backup_dir)

        # Worker erzeugt neue Versionen
        self.remote.fetch_to(worker_dir, report)
        self.remote.fetch_to(worker_dir, fp_json)
        write_file(os.path.join(worker_dir, report), "# New Report\n")
        write_file(os.path.join(worker_dir, fp_json),
                   '{"ips": ["1.1.1.1", "2.2.2.2"]}')

        # Schritt 1: Backup VOR reset (cp → /tmp)
        shutil.copy2(os.path.join(worker_dir, report),
                     os.path.join(backup_dir, report))
        shutil.copy2(os.path.join(worker_dir, fp_json),
                     os.path.join(backup_dir, fp_json))

        # Simuliere: anderer Worker ändert Remote
        other_dir = os.path.join(self.tmpdir, "other")
        os.makedirs(other_dir)
        self.remote.fetch_to(other_dir, report)
        write_file(os.path.join(other_dir, report), "# Other Report\n")
        self.remote.push_from(other_dir, report)

        # Schritt 2: reset --hard (fetch aktuellen Remote-Stand)
        self.remote.fetch_to(worker_dir, report)
        self.remote.fetch_to(worker_dir, fp_json)

        # Prüfe: nach reset ist der eigene Report weg
        self.assertEqual(read_file(os.path.join(worker_dir, report)),
                         "# Other Report\n")

        # Schritt 3: Backup zurückkopieren (last-write-wins)
        shutil.copy2(os.path.join(backup_dir, report),
                     os.path.join(worker_dir, report))
        shutil.copy2(os.path.join(backup_dir, fp_json),
                     os.path.join(worker_dir, fp_json))

        # Schritt 4: Push
        v = self.remote.get_version()
        self.assertTrue(self.remote.push_from(worker_dir, report, v))

        result = self.remote.get_file(report)
        self.assertEqual(result, "# New Report\n",
                         "Eigener Report muss nach reset+restore überleben")

    def test_mixed_append_and_overwrite(self):
        """false_positive_checker: Log (append) + Report/JSON (overwrite)."""
        logfile = "false_positives_log.txt"
        report = "false_positive_report.md"
        fp_json = "false_positives_set.json"

        self.remote.init_file(logfile, "# FP Log\nold_fp_1.1.1.1\n")
        self.remote.init_file(report, "# Old Report\n")
        self.remote.init_file(fp_json, '{"ips": []}')

        worker_dir = os.path.join(self.tmpdir, "worker")
        backup_dir = os.path.join(self.tmpdir, "backup")
        os.makedirs(worker_dir)
        os.makedirs(backup_dir)

        # Worker-Run: erzeugt neue Daten
        for f in [logfile, report, fp_json]:
            self.remote.fetch_to(worker_dir, f)

        local_log_appends = ["new_fp_2.2.2.2", "new_fp_3.3.3.3"]
        append_lines(os.path.join(worker_dir, logfile), local_log_appends)
        write_file(os.path.join(worker_dir, report), "# Updated Report\n")
        write_file(os.path.join(worker_dir, fp_json),
                   '{"ips": ["2.2.2.2", "3.3.3.3"]}')

        # Backup
        shutil.copy2(os.path.join(worker_dir, report),
                     os.path.join(backup_dir, report))
        shutil.copy2(os.path.join(worker_dir, fp_json),
                     os.path.join(backup_dir, fp_json))

        # Simuliere Konflikt: anderer Worker fügt zum Log hinzu
        other_dir = os.path.join(self.tmpdir, "other")
        os.makedirs(other_dir)
        self.remote.fetch_to(other_dir, logfile)
        append_lines(os.path.join(other_dir, logfile), ["remote_fp_4.4.4.4"])
        self.remote.push_from(other_dir, logfile)

        # RACE5-Pattern: reset + re-apply
        for f in [logfile, report, fp_json]:
            self.remote.fetch_to(worker_dir, f)

        # Append-only: dedup-append
        dedup_append_lines(os.path.join(worker_dir, logfile), local_log_appends)

        # Overwrite: restore from backup
        shutil.copy2(os.path.join(backup_dir, report),
                     os.path.join(worker_dir, report))
        shutil.copy2(os.path.join(backup_dir, fp_json),
                     os.path.join(worker_dir, fp_json))

        # Push
        v = self.remote.get_version()
        self.assertTrue(self.remote.push_from(worker_dir, logfile, v))

        result_log = self.remote.get_file(logfile)
        self.assertIn("old_fp_1.1.1.1", result_log, "Alter Eintrag erhalten")
        self.assertIn("remote_fp_4.4.4.4", result_log, "Remote-Append erhalten")
        self.assertIn("new_fp_2.2.2.2", result_log, "Eigener Append erhalten")
        self.assertIn("new_fp_3.3.3.3", result_log, "Eigener Append erhalten")

        result_report = read_file(os.path.join(worker_dir, report))
        self.assertEqual(result_report, "# Updated Report\n",
                         "Overwrite-Datei muss eigene Version behalten")


# ═══════════════════════════════════════════════════════════════
# Test 4: End-to-End – Mehrere parallele Worker
# ═══════════════════════════════════════════════════════════════

class TestCombinedWorkflowRaceScenario(unittest.TestCase):
    """End-to-end: Mehrere Worker operieren auf gemeinsamen Dateien.
    Verifiziert dass nach allen Push/Retry-Zyklen kein Eintrag
    verloren geht."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.remote = SimulatedRemote(self.tmpdir)
        self.logfile = "test_log.txt"
        self.report = "test_report.md"

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _run_worker_race5(self, worker_id, log_appends, report_content,
                          max_attempts=5):
        """Simuliert einen Worker mit dem vollständigen RACE5-Pattern."""
        wdir = os.path.join(self.tmpdir, f"w_{worker_id}")
        bdir = os.path.join(self.tmpdir, f"b_{worker_id}")
        os.makedirs(wdir, exist_ok=True)
        os.makedirs(bdir, exist_ok=True)

        for attempt in range(1, max_attempts + 1):
            # reset --hard origin
            self.remote.fetch_to(wdir, self.logfile)
            self.remote.fetch_to(wdir, self.report)

            # apply changes
            dedup_append_lines(os.path.join(wdir, self.logfile), log_appends)
            write_file(os.path.join(wdir, self.report), report_content)

            # try push (logfile)
            v = self.remote.get_version()
            if self.remote.push_from(wdir, self.logfile, v):
                # Report auch pushen
                self.remote.push_from(wdir, self.report)
                return attempt
        return None

    def test_two_parallel_workers(self):
        """2 Worker: beide Appends überleben, letzter Report gewinnt."""
        self.remote.init_file(self.logfile, "# Log\n")
        self.remote.init_file(self.report, "# Initial\n")

        # Worker A
        a = self._run_worker_race5("a", ["ip_from_a"], "# Report A\n")
        self.assertIsNotNone(a)

        # Worker B (startet nach A gepusht hat)
        b = self._run_worker_race5("b", ["ip_from_b"], "# Report B\n")
        self.assertIsNotNone(b)

        result = self.remote.get_file(self.logfile)
        self.assertIn("ip_from_a", result, "Worker A Eintrag muss erhalten bleiben")
        self.assertIn("ip_from_b", result, "Worker B Eintrag muss vorhanden sein")

    def test_five_parallel_workers(self):
        """5 Worker hintereinander – alle Appends überleben."""
        self.remote.init_file(self.logfile, "# Log\n")
        self.remote.init_file(self.report, "# Initial\n")

        expected_entries = []
        for i in range(5):
            entry = f"ip_from_worker_{i}"
            expected_entries.append(entry)
            result = self._run_worker_race5(
                str(i), [entry], f"# Report {i}\n"
            )
            self.assertIsNotNone(result, f"Worker {i} muss erfolgreich pushen")

        result = self.remote.get_file(self.logfile)
        for entry in expected_entries:
            self.assertIn(entry, result,
                          f"{entry} darf nicht verloren gehen")

    def test_interleaved_workers_with_conflicts(self):
        """Simuliert echtes Interleaving: Worker B startet bevor A fertig ist."""
        self.remote.init_file(self.logfile, "# Log\n")

        wdir_a = os.path.join(self.tmpdir, "w_ia")
        wdir_b = os.path.join(self.tmpdir, "w_ib")
        bdir_b = os.path.join(self.tmpdir, "b_ib")
        for d in [wdir_a, wdir_b, bdir_b]:
            os.makedirs(d, exist_ok=True)

        # Beide Worker lesen gleichzeitig den gleichen Stand
        self.remote.fetch_to(wdir_a, self.logfile)
        self.remote.fetch_to(wdir_b, self.logfile)

        # Worker A ändert und pusht
        append_lines(os.path.join(wdir_a, self.logfile), ["entry_alpha"])
        v = self.remote.get_version()
        self.assertTrue(self.remote.push_from(wdir_a, self.logfile, v))

        # Worker B: eigene Appends sichern
        local_appends_b = ["entry_beta"]

        # Worker B: Push scheitert (alter Stand)
        v_old = v  # B hat alten Stand, Remote hat jetzt v+1
        self.assertFalse(self.remote.push_from(wdir_b, self.logfile, v_old))

        # Worker B: RACE5 retry
        self.remote.fetch_to(wdir_b, self.logfile)
        dedup_append_lines(os.path.join(wdir_b, self.logfile), local_appends_b)
        v = self.remote.get_version()
        self.assertTrue(self.remote.push_from(wdir_b, self.logfile, v))

        result = self.remote.get_file(self.logfile)
        self.assertIn("entry_alpha", result, "Alpha darf nicht verloren gehen")
        self.assertIn("entry_beta", result, "Beta muss vorhanden sein")
        # Keine Duplikate
        self.assertEqual(result.count("entry_alpha"), 1)
        self.assertEqual(result.count("entry_beta"), 1)


# ═══════════════════════════════════════════════════════════════
# Test 5: CIDR-Overlap-Bug (BUG-PRIV1)
# ═══════════════════════════════════════════════════════════════

class TestCIDROverlapBug(unittest.TestCase):
    """Verifiziert den Fix für BUG-PRIV1: CIDRs die private Ranges
    überlappen müssen abgelehnt werden."""

    def test_192_128_slash9_rejected(self):
        """192.128.0.0/9 überlappt 192.168.0.0/16 → muss False sein."""
        from netshield_common import is_valid_public_cidr
        self.assertFalse(is_valid_public_cidr("192.128.0.0/9"))

    def test_100_64_slash10_rejected(self):
        """100.64.0.0/10 ist CGNAT → muss False sein."""
        from netshield_common import is_valid_public_cidr
        self.assertFalse(is_valid_public_cidr("100.64.0.0/10"))

    def test_10_slash7_rejected(self):
        """10.0.0.0/7 überlappt 10.0.0.0/8 → muss False sein."""
        from netshield_common import is_valid_public_cidr
        self.assertFalse(is_valid_public_cidr("10.0.0.0/7"))

    def test_172_slash8_rejected(self):
        """172.0.0.0/8 überlappt 172.16.0.0/12 → muss False sein."""
        from netshield_common import is_valid_public_cidr
        self.assertFalse(is_valid_public_cidr("172.0.0.0/8"))

    def test_public_cidr_accepted(self):
        """Normales öffentliches CIDR bleibt gültig."""
        from netshield_common import is_valid_public_cidr
        self.assertTrue(is_valid_public_cidr("1.2.3.0/24"))
        self.assertTrue(is_valid_public_cidr("5.72.0.0/15"))
        self.assertTrue(is_valid_public_cidr("192.128.0.0/16"))  # kein Overlap

    def test_parse_entries_filters_overlapping_cidr(self):
        """parse_entries() muss 192.128.0.0/9 herausfiltern."""
        from netshield_common import parse_entries
        result = parse_entries("192.128.0.0/9\n1.2.3.4\n100.64.0.0/10")
        self.assertNotIn("192.128.0.0/9", result)
        self.assertNotIn("100.64.0.0/10", result)
        self.assertIn("1.2.3.4", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
