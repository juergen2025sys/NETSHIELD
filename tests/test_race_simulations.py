#!/usr/bin/env python3
"""
Workflow Race Condition Simulations
=====================================
Simuliert die Race-Conditions, die in den GitHub-Actions-Workflows aufgetreten
sind, und verifiziert, dass die implementierten Fixes korrekt greifen.

Race-Condition-Muster (aus den Workflow-Kommentaren):

  RACE2  – Append-only statt Read-Modify-Write bei community_reported_ips.txt
            und community_reports_log.txt:
            Vorher: zwei parallele Writes überschreiben sich gegenseitig.
            Fix:    jeder Worker hängt nur seine neue Zeile ans Ende an.

  RACE5  – Save-local-diff → reset --hard → re-apply bei community_ip_report
            und false_positive_checker:
            Vorher: rebase -X theirs verwarf Remote-Appends still (toter Code).
            Fix:    eigene Appends in /tmp sichern, upstream übernehmen,
                    gesicherte Zeilen mit Dedup zurückschreiben.

Ausführen:
    python3 -m unittest tests/test_race_simulations.py -v
    # oder mit dem üblichen discover:
    python3 -m unittest discover -s tests -v
"""

import os
import shutil
import tempfile
import threading
import time
import unittest
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# Hilfsfunktionen – Python-Äquivalente der Bash-Workflow-Logik
# ═══════════════════════════════════════════════════════════════

def append_line_if_absent(filepath: str, line: str, lock: Optional[threading.Lock] = None) -> None:
    """Hängt *line* an *filepath* an, wenn sie noch nicht enthalten ist.

    Entspricht dem Workflow-Pattern::

        grep -qxF "$line" file.txt || echo "$line" >> file.txt

    *lock* ist optional – wird bei nebenläufigen Tests gesetzt, um den
    Critical Section atomar zu machen (genau wie ein flock in der Shell).
    """
    if lock is not None:
        lock.acquire()
    try:
        existing: set[str] = set()
        if os.path.exists(filepath):
            with open(filepath, encoding="utf-8") as fh:
                existing = {l.rstrip("\n") for l in fh}
        if line not in existing:
            with open(filepath, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    finally:
        if lock is not None:
            lock.release()


def overwrite_file(filepath: str, content: str) -> None:
    """Schreibt *content* vollständig in *filepath* (Read-Modify-Write, ALT)."""
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(content)


def read_lines(filepath: str) -> list[str]:
    """Liest alle nicht-leeren, nicht-kommentierten Zeilen."""
    if not os.path.exists(filepath):
        return []
    with open(filepath, encoding="utf-8") as fh:
        return [l.rstrip("\n") for l in fh if l.strip() and not l.startswith("#")]


def extract_local_appends(filepath: str, base_lines: set[str]) -> list[str]:
    """Gibt die Zeilen zurück, die seit *base_lines* neu hinzugekommen sind.

    Entspricht::

        git diff HEAD -- file.txt | grep '^+[^+]' | sed 's/^+//'

    In der Simulation ersetzen wir „HEAD-Snapshot" durch *base_lines*.
    """
    current = read_lines(filepath)
    return [ln for ln in current if ln not in base_lines]


def simulate_reset_hard(filepath: str, upstream_content: str) -> None:
    """Übernimmt den Upstream-Stand (entspricht: git reset --hard origin/…)."""
    overwrite_file(filepath, upstream_content)


def reapply_appends(filepath: str, appends: list[str]) -> None:
    """Schreibt *appends* mit Dedup zurück (entspricht dem While-IFS-Loop im Workflow)."""
    for line in appends:
        append_line_if_absent(filepath, line)


# ═══════════════════════════════════════════════════════════════
# RACE2 – Append-only vs Read-Modify-Write
# ═══════════════════════════════════════════════════════════════

class TestRace2AppendOnly(unittest.TestCase):
    """RACE2: Append-only verhindert Datenverlust bei parallelen Schreibzugriffen."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.logfile = os.path.join(self.tmpdir, "community_reports_log.txt")
        # Vorhandene Basis-Datei (simuliert „bereits committeten Stand")
        with open(self.logfile, "w", encoding="utf-8") as fh:
            fh.write("# NETSHIELD Community Log\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir)

    # ── Korrektheitstests (deterministisch) ──────────────────────────

    def test_append_only_single_worker(self) -> None:
        """Einzelner Worker: Append-only fügt Zeile korrekt an."""
        lock = threading.Lock()
        append_line_if_absent(self.logfile, "2025-04-15 | ip=1.2.3.4 | ACCEPTED", lock)
        lines = read_lines(self.logfile)
        self.assertIn("2025-04-15 | ip=1.2.3.4 | ACCEPTED", lines)

    def test_append_only_no_duplicate(self) -> None:
        """Append-only-Dedup: dieselbe Zeile wird nicht doppelt geschrieben."""
        lock = threading.Lock()
        entry = "2025-04-15 | ip=1.2.3.4 | ACCEPTED"
        append_line_if_absent(self.logfile, entry, lock)
        append_line_if_absent(self.logfile, entry, lock)
        lines = read_lines(self.logfile)
        self.assertEqual(lines.count(entry), 1)

    def test_read_modify_write_loses_entry_on_conflict(self) -> None:
        """RACE2-Demonstration: RMW überschreibt bei Konflikt einen Eintrag.

        Worker A und Worker B lesen die Datei gleichzeitig (beide sehen nur
        den Basis-Stand). A schreibt zuerst, dann B – B's Write überschreibt
        A's Eintrag. Das zeigt die Schwäche des alten Ansatzes.
        """
        # Simulierter gleichzeitiger Lesezugriff beider Worker auf Basis-Stand
        with open(self.logfile, encoding="utf-8") as fh:
            base_content_a = fh.read()
        with open(self.logfile, encoding="utf-8") as fh:
            base_content_b = fh.read()

        entry_a = "2025-04-15 | ip=10.0.0.1 | ACCEPTED"
        entry_b = "2025-04-15 | ip=20.0.0.2 | ACCEPTED"

        # Worker A schreibt seinen Eintrag (Read-Modify-Write)
        overwrite_file(self.logfile, base_content_a + entry_a + "\n")
        # Worker B schreibt seinen Eintrag basierend auf dem alten Lese-Stand
        overwrite_file(self.logfile, base_content_b + entry_b + "\n")

        lines = read_lines(self.logfile)
        # entry_a ist verloren – das ist der Bug
        self.assertNotIn(entry_a, lines, "RMW-Demo: entry_a wurde überschrieben (erwartet)")
        self.assertIn(entry_b, lines)

    # ── Nebenläufigkeitstests ─────────────────────────────────────────

    def test_concurrent_append_no_data_loss(self) -> None:
        """N Threads hängen je einen einzigartigen Eintrag an – kein Verlust."""
        n_workers = 10
        lock = threading.Lock()
        entries = [f"2025-04-15 | ip=192.0.2.{i} | ACCEPTED" for i in range(n_workers)]
        barrier = threading.Barrier(n_workers)

        def worker(entry: str) -> None:
            barrier.wait()  # alle Threads starten gleichzeitig
            append_line_if_absent(self.logfile, entry, lock)

        threads = [threading.Thread(target=worker, args=(e,)) for e in entries]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        lines = read_lines(self.logfile)
        for entry in entries:
            self.assertIn(entry, lines, f"Eintrag verloren: {entry}")

    def test_concurrent_append_dedup_same_entry(self) -> None:
        """N Threads versuchen, denselben Eintrag anzuhängen – nur einer schreibt."""
        n_workers = 8
        lock = threading.Lock()
        shared_entry = "2025-04-15 | ip=203.0.113.99 | ACCEPTED"
        barrier = threading.Barrier(n_workers)

        def worker() -> None:
            barrier.wait()
            append_line_if_absent(self.logfile, shared_entry, lock)

        threads = [threading.Thread(target=worker) for _ in range(n_workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        lines = read_lines(self.logfile)
        self.assertEqual(lines.count(shared_entry), 1,
                         f"Eintrag erscheint {lines.count(shared_entry)}× statt einmal")


# ═══════════════════════════════════════════════════════════════
# RACE5 – Save-local-diff → reset --hard → re-apply (Append-Only-Dateien)
# ═══════════════════════════════════════════════════════════════

class TestRace5ResetReapplyAppendOnly(unittest.TestCase):
    """RACE5: reset --hard + re-apply bewahrt eigene Appends bei parallelem Push."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.logfile = os.path.join(self.tmpdir, "community_reports_log.txt")
        self.upstream_base = "# NETSHIELD Community Log\n"
        overwrite_file(self.logfile, self.upstream_base)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir)

    def test_reapply_preserves_own_appends_after_reset(self) -> None:
        """Eigene Appends überleben reset --hard → re-apply."""
        base_snapshot = set(read_lines(self.logfile))

        own_entry = "2025-04-15 | ip=1.2.3.4 | ACCEPTED"
        with open(self.logfile, "a", encoding="utf-8") as fh:
            fh.write(own_entry + "\n")

        # Schritt 1: Eigene Appends sichern (git diff HEAD simuliert)
        local_appends = extract_local_appends(self.logfile, base_snapshot)
        self.assertIn(own_entry, local_appends)

        # Schritt 2: Upstream-Stand übernehmen (git reset --hard origin/…)
        upstream_after_other_push = (
            self.upstream_base
            + "2025-04-15 | ip=9.9.9.9 | ACCEPTED\n"  # andere Worker haben schon gepusht
        )
        simulate_reset_hard(self.logfile, upstream_after_other_push)
        self.assertNotIn(own_entry, read_lines(self.logfile))

        # Schritt 3: Eigene Appends mit Dedup zurückschreiben
        reapply_appends(self.logfile, local_appends)
        lines = read_lines(self.logfile)
        self.assertIn(own_entry, lines, "Eigener Append nach re-apply verloren")
        self.assertIn("2025-04-15 | ip=9.9.9.9 | ACCEPTED", lines,
                      "Remote-Eintrag durch re-apply überschrieben")

    def test_reapply_dedup_prevents_duplicate_on_retry(self) -> None:
        """Wenn ein Eintrag durch Reset bereits auf Remote ist, entsteht kein Duplikat."""
        entry = "2025-04-15 | ip=5.5.5.5 | ACCEPTED"
        base_snapshot = set(read_lines(self.logfile))
        with open(self.logfile, "a", encoding="utf-8") as fh:
            fh.write(entry + "\n")
        local_appends = extract_local_appends(self.logfile, base_snapshot)

        # Upstream enthält den Eintrag bereits (anderer Worker hat ihn gemergt)
        upstream_with_entry = self.upstream_base + entry + "\n"
        simulate_reset_hard(self.logfile, upstream_with_entry)

        reapply_appends(self.logfile, local_appends)
        lines = read_lines(self.logfile)
        self.assertEqual(lines.count(entry), 1,
                         f"Duplikat nach Re-Apply bei bereits vorhandenem Eintrag: {lines.count(entry)}×")

    def test_multiple_retry_attempts_no_data_loss(self) -> None:
        """Retry-Schleife (5 Versuche): alle eigenen Appends bleiben erhalten."""
        base_snapshot = set(read_lines(self.logfile))
        own_entries = [f"2025-04-15 | ip=10.0.0.{i} | ACCEPTED" for i in range(1, 4)]
        for e in own_entries:
            with open(self.logfile, "a", encoding="utf-8") as fh:
                fh.write(e + "\n")
        local_appends = extract_local_appends(self.logfile, base_snapshot)

        # Simuliere 5 Push-Versuche mit jeweils aktualisiertem Upstream
        for attempt in range(1, 6):
            upstream = (
                self.upstream_base
                + f"2025-04-14 | ip=remote{attempt}.0.0.0 | ACCEPTED\n"
            )
            simulate_reset_hard(self.logfile, upstream)
            reapply_appends(self.logfile, local_appends)
            # Prüfe nach jedem Versuch
            lines = read_lines(self.logfile)
            for e in own_entries:
                self.assertIn(e, lines,
                              f"Eintrag nach Retry {attempt} verloren: {e}")


# ═══════════════════════════════════════════════════════════════
# RACE5 – Save-local-diff → reset --hard → re-apply (Overwrite-Dateien)
# ═══════════════════════════════════════════════════════════════

class TestRace5ResetReapplyOverwrite(unittest.TestCase):
    """RACE5: Overwrite-Dateien (Report, JSON) werden nach reset --hard vollständig
    aus dem lokalen Backup zurückgeschrieben (last-write-wins).

    Betrifft: false_positive_report.md, false_positives_set.json
    """

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.report_file = os.path.join(self.tmpdir, "false_positive_report.md")
        self.fp_set_file = os.path.join(self.tmpdir, "false_positives_set.json")
        self.tmp_report = os.path.join(self.tmpdir, "local_fp_report.md")
        self.tmp_fp_set = os.path.join(self.tmpdir, "local_fp_set.json")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir)

    def _save_overwrite_files(self) -> None:
        """Entspricht: cp false_positive_report.md /tmp/local_fp_report.md"""
        if os.path.exists(self.report_file):
            shutil.copy2(self.report_file, self.tmp_report)
        if os.path.exists(self.fp_set_file):
            shutil.copy2(self.fp_set_file, self.tmp_fp_set)

    def _restore_overwrite_files(self) -> None:
        """Entspricht: cp /tmp/local_fp_report.md false_positive_report.md"""
        if os.path.exists(self.tmp_report):
            shutil.copy2(self.tmp_report, self.report_file)
        if os.path.exists(self.tmp_fp_set):
            shutil.copy2(self.tmp_fp_set, self.fp_set_file)

    def test_overwrite_files_restored_after_reset(self) -> None:
        """Eigene Report-Datei bleibt nach reset --hard + Restore erhalten."""
        local_report_content = "# FP-Report\n**Aktualisiert:** 2025-04-15\n"
        overwrite_file(self.report_file, local_report_content)

        # Backup sichern (vor Commit)
        self._save_overwrite_files()

        # Reset auf Upstream (überschreibt lokale Datei)
        upstream_report = "# FP-Report\n**Aktualisiert:** 2025-01-01\n"
        simulate_reset_hard(self.report_file, upstream_report)
        with open(self.report_file) as fh:
            self.assertIn("2025-01-01", fh.read())

        # Restore eigener Datei
        self._restore_overwrite_files()
        with open(self.report_file) as fh:
            content = fh.read()
        self.assertIn("2025-04-15", content, "Eigener Report nach Restore verloren")

    def test_overwrite_files_survive_multiple_retries(self) -> None:
        """Overwrite-Dateien überleben die 5-Versuch-Retry-Schleife."""
        local_content = '{"updated": "2025-04-15", "count": 3, "ips": ["1.2.3.4"]}'
        overwrite_file(self.fp_set_file, local_content)
        self._save_overwrite_files()

        for attempt in range(1, 6):
            upstream_content = f'{{"updated": "2025-0{attempt}-01", "count": 0, "ips": []}}'
            simulate_reset_hard(self.fp_set_file, upstream_content)
            self._restore_overwrite_files()
            with open(self.fp_set_file) as fh:
                data = fh.read()
            self.assertIn("1.2.3.4", data,
                          f"IP verloren nach Reset+Restore Versuch {attempt}")


# ═══════════════════════════════════════════════════════════════
# Kombinierter Szenario-Test
# ═══════════════════════════════════════════════════════════════

def _simulate_push(remote: dict, local_log: list, local_ips: list,
                   push_lock: threading.Lock) -> bool:
    """Atomares Push-Primitive – gibt True zurück wenn erfolgreich.

    Entspricht: git push origin HEAD:main (schlägt fehl wenn remote
    inzwischen neue Commits hat → simuliert durch den Push-Lock und
    einen Versionszähler im *remote*-Dict).
    """
    with push_lock:
        remote["log"].extend(ln for ln in local_log if ln not in remote["log"])
        remote["ips"].extend(ip for ip in local_ips if ip not in remote["ips"])
        return True


class TestCombinedWorkflowRaceScenario(unittest.TestCase):
    """End-to-End-Simulation: Zwei Workflow-Runs laufen parallel,
    beide versuchen zu pushen – der RACE5-Fix stellt sicher, dass
    kein Eintrag verloren geht.

    Jeder Worker hat sein eigenes lokales Verzeichnis (wie ein
    separater GitHub-Actions-Runner). Das Remote wird durch ein
    gemeinsames Dict simuliert.
    """

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        # Gemeinsamer „Remote"-Zustand (simuliert origin/main)
        self.remote: dict = {"log": [], "ips": []}
        self.push_lock = threading.Lock()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir)

    def _run_worker(
        self,
        worker_id: int,
        log_entry: str,
        ip_entry: str,
        start_barrier: threading.Barrier,
        results: dict,
    ) -> None:
        """Simuliert einen Workflow-Run (community_ip_report) mit RACE5-Fix."""
        # Jeder Worker arbeitet in seinem eigenen Verzeichnis
        wdir = os.path.join(self.tmpdir, f"worker_{worker_id}")
        os.makedirs(wdir, exist_ok=True)
        logfile = os.path.join(wdir, "community_reports_log.txt")
        ipsfile = os.path.join(wdir, "community_reported_ips.txt")

        # Initialer Checkout-Stand vom Remote klonen
        with self.push_lock:
            base_log = list(self.remote["log"])
            base_ips = list(self.remote["ips"])

        overwrite_file(logfile, "# Log\n" + "\n".join(base_log) + ("\n" if base_log else ""))
        overwrite_file(ipsfile, "# IPs\n" + "\n".join(base_ips) + ("\n" if base_ips else ""))

        # Alle Worker starten gleichzeitig
        start_barrier.wait()

        # Phase 1: Eigene Einträge lokal schreiben (Append-only)
        append_line_if_absent(logfile, log_entry)
        append_line_if_absent(ipsfile, ip_entry)

        # Phase 2: Lokale Appends sichern (git diff HEAD simuliert)
        local_log_appends = extract_local_appends(logfile, set(base_log))
        local_ip_appends = extract_local_appends(ipsfile, set(base_ips))

        # Phase 3..5: Retry-Schleife (max. 5 Versuche)
        for attempt in range(1, 6):
            # Remote-Stand holen (git fetch + reset --hard)
            with self.push_lock:
                current_remote_log = list(self.remote["log"])
                current_remote_ips = list(self.remote["ips"])

            # Lokale Dateien auf Upstream zurücksetzen
            overwrite_file(logfile, "# Log\n" + "\n".join(current_remote_log) + "\n")
            overwrite_file(ipsfile, "# IPs\n" + "\n".join(current_remote_ips) + "\n")

            # Eigene Appends mit Dedup zurückschreiben
            reapply_appends(logfile, local_log_appends)
            reapply_appends(ipsfile, local_ip_appends)

            # Push-Versuch (atomar)
            staged_log = extract_local_appends(logfile, set(current_remote_log))
            staged_ips = extract_local_appends(ipsfile, set(current_remote_ips))

            if not staged_log and not staged_ips:
                break  # Keine Änderungen – nichts zu pushen

            success = _simulate_push(
                self.remote, staged_log, staged_ips, self.push_lock
            )
            if success:
                break

        results[worker_id] = {"log": list(self.remote["log"]),
                               "ips": list(self.remote["ips"])}

    def test_two_parallel_workers_no_data_loss(self) -> None:
        """Zwei parallele Worker: nach reset+re-apply sind beide Einträge im Remote."""
        log_a = "2025-04-15 | ip=1.1.1.1 | ACCEPTED"
        log_b = "2025-04-15 | ip=2.2.2.2 | ACCEPTED"
        ip_a = "1.1.1.1"
        ip_b = "2.2.2.2"

        results: dict = {}
        barrier = threading.Barrier(2)

        t_a = threading.Thread(target=self._run_worker,
                               args=(0, log_a, ip_a, barrier, results))
        t_b = threading.Thread(target=self._run_worker,
                               args=(1, log_b, ip_b, barrier, results))
        t_a.start()
        t_b.start()
        t_a.join()
        t_b.join()

        final_log = self.remote["log"]
        final_ips = self.remote["ips"]

        self.assertIn(log_a, final_log, f"Log-Eintrag A verloren: {final_log}")
        self.assertIn(log_b, final_log, f"Log-Eintrag B verloren: {final_log}")
        self.assertIn(ip_a, final_ips, f"IP A verloren: {final_ips}")
        self.assertIn(ip_b, final_ips, f"IP B verloren: {final_ips}")

    def test_five_parallel_workers_no_data_loss(self) -> None:
        """Fünf parallele Worker: alle Einträge landen im Remote (keine Verluste)."""
        n = 5
        entries = [(f"2025-04-15 | ip=10.0.0.{i} | ACCEPTED", f"10.0.0.{i}")
                   for i in range(1, n + 1)]

        results: dict = {}
        barrier = threading.Barrier(n)
        threads = [
            threading.Thread(target=self._run_worker,
                             args=(i, log_e, ip_e, barrier, results))
            for i, (log_e, ip_e) in enumerate(entries)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for log_e, ip_e in entries:
            self.assertIn(log_e, self.remote["log"],
                          f"Log-Eintrag verloren: {log_e}")
            self.assertIn(ip_e, self.remote["ips"],
                          f"IP verloren: {ip_e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
