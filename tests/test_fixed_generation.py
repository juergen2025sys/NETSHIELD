import json
import ipaddress
import sqlite3
import tempfile
import time
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from netshield_common import canonical_host_entries
from netshield_report_utils import published_list_status
from netshield_snapshot import validate_snapshot


class FixedGenerationTests(unittest.TestCase):
    def test_host_normalization_removes_only_slash32_duplicates(self):
        self.assertEqual(canonical_host_entries([
            '8.8.8.8', '8.8.8.8/32', '192.0.2.0/24', 'invalid',
        ]), {'8.8.8.8'})

    def test_report_marks_missing_confidence_part(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'blacklist_confidence40_ipv4.txt'
            path.with_name(path.stem + '_part1.txt').write_text(
                '# Aktualisiert: 2026-09-12 12:00 CEST\n8.8.8.8\n', encoding='utf-8')
            self.assertEqual(published_list_status(path, required_parts=(1, 2))['state'], 'incomplete')

    def test_snapshot_rejects_future_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'snapshot.sqlite3'
            now = int(time.time())
            db = sqlite3.connect(path)
            db.executescript('''
                CREATE TABLE hits(entry TEXT, feed TEXT);
                CREATE TABLE meta(key TEXT, value TEXT);
                CREATE TABLE feed_stats(feed TEXT, entries INTEGER, status TEXT, last_success_epoch INTEGER);
            ''')
            base = int(ipaddress.IPv4Address('45.1.0.1'))
            rows = [(str(ipaddress.IPv4Address(base + i)), 'feed') for i in range(50000)]
            db.executemany('INSERT INTO hits VALUES (?,?)', rows)
            db.executemany('INSERT INTO meta VALUES (?,?)', [
                ('refresh_run_at_epoch', str(now)), ('generated_at_epoch', str(now + 1))])
            db.execute('INSERT INTO feed_stats VALUES (?,?,?,?)', ('feed', 50000, 'ok', now + 1))
            db.commit(); db.close()
            with self.assertRaises(ValueError):
                validate_snapshot(path, now=now)

    def test_report_distinguishes_absent_empty_and_unexpected_parts(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'blacklist_confidence40_ipv4.txt'
            self.assertEqual(published_list_status(path, (1, 2))['state'], 'missing')
            for number in (1, 2):
                path.with_name(path.stem + f'_part{number}.txt').write_text('# empty\n')
            self.assertEqual(published_list_status(path, (1, 2))['state'], 'empty')
            path.with_name(path.stem + '_part3.txt').write_text('45.1.0.1\n')
            self.assertEqual(published_list_status(path, (1, 2))['state'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
