"""Performance paths must preserve feed bytes, fresh values and SQL results."""
import ast
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import netshield_common as nc


class CombinedTimingTests(unittest.TestCase):
    def db(self):
        db = nc.SqliteSeenDB(':memory:')
        self.addCleanup(db.close)
        return db

    def test_cached_feed_bytes_and_database_rows_match_uncached(self):
        before, after = self.db(), self.db()
        after.set_feed_cache_enabled(True)
        values = [[], ['b', 'a', 'a'], ['quote"', 'back\\slash', '\n', 'ä', '𐍈'],
                  [str(i) for i in range(300)], ['x' * 9000],
                  [1, None, True], [{'nested': ['a']}], {'legacy': 'value'}]
        for i, feeds in enumerate(values):
            entry = dict(first='2026-08-01', last='2000-01-01', hq=False,
                         feeds=feeds, hq_feed_names=feeds, hq_feeds=2,
                         today_count=3, today_hq=True, days_seen=7,
                         auto_today_count=4 if i % 2 else None)
            for db in (before, after):
                db[str(i)] = entry
            self.assertEqual(before[str(i)], after[str(i)])
        self.assertEqual(list(before._conn.execute('SELECT * FROM seen_db ORDER BY ip')),
                         list(after._conn.execute('SELECT * FROM seen_db ORDER BY ip')))

    def test_cached_reads_are_fresh_and_never_cache_ip_state(self):
        db = self.db()
        db.set_feed_cache_enabled(True)
        for ip in ('a', 'b'):
            db[ip] = dict(feeds=['z', 'a'], hq_feed_names=['hq'], last='2026-09-12')
        value = db['a']
        value['feeds'].append('changed')
        value['hq_feed_names'].clear()
        self.assertEqual(db['a']['feeds'], ['z', 'a'])
        self.assertEqual(db['b']['hq_feed_names'], ['hq'])
        db._conn.execute("UPDATE seen_db SET feeds = ?, last = ? WHERE ip = 'a'",
                         ('["new"]', '2026-09-13'))
        self.assertEqual(db['a']['feeds'], ['new'])
        self.assertEqual(db['a']['last'], '2026-09-13')
        del db['a']
        self.assertIsNone(db.get('a'))

    def test_mutable_nonstandard_json_and_parse_errors_keep_original_behavior(self):
        db = self.db()
        db.set_feed_cache_enabled(True)
        for raw in ('[{"nested":[1]}]', '{"legacy":[1]}', 'null', '1', '"name"'):
            first = db._decode_feed_list(raw)
            if isinstance(first, list):
                first[0]['nested'].append(2)
            elif isinstance(first, dict):
                first['legacy'].append(2)
            self.assertEqual(db._decode_feed_list(raw), json.loads(raw))
        for raw in ('[broken', b'[broken'):
            with self.assertRaises(json.JSONDecodeError):
                db._decode_feed_list(raw)
        with self.assertRaises(TypeError):
            db._encode_feed_list([{'unserializable': object()}])

    def test_repeated_values_use_bounded_caches_and_disable_releases_them(self):
        db = self.db()
        with patch.object(nc.json, 'loads', wraps=json.loads) as loads:
            db.set_feed_cache_enabled(True)
            for _ in range(3):
                db._decode_feed_list('["first"]')
            self.assertEqual(loads.call_count, 1)
            for i in range(4096):
                db._decode_feed_list('["feed_' + str(i) + '"]')
            calls = loads.call_count
            db._decode_feed_list('["first"]')
            self.assertEqual(loads.call_count, calls + 1)
        with patch.object(nc.json, 'dumps', wraps=json.dumps) as dumps:
            db.set_feed_cache_enabled(True)
            for _ in range(3):
                db._encode_feed_list(['first'])
            self.assertEqual(dumps.call_count, 1)
            for i in range(4096):
                db._encode_feed_list(['feed_' + str(i)])
            calls = dumps.call_count
            db._encode_feed_list(['first'])
            self.assertEqual(dumps.call_count, calls + 1)
        db.set_feed_cache_enabled(False)
        self.assertIs(db._decode_feed_list, json.loads)
        self.assertIs(db._encode_feed_list, json.dumps)

    def test_export_is_byte_identical_and_rollback_remains_effective(self):
        before, after = self.db(), self.db()
        after.set_feed_cache_enabled(True)
        for db in (before, after):
            db['45.1.0.1'] = dict(feeds=['z', 'a'], hq_feed_names=['hq'], days_seen=2)
            db.commit()
            value = db['45.1.0.1']
            value['feeds'].append('new')
            db['45.1.0.1'] = value
            db._conn.rollback()
            self.assertEqual(db['45.1.0.1']['feeds'], ['z', 'a'])
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / 'a.json', Path(directory) / 'b.json'
            before.export_json_atomic(str(a))
            after.export_json_atomic(str(b))
            self.assertEqual(a.read_bytes(), b.read_bytes())

    def test_ordered_ingest_preserves_duplicates_hq_overrides_and_feed_counts(self):
        source = (ROOT / '.github/workflows/update_combined_blacklist.yml').read_text(encoding='utf-8')
        start = source.index('          def _ingest(name, ips, is_hq_override=None):')
        end = source.index('          # ── Slow-Feeds', start)
        code = textwrap.dedent(source[start:end])
        # Reference uses the previous insertion order with the same SQL.
        reference = code.replace('for ip in sorted(ips)', 'for ip in ips')
        self.assertNotEqual(reference, code)
        results = []
        for version in (reference, code):
            conn = sqlite3.connect(':memory:')
            self.addCleanup(conn.close)
            conn.execute('CREATE TEMP TABLE run_feed_hits (ip TEXT NOT NULL, feed TEXT NOT NULL, '
                         'is_hq INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(ip,feed)) WITHOUT ROWID')
            env = dict(_run_conn=conn, HIGH_QUALITY={'hq'}, coerce_bool=nc.coerce_bool, feed_stats=[])
            exec(compile(ast.parse(version), '<workflow ingest>', 'exec'), env)
            for name, ips, override in [
                ('normal', ['45.10.0.2', '45.2.0.1', '45.10.0.2', '45.1.0.0/24'], None),
                ('normal', ['45.2.0.1'], True),
                ('normal', ['45.2.0.1'], False),
                ('hq', {'45.2.0.1', '45.1.0.2'}, None),
                ('empty', set(), False),
            ]:
                env['_ingest'](name, ips, override)
            results.append((list(conn.execute('SELECT * FROM temp.run_feed_hits ORDER BY ip,feed')),
                            env['feed_stats']))
        self.assertEqual(results[0], results[1])


if __name__ == '__main__':
    unittest.main()
