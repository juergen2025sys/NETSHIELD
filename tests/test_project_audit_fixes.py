"""Project audit and performance regressions using real workflow code offline."""
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import sqlite3
import subprocess
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
import urllib.error

import yaml

from tests import test_release_audit_fixes as helpers

ROOT = helpers.ROOT
nc = helpers.nc


def steps(workflow):
    doc = yaml.safe_load((ROOT / '.github/workflows' / workflow).read_text())
    return [step for job in doc['jobs'].values() for step in job['steps']]


def eligible(condition, outcomes):
    """Evaluate the success conjunctions used by these publication steps."""
    values = []
    for clause in condition.split('&&'):
        clause = clause.strip()
        if clause == 'always()':
            values.append(True)
        elif clause == 'success()':
            values.append(all(value == 'success' for value in outcomes.values()))
        else:
            match = re.fullmatch(r"steps\.([a-z_]+)\.outcome == 'success'", clause)
            if not match:
                raise AssertionError(f'Unexpected condition: {condition}')
            values.append(outcomes.get(match[1]) == 'success')
    return all(values)


class ProjectAuditTests(unittest.TestCase):
    def setUp(self):
        self.case = helpers.AuditFixTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def test_confidence_small_output_keeps_both_canonical_parts(self):
        ips = helpers.public_ips(1201)
        now = datetime.now(timezone.utc)
        day = now.strftime('%Y-%m-%d')
        entry = {'first': day, 'last': day, 'hq': True, 'feeds': ['a', 'b'],
                 'today_count': 2, 'days_seen': 14}
        Path('seen_db.json').write_text(json.dumps({ip: entry for ip in ips}))
        Path('combined_threat_blacklist_ipv4.txt').write_text('\n'.join(ips))
        Path('state/seen_db_meta.json').write_text(json.dumps({'updated': now.strftime('%Y-%m-%d %H:%M UTC')}))
        Path('blacklist_confidence40_ipv4_part3.txt').write_text('45.99.0.1\n')
        result = self.case.run_code('update_confidence_blacklist.yml', 'combined_ips = set()', {'NETSHIELD_SQLITE_TEST': '0'})
        self.case.assert_run_ok(result)
        parts = [Path(f'blacklist_confidence40_ipv4_part{i}.txt') for i in (1, 2)]
        rows = [[v for v in p.read_text().splitlines() if v and not v.startswith('#')] for p in parts]
        self.assertEqual(list(map(len, rows)), [601, 600])
        self.assertEqual(rows[0] + rows[1], [ip for ip, score in result[0]['confidence40']])
        self.assertEqual(set(rows[0] + rows[1]), set(ips))
        self.assertFalse(Path('blacklist_confidence40_ipv4_part3.txt').exists())

    def test_publications_require_build_and_validation_success(self):
        cases = [
            ('update_confidence_blacklist.yml', 'Commit', ['build_confidence']),
            ('update-blocklist.yml', 'Commit and Push', ['build_countries']),
            ('auto_feed_refresh.yml', 'Save Auto-Feed Snapshot Cache', ['refresh', 'validate_snapshot']),
            ('auto_feed_refresh.yml', 'Alte Auto-Feed Snapshot Caches aufraeumen', ['refresh', 'validate_snapshot']),
            ('auto_feed_refresh.yml', 'Commit Report und Kompatibilitaetsliste', ['refresh', 'validate_snapshot']),
        ]
        for workflow, name, required in cases:
            with self.subTest(workflow=workflow, step=name):
                sequence = steps(workflow)
                step = next(step for step in sequence if step.get('name') == name)
                step_ids = {step.get('id') for step in sequence}
                missing = set(required) - step_ids
                self.assertEqual(missing, set())
                ok = dict.fromkeys(required, 'success')
                self.assertTrue(eligible(step['if'], ok))
                for dependency in required:
                    for failure in ('failure', 'skipped', 'cancelled'):
                        self.assertFalse(eligible(step['if'], {**ok, dependency: failure}))

    def test_fp_hosts_ranges_and_absent_exclusions_survive(self):
        self.case.fp(['45.1.0.1/32', '45.2.0.37/24', '45.99.1.7'])
        Path('combined_threat_blacklist_ipv4.txt').write_text('\n'.join(helpers.public_ips(1200)))
        result = self.case.run_code('false_positive_checker.yml', 'FP_JSON =')
        self.case.assert_run_ok(result)
        self.assertEqual(set(json.loads(Path('state/false_positives_set.json').read_text())['ips']),
                         {'45.1.0.1', '45.2.0.0/24', '45.99.1.7'})

    def test_corrupt_fp_aborts_without_replacing_state(self):
        path = Path('state/false_positives_set.json')
        path.write_text('{broken')
        result = self.case.run_code('false_positive_checker.yml', 'FP_JSON =')
        self.assertIsInstance(result[1], ValueError)
        self.assertEqual(path.read_text(), '{broken')

    def geo(self, failure):
        old = '45.99.0.1'
        paths = [Path('all_countries_ipv4.txt'), Path('continents/europe_ipv4.txt'),
                 Path('countries/europe/malta_ipv4.txt')]
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f'# old complete snapshot\n{old}\n')
        before = [p.read_bytes() for p in paths]
        body = '\n'.join(helpers.public_ips(240001)).encode()
        calls = []

        def fetch(url, **kwargs):
            cc = url.rsplit('/', 1)[1].split('_', 1)[0]
            if cc == 'AO':
                return helpers.Response(body)
            if cc == 'MT':
                calls.append(cc)
                if failure == 'recover' and len(calls) > 1:
                    return helpers.Response(old.encode())
                code = 503 if failure == 'recover' else failure
                raise urllib.error.HTTPError(url, code, 'fixture', {}, None)
            return helpers.Response(b'')

        with patch.object(nc, 'safe_urlopen', side_effect=fetch), patch('time.sleep'):
            result = self.case.run_code('update-blocklist.yml', 'COUNTRY_MAP =')
        return result, paths, before, calls, old

    def test_geo_partial_failure_preserves_all_outputs_above_minimum(self):
        result, paths, before, calls, _ = self.geo(503)
        self.assertIsInstance(result[1], RuntimeError)
        self.assertEqual(len(calls), 3)
        self.assertEqual([p.read_bytes() for p in paths], before)

    def test_geo_known_missing_country_is_valid_empty_source(self):
        result, paths, _, calls, old = self.geo(404)
        self.case.assert_run_ok(result)
        self.assertEqual(len(calls), 1)
        self.assertNotIn(old, self.case.rows(paths[0]))
        self.assertEqual(self.case.rows(paths[2]), set())

    def test_geo_transient_failure_retries_and_keeps_aggregate_coverage(self):
        result, paths, _, calls, old = self.geo('recover')
        self.case.assert_run_ok(result)
        self.assertEqual(len(calls), 2)
        for path in paths:
            self.assertIn(old, self.case.rows(path))

    def test_auto_snapshot_future_timestamp_is_rejected(self):
        now = int(time.time()) + 100000
        with sqlite3.connect('state/auto_feed_daily.sqlite3') as db:
            db.execute('CREATE TABLE hits(entry TEXT, feed TEXT)')
            db.execute('CREATE TABLE meta(key TEXT, value TEXT)')
            db.execute('CREATE TABLE feed_stats(feed TEXT, entries INTEGER, status TEXT, last_success_epoch INTEGER)')
            db.executemany('INSERT INTO hits VALUES (?, ?)', ((ip, 'feed') for ip in helpers.public_ips(50000)))
            db.executemany('INSERT INTO meta VALUES (?, ?)', [('generated_at_epoch', str(now)), ('refresh_run_at_epoch', str(now))])
            db.execute('INSERT INTO feed_stats VALUES (?, ?, ?, ?)', ('feed', 50000, 'ok', now))
        result = self.case.run_code('auto_feed_refresh.yml', 'MAX_REFRESH_AGE_SECONDS = 3600')
        self.assertIsInstance(result[1], AssertionError)

    def test_report_uses_parts_and_ignores_stale_main(self):
        from netshield_report_utils import count_published_ips, published_list_sources
        Path('sample.txt').write_text('45.99.0.1\n')
        Path('sample_part10.txt').write_text('# header\n45.1.0.2\n')
        Path('sample_part2.txt').write_text('45.1.0.1\n45.1.0.2\n')
        Path('sample_part_bad.txt').write_text('45.99.0.2\n')
        self.assertEqual(count_published_ips('sample.txt'), 2)
        self.assertEqual([p.name for p in published_list_sources('sample.txt')], ['sample_part2.txt', 'sample_part10.txt'])

    def test_report_missing_legacy_and_inconsistent_part_dates(self):
        from netshield_report_utils import count_published_ips, published_list_updated
        self.assertEqual(count_published_ips('sample.txt'), 0)
        self.assertIsNone(count_published_ips('sample.txt', missing=None))
        self.assertEqual(published_list_updated('sample.txt'), '–')
        Path('sample.txt').write_text('# Aktualisiert: 2026-09-11 12:00 UTC\n45.1.0.1\n')
        self.assertEqual(count_published_ips('sample.txt'), 1)
        self.assertEqual(published_list_updated('sample.txt'), '2026-09-11 12:00 UTC')
        for i in (1, 2):
            Path(f'sample_part{i}.txt').write_text(f'# Aktualisiert: 2026-09-11 12:0{i} CEST (Europe/Berlin)\n45.1.0.{i}\n')
        self.assertEqual(published_list_updated('sample.txt'), 'Uneinheitliche Part-Zeitstempel')

    def test_actual_report_marks_parts_only_confidence_as_available(self):
        stem = 'blacklist_confidence40_ipv4'
        for i in (1, 2):
            Path(f'{stem}_part{i}.txt').write_text(f'# Aktualisiert: 2026-09-11 12:00 UTC\n45.1.0.{i}\n')
        result = self.case.run_code('netshield_report_generator.yml', 'FILES = {')
        self.case.assert_run_ok(result)
        report = Path('reports/NETSHIELD_REPORT.md').read_text()
        row = next(row for row in report.splitlines() if f'{stem}_part1.txt' in row)
        self.assertIn('✅', row)
        self.assertIn('**2**', row)
        self.assertIn('2026-09-11 12:00 UTC', row)
        self.assertIn(f'../{stem}_part2.txt', row)

    def honey(self, count):
        ips = helpers.public_ips(count)

        def fetch(url, **kwargs):
            body = [{'remote_host': ip} for ip in ips] if url.endswith('/bad-hosts') else []
            return helpers.Response(json.dumps(body).encode())

        env = {'HONEYDB_API_ID': 'DUMMY', 'HONEYDB_API_KEY': 'DUMMY',
               'GITHUB_EVENT_NAME': 'schedule', 'FORCE_LIGHT': 'false'}
        with patch.object(nc, 'safe_urlopen', side_effect=fetch), patch('time.sleep'):
            return self.case.run_code('honigtopf.yml', 'def api_get(', env)

    def test_honey_report_describes_retained_then_successful_list(self):
        self.case.assert_run_ok(self.honey(800))
        before = Path('honigtopf_ips.txt').read_bytes()
        self.assertIsInstance(self.honey(100)[1], SystemExit)
        self.assertEqual(Path('honigtopf_ips.txt').read_bytes(), before)
        report = Path('reports/honigtopf_report.md').read_text()
        for value in ('Gesamt Honigtopf-IPs | **800**', 'Kandidaten dieses Abrufs | **100**',
                      'Entfernt | **-0**', 'Abgelehnt durch Leerungsschutz'):
            self.assertIn(value, report)
        self.case.assert_run_ok(self.honey(600))
        report = Path('reports/honigtopf_report.md').read_text()
        self.assertIn('Gesamt Honigtopf-IPs | **600**', report)
        self.assertIn('Entfernt | **-200**', report)

    def test_honey_write_failure_does_not_claim_new_publication(self):
        self.case.assert_run_ok(self.honey(800))
        paths = [Path('honigtopf_ips.txt'), Path('reports/honigtopf_report.md')]
        before = [path.read_bytes() for path in paths]
        with patch.object(nc, 'write_ip_list', side_effect=OSError('fixture disk full')):
            self.assertIsInstance(self.honey(600)[1], OSError)
        self.assertEqual([path.read_bytes() for path in paths], before)

    def git(self, directory, *args):
        return subprocess.run(['git', '-C', str(directory), *args], check=True,
                              text=True, capture_output=True).stdout.strip()

    def prepare_reset(self):
        root = self.case.path
        remote, writer, reset = (root / name for name in ('remote.git', 'writer', 'reset'))
        self.git(root, 'init', '--bare', '--initial-branch=main', str(remote))
        self.git(root, 'clone', str(remote), str(writer))
        for key, value in [('user.name', 'Local test'), ('user.email', 'test@example.invalid')]:
            self.git(writer, 'config', key, value)
        (writer / 'data.txt').write_text('initial\n')
        self.git(writer, 'add', 'data.txt')
        self.git(writer, 'commit', '-m', 'initial')
        self.git(writer, 'push', 'origin', 'main')
        self.git(root, 'clone', str(remote), str(reset))
        for key, value in [('user.name', 'Local test'), ('user.email', 'test@example.invalid')]:
            self.git(reset, 'config', key, value)
        expected = self.git(reset, 'rev-parse', 'HEAD')
        self.git(reset, 'checkout', '--orphan', 'new-root')
        self.git(reset, 'commit', '-m', 'reset')
        return remote, writer, reset, expected

    def push_reset(self, reset, expected):
        step = next(step for step in steps('history_fresh_start.yml') if step.get('name') == 'Force-Push')
        return subprocess.run(['bash', '-c', step['run']], cwd=reset,
                              env={**os.environ, 'EXPECTED_MAIN': expected}, capture_output=True, text=True, timeout=15)

    def test_history_reset_lease_is_captured_from_main_checkout(self):
        sequence = steps('history_fresh_start.yml')
        checkout = next(step for step in sequence if 'actions/checkout@' in step.get('uses', ''))
        self.assertEqual(checkout['with']['ref'], 'main')
        remote, _, reset, expected = self.prepare_reset()
        # Capture step runs before the orphan commit in production.
        self.git(reset, 'checkout', '--detach', expected)
        capture = next(step for step in sequence if step.get('id') == 'reset_base')
        output = self.case.path / 'step-output'
        subprocess.run(['bash', '-c', capture['run']], cwd=reset,
                       env={**os.environ, 'GITHUB_OUTPUT': str(output)}, check=True, capture_output=True)
        self.assertEqual(output.read_text().strip(), f'expected_main={self.git(remote, "rev-parse", "main")}')

    def test_history_reset_preserves_concurrent_remote_commit(self):
        remote, writer, reset, expected = self.prepare_reset()
        (writer / 'data.txt').write_text('newer user data\n')
        self.git(writer, 'commit', '-am', 'concurrent change')
        self.git(writer, 'push', 'origin', 'main')
        newer = self.git(writer, 'rev-parse', 'HEAD')
        result = self.push_reset(reset, expected)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git(remote, 'rev-parse', 'main'), newer)
        self.assertEqual(self.git(remote, 'show', 'main:data.txt'), 'newer user data')

    def test_history_reset_success_and_lost_response_retry(self):
        remote, _, reset, expected = self.prepare_reset()
        for _ in range(2):
            result = self.push_reset(reset, expected)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.git(remote, 'rev-list', '--count', 'main'), '1')
        self.assertEqual(self.git(remote, 'show', 'main:data.txt'), 'initial')

    def test_history_reset_rejects_missing_or_invalid_lease(self):
        for lease in ('', 'main', '0' * 39, 'x' * 40):
            with self.subTest(lease=lease):
                result = self.push_reset(self.case.path, lease)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Reset-Basis fehlt', result.stdout)


class PublicIPv4PerformanceTests(unittest.TestCase):
    def assert_parity(self, values):
        for value in values:
            self.assertEqual(nc.is_valid_public_ipv4(value), nc._is_valid_public_ipv4_reference(value), repr(value))
            if isinstance(value, str):
                cidr = value + '/32'
                self.assertEqual(nc.is_valid_public_cidr(cidr), nc._is_valid_public_cidr_reference(cidr), repr(cidr))

    def test_every_policy_boundary_and_neighbor_matches_reference(self):
        self.assertIsNotNone(nc._PUBLIC_IPV4_POLICY_INDEX)
        values = {0, (1 << 32) - 1}

        def collect(item):
            if isinstance(item, ipaddress.IPv4Network):
                for endpoint in (int(item.network_address), int(item.broadcast_address)):
                    values.update(i for i in range(max(0, endpoint - 2), min(1 << 32, endpoint + 3)))
            elif isinstance(item, (tuple, list, set, frozenset)):
                for entry in item:
                    collect(entry)

        collect(nc._RESERVED_NETS)
        for item in vars(ipaddress.IPv4Address._constants).values():
            collect(item)
        self.assert_parity(str(ipaddress.IPv4Address(i)) for i in sorted(values))

    def test_random_ipv4_and_cidr_policy_matches_reference(self):
        rng = random.Random(93825693681)
        self.assert_parity(str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(100000))

    def test_invalid_and_legacy_input_compatibility(self):
        self.assert_parity(['', '45.1.1', '45.1', '045.1.0.1', '45.1.0.1\x00', '45.1.0.1 ',
                            ' 45.1.0.1', '45.1.0.256', '45.1.0.-1', '0x2d010001', '::1',
                            '４５.1.0.1', '45.1.0.1/32', None, [], {}, -1, 2**32,
                            755040257, b'\x2d\x01\x00\x01', ipaddress.IPv4Address('45.1.0.1')])
        for cidr in ('45.1.0.1/24', '45.1.0.1/31', '45.1.0.1/0', '45.1.0.1/255.255.255.255',
                     '45.1.0.1', ('45.1.0.1', 32), None, '45.1.0.1/garbage'):
            self.assertEqual(nc.is_valid_public_cidr(cidr), nc._is_valid_public_cidr_reference(cidr), repr(cidr))

    def test_missing_policy_metadata_falls_back_to_reference(self):
        with patch.object(ipaddress.IPv4Address, '_constants', object()):
            self.assertIsNone(nc._build_public_ipv4_policy_index())
        with patch.object(nc, '_PUBLIC_IPV4_POLICY_INDEX', None):
            self.assert_parity(['45.1.0.1', '100.64.0.1', '192.0.0.9', '192.0.0.8', 'bad', None])


if __name__ == '__main__':
    unittest.main()
