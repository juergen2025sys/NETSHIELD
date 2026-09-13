"""Fault-injection coverage for Combined's three state-recovery fixes."""
import copy
import fnmatch
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from tests import test_combined_fixes_20260912 as t
import netshield_history as history


class FakeGitHub:
    """Local immutable asset store, including post-commit connection failures."""
    def __init__(self):
        self.tags = {}
        self.assets = {}
        self.next_id = 1
        self.calls = []
        self.mutations = 0
        self.fail_at = None
        self.fail_after = False

    def release(self, tag, create=False):
        self.calls.append(('release', tag))
        if tag not in self.tags:
            if not create:
                return None
            self.tags[tag] = {'id': len(self.tags) + 1, 'body': history.BOOTSTRAP}
        return dict(self.tags[tag], tag=tag, assets=[copy.deepcopy(a['meta'])
                    for a in self.assets.values() if a['tag'] == tag])

    def add(self, tag, name, data):
        self.tags.setdefault(tag, {'id': len(self.tags) + 1, 'body': ''})
        if any(a['tag'] == tag and a['meta']['name'] == name for a in self.assets.values()):
            raise history.HistoryError('Duplicate asset name')
        asset_id = self.next_id
        self.next_id += 1
        meta = dict(id=asset_id, name=name, size=len(data), state='uploaded',
                    created_at='2026-09-13T00:00:00Z', digest='sha256:' + hashlib.sha256(data).hexdigest())
        self.assets[asset_id] = dict(tag=tag, meta=meta, data=data)
        return copy.deepcopy(meta)

    def tick(self, after=False):
        if not after:
            self.mutations += 1
        if self.mutations == self.fail_at and after == self.fail_after:
            raise OSError('Injected connection interruption')

    def upload(self, release, name, path):
        self.calls.append(('upload', name))
        self.tick()
        result = self.add(release['tag'], name, Path(path).read_bytes())
        self.tick(after=True)
        return result

    def rename(self, asset_id, name):
        self.calls.append(('rename', asset_id, name))
        self.tick()
        item = self.assets[asset_id]
        if any(a['tag'] == item['tag'] and a['meta']['name'] == name and i != asset_id
               for i, a in self.assets.items()):
            raise history.HistoryError('Duplicate asset name')
        item['meta']['name'] = name
        self.tick(after=True)

    def delete(self, asset_id):
        self.calls.append(('delete', asset_id))
        self.tick()
        del self.assets[asset_id]
        self.tick(after=True)

    def download(self, asset_id, path):
        self.calls.append(('download', asset_id))
        Path(path).write_bytes(self.assets[asset_id]['data'])


TAG = 'anti-churn-ledger-backup'
WATCH = 'watchlist_expired_history'
ACTIVE = 'active_expired_history'


def compressed(entries):
    return gzip.compress(json.dumps({'entries': entries}).encode(), mtime=0)


def seed(client, tag=TAG):
    data = {prefix: compressed({'45.1.0.1': {'first': '2026-08-01', 'last': '2026-01-01',
                                          'eingefroren_am': '2026-09-12'}})
            for prefix in history.GROUPS[tag]}
    for prefix, payload in data.items():
        client.add(tag, prefix + '.json.gz.part000', payload)
    return data


def assert_restore_scenarios(case):
    with tempfile.TemporaryDirectory() as tmp:
        client = FakeGitHub()
        history.restore(client, TAG, tmp)  # Genuine first run.
        seed(client)
        history.restore(client, TAG, tmp)
        case.assertTrue((Path(tmp)/(WATCH + '.json.gz.part000')).exists())
        watch_id = next(i for i, a in client.assets.items() if a['meta']['name'].startswith(WATCH))
        del client.assets[watch_id]
        with case.assertRaises(history.HistoryError):
            history.restore(client, TAG, tmp)
        with patch.object(client, 'release', side_effect=OSError('API unavailable')):
            with case.assertRaises(OSError):
                history.restore(client, TAG, tmp)


class HistorySafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def parts(self, data, split=False):
        files = []
        for prefix, payload in data.items():
            chunks = [payload[:len(payload)//2], payload[len(payload)//2:]] if split else [payload]
            for i, chunk in enumerate(chunks):
                path = self.directory/f'{prefix}.json.gz.part{i:03d}'
                path.write_bytes(chunk)
                files.append(path)
        return files

    def restored(self, client, tag=TAG):
        destination = self.directory/'restored'
        history.restore(client, tag, destination)
        return {prefix: b''.join(p.read_bytes() for p in sorted(destination.glob(prefix + '.json.gz.part*')))
                for prefix in history.GROUPS[tag]}

    def test_every_upload_and_rename_interruption_preserves_complete_history(self):
        newer = {prefix: compressed({'45.1.0.2': 'new'}) for prefix in (WATCH, ACTIVE)}
        for after in (False, True):
            for failure in range(1, 14):
                with self.subTest(failure=failure, after=after):
                    client = FakeGitHub()
                    old = seed(client)
                    client.fail_at, client.fail_after = failure, after
                    try:
                        history.publish(client, TAG, self.parts(newer))
                    except OSError:
                        pass
                    client.fail_at = None
                    restored = self.restored(client)
                    self.assertIn(restored, (old, newer))
                    # Neither a mixed generation nor an empty history is accepted.
                    self.assertTrue(all(restored.values()))

    def test_partial_data_upload_never_changes_original_assets(self):
        client = FakeGitHub()
        old = seed(client)
        original = copy.deepcopy(client.assets)
        client.fail_at = 2
        with self.assertRaises(OSError):
            history.publish(client, TAG, self.parts({k: compressed({'new': k}) for k in old}))
        for asset_id, value in original.items():
            self.assertEqual(client.assets[asset_id], value)

    def test_fewer_parts_leave_no_stale_canonical_tail(self):
        client = FakeGitHub()
        seed(client)
        old = {prefix: compressed({'old': prefix}) for prefix in (WATCH, ACTIVE)}
        history.publish(client, TAG, self.parts(old, split=True))
        new = {WATCH: compressed({'new': 'watchlist'})}
        history.publish(client, TAG, self.parts(new))
        self.assertEqual(self.restored(client), old | new)
        names = [a['meta']['name'] for a in client.assets.values()]
        self.assertNotIn(WATCH + '.json.gz.part001', names)

    def test_two_generations_retained_and_bounded(self):
        client = FakeGitHub()
        seed(client)
        for i in range(6):
            data = {prefix: compressed({'generation': i}) for prefix in (WATCH, ACTIVE)}
            history.publish(client, TAG, self.parts(data))
        self.assertEqual(len(client.assets), 6)  # Four parts and two manifests.
        self.assertEqual(self.restored(client), data)
        legacy_matches = [a['meta']['name'] for a in client.assets.values()
                          if fnmatch.fnmatchcase(a['meta']['name'], '*_expired_history.json.gz.part*')]
        self.assertEqual(sorted(legacy_matches), sorted(prefix + '.json.gz.part000' for prefix in (WATCH, ACTIVE)))

    def test_manifest_missing_asset_or_bad_digest_aborts_restore(self):
        for corrupt in ('missing', 'bytes', 'manifest'):
            with self.subTest(corrupt=corrupt):
                client = FakeGitHub()
                data = seed(client)
                history.publish(client, TAG, self.parts(data))
                manifest = history.manifest_assets(client.release(TAG))[0]
                metadata = json.loads(client.assets[manifest['id']]['data'])
                asset_id = metadata['entries'][WATCH][0]['id']
                if corrupt == 'missing':
                    del client.assets[asset_id]
                elif corrupt == 'bytes':
                    client.assets[asset_id]['data'] = b'x' * client.assets[asset_id]['meta']['size']
                else:
                    client.assets[manifest['id']]['data'] = b'{}'
                with self.assertRaises(history.HistoryError):
                    self.restored(client)

    def test_existing_release_missing_one_ledger_is_not_first_run(self):
        assert_restore_scenarios(self)

    def test_legacy_assets_with_null_digest_restore(self):
        client = FakeGitHub()
        old = seed(client)
        for asset in client.assets.values():
            asset['meta']['digest'] = None
        self.assertEqual(self.restored(client), old)

    def test_first_publication_can_retry_after_upload_failure(self):
        for failure in (1, 2):
            client = FakeGitHub()
            client.fail_at = failure
            files = self.parts({WATCH: compressed({'first': 'watchlist'})})
            with self.assertRaises(OSError):
                history.publish(client, TAG, files)
            client.fail_at = None
            history.publish(client, TAG, files)
            restored = self.restored(client)
            self.assertTrue(restored[WATCH])
            self.assertEqual(restored[ACTIVE], b'')

    def test_waitlist_uses_the_same_safe_commit_protocol(self):
        client = FakeGitHub()
        tag = 'aufnahme-warteliste-backup'
        old = seed(client, tag)
        client.fail_at = 1
        with self.assertRaises(OSError):
            history.publish(client, tag, self.parts({'aufnahme_warteliste': compressed({'new': 'proof'})}))
        client.fail_at = None
        self.assertEqual(self.restored(client, tag), old)

    def test_restore_repairs_interrupted_public_filenames_without_new_upload(self):
        client = FakeGitHub()
        seed(client)
        data = {prefix: compressed({'new': prefix}) for prefix in (WATCH, ACTIVE)}
        client.fail_at = 5  # After commit, during canonical-name updates.
        with self.assertRaises(OSError):
            history.publish(client, TAG, self.parts(data))
        client.fail_at = None
        self.assertEqual(self.restored(client), data)
        names = {a['meta']['name'] for a in client.assets.values()}
        for prefix in (WATCH, ACTIVE):
            self.assertIn(prefix + '.json.gz.part000', names)


class CombinedRecoveryTests(unittest.TestCase):
    setUp = t.CombinedFixTests.setUp
    db = t.CombinedFixTests.db
    entry = staticmethod(t.CombinedFixTests.entry)
    ingest = t.CombinedFixTests.ingest
    cleanup = t.CombinedFixTests.cleanup
    def test_confirmed_missing_ip_returns_without_new_hit_and_without_fresh_date(self):
        db = self.db()
        ip = '45.1.0.1'
        waiting = {ip: {'feed_a': '2026-09-10', 'feed_b': '2026-09-11'}}
        result = self.ingest(db, {}, day='2026-09-13', waiting=waiting)
        self.cleanup(db, waiting, day='2026-09-13')
        self.assertIn(ip, db)
        self.assertEqual(db[ip]['first'], '2026-09-11')
        self.assertEqual(db[ip]['last'], '2000-01-01')
        self.assertEqual(db[ip]['today_count'], 0)
        self.assertFalse(db[ip]['today_hq'])
        self.assertIn(ip, waiting)
        self.assertEqual(result['_aufn_recovered'], 1)
        db.close()
        db = self.db()
        self.ingest(db, {}, day='2026-09-14', waiting=waiting)
        self.assertNotIn(ip, waiting)

    def test_recovered_confirmation_obeys_original_expiry_and_frozen_anchor(self):
        for frozen in (False, True):
            with self.subTest(frozen=frozen):
                db = self.db()
                ip = '45.1.0.1'
                waiting = {ip: {'feed_a': '2026-09-10', 'feed_b': '2026-09-11'}}
                ledger = {ip: {'first': '2026-07-01', 'eingefroren_am': '2026-09-12'}} if frozen else {}
                day = '2026-09-13' if frozen else '2026-10-13'
                self.ingest(db, {}, day=day, waiting=waiting, ledger=ledger)
                self.cleanup(db, waiting, day=day, ledger=ledger, cap_used=False)
                self.assertNotIn(ip, db)
                self.assertNotIn(ip, waiting)
                db.close()

    def test_no_single_feed_proof_is_promoted(self):
        db = self.db()
        waiting = {'45.1.0.1': {'feed_a': '2026-09-12'}}
        self.ingest(db, {}, waiting=waiting)
        self.assertEqual(len(db), 0)

    def test_upload_failure_keeps_frozen_reentry_rule_effective(self):
        client = FakeGitHub()
        seed(client)
        path = self.directory/(WATCH + '.json.gz.part000')
        path.write_bytes(compressed({'new': 'entry'}))
        client.fail_at = 1
        with self.assertRaises(OSError):
            history.publish(client, TAG, [path])
        client.fail_at = None
        history.restore(client, TAG, 'state')
        loaded = t.CombinedFixTests.load_state(self)
        ledger = loaded['_wl_expired_first']
        db = self.db()
        ip = '45.1.0.1'
        self.ingest(db, {ip: {'feed_a', 'feed_b'}}, ledger=ledger, day='2026-09-13')
        self.assertEqual(db[ip]['first'], '2026-08-01')
        self.cleanup(db, {}, ledger=ledger, day='2026-09-13', cap_used=False)
        self.assertNotIn(ip, db)

    def test_newer_checkout_wins_over_stale_cache(self):
        cap = Path('state/watchlist_daily_cap_state.json')
        saved = self.directory/'netshield-watchlist-cap-from-git.json'
        for git_day, cache_day, expected in [
            ('2026-09-13', '2026-09-12', True),
            ('2026-09-12', '2026-09-13', True),
            ('2026-09-12', '2026-09-12', False),
        ]:
            with self.subTest(git_day=git_day, cache_day=cache_day):
                saved.write_text(json.dumps({'letzter_lauf': git_day}))
                cap.write_text(json.dumps({'letzter_lauf': cache_day}))
                env = dict(now=datetime(2026, 9, 13, tzinfo=timezone.utc), os=os, json=json,
                           write_json_atomic=t.nc.write_json_atomic)
                with patch.dict(os.environ, RUNNER_TEMP=str(self.directory)):
                    exec(t.workflow_section('WATCHLIST_DAILY_CAP = 2000', '_wl_kandidaten = []'), env)
                self.assertEqual(env['_wl_cap_heute_bereits_gelaufen'], expected)
                self.assertEqual(json.loads(cap.read_text())['letzter_lauf'], max(git_day, cache_day))

    def test_saved_git_cap_survives_missing_or_corrupt_cache(self):
        cap = Path('state/watchlist_daily_cap_state.json')
        saved = self.directory/'netshield-watchlist-cap-from-git.json'
        saved.write_text('{"letzter_lauf":"2026-09-13"}')
        for content in (None, '{broken'):
            if content is None:
                cap.unlink(missing_ok=True)
            else:
                cap.write_text(content)
            env = dict(now=datetime(2026, 9, 13, tzinfo=timezone.utc), os=os, json=json,
                       write_json_atomic=t.nc.write_json_atomic)
            with patch.dict(os.environ, RUNNER_TEMP=str(self.directory)):
                exec(t.workflow_section('WATCHLIST_DAILY_CAP = 2000', '_wl_kandidaten = []'), env)
            self.assertTrue(env['_wl_cap_heute_bereits_gelaufen'])


class GitHubTransportTests(unittest.TestCase):
    def test_stream_upload_download_and_metadata_over_http(self):
        received = []
        payload = b'backup-data-' * 100000

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def handle_request(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                received.append((self.command, self.path, dict(self.headers), body))
                if self.command == 'GET':
                    data = payload
                elif self.command == 'DELETE':
                    data = b''
                else:
                    data = json.dumps({'id': 7, 'size': len(body), 'state': 'uploaded'}).encode()
                self.send_response(200 if data else 204)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PATCH = do_DELETE = handle_request

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        origin = f'http://127.0.0.1:{server.server_port}'
        client = history.GitHub('owner/repo', 'local-test-token')
        client.base = origin + '/repos/owner/repo'
        opener = client.opener

        class LocalUpload:
            def open(self, request, timeout):
                if request.full_url.startswith('https://uploads.github.com/'):
                    request.full_url = origin + '/upload?' + history.urllib.parse.urlsplit(request.full_url).query
                return opener.open(request, timeout=timeout)

        client.opener = LocalUpload()
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp)/'source', Path(tmp)/'target'
            source.write_bytes(payload)
            result = client.upload({'upload_url': 'https://uploads.github.com/assets{?name,label}'}, 'part 000', source)
            self.assertEqual(result['size'], len(payload))
            client.download(7, target)
            self.assertEqual(target.read_bytes(), payload)
            client.rename(7, 'part000')
            client.delete(7)
        self.assertEqual([r[0] for r in received], ['POST', 'GET', 'PATCH', 'DELETE'])
        self.assertEqual(received[0][1], '/upload?name=part%20000')
        self.assertEqual(received[0][3], payload)
        self.assertEqual(received[0][2]['Authorization'], 'Bearer local-test-token')
        self.assertEqual(json.loads(received[2][3]), {'name': 'part000'})

    def test_redirect_does_not_forward_token_to_asset_host(self):
        request = history.urllib.request.Request('https://api.github.com/asset',
                                                headers={'Authorization': 'Bearer local-test-token'})
        redirect = history.SafeRedirect().redirect_request(
            request, None, 302, 'Found', {}, 'https://release-assets.githubusercontent.com/data')
        self.assertFalse(redirect.has_header('Authorization'))


if __name__ == '__main__':
    unittest.main()
