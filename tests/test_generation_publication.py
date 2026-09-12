"""Regression tests for release failure, workflow wiring and publication races."""
from contextlib import closing
import gzip
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import netshield_release_state as state
import netshield_generation as generation
from check_pipeline_consistency import check


class StrictLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f'Duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


class WorkflowPublicationTests(unittest.TestCase):
    def test_all_workflows_reject_duplicate_yaml_keys(self):
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            with self.subTest(workflow=path.name):
                yaml.load(path.read_text(encoding='utf-8'), Loader=StrictLoader)

    def test_single_writer_and_complete_order(self):
        doc = yaml.load((ROOT / '.github/workflows/update_combined_blacklist.yml').read_text(encoding='utf-8'), Loader=StrictLoader)
        steps = doc['jobs']['update']['steps']
        ids = {s['id']: i for i, s in enumerate(steps) if 'id' in s}
        order = ['restore_generation', 'build_combined', 'shrink_guard', 'current_state', 'build_confidence', 'validate_generation', 'prepare_generation', 'commit']
        self.assertEqual([ids[k] for k in order], sorted(ids[k] for k in order))
        self.assertIn('netshield_release_state.py promote', steps[ids['current_state']]['run'])
        self.assertIn('SELECT COUNT(*) FROM seen_db', steps[ids['current_state']]['run'])
        for index, step in enumerate(steps):
            if '/save@' in step.get('uses', ''):
                self.assertGreater(index, ids['commit'])
                self.assertIn("steps.commit.outcome == 'success'", step['if'])
        text = '\n'.join(s.get('run', '') for s in steps)
        self.assertNotIn('gh release upload', text)
        self.assertIn('NETSHIELD_GENERATION_EPOCH=', text)
        confidence = (ROOT / '.github/workflows/update_confidence_blacklist.yml').read_text(encoding='utf-8')
        self.assertNotIn('git push', confidence)
        self.assertNotIn('schedule:', confidence)
        self.assertIn('gh workflow run update_combined_blacklist.yml', confidence)


class ReleaseTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = Path.cwd()
        os.chdir(self.temp.name)
        Path('state').mkdir()
        self.remote = Path('mock-releases')
        self.remote.mkdir()
        self.calls = []
        with closing(sqlite3.connect('seen_db.sqlite3')) as db:
            db.execute('CREATE TABLE seen_db(ip TEXT PRIMARY KEY)')
            db.executemany('INSERT INTO seen_db VALUES (?)', ((str(i),) for i in range(100000)))
            db.commit()
        for key, path in state.FILES.items():
            if key != 'database':
                path.write_text(json.dumps({} if key == 'cap' else {'entries': {'old': {'last': '2026-09-11'}}}))
        self.gh_patch = patch.object(state, 'gh', side_effect=self.fake_gh)
        self.gh_patch.start()
        self.sleep_patch = patch.object(state.time, 'sleep')
        self.sleep_patch.start()

    def tearDown(self):
        self.sleep_patch.stop()
        self.gh_patch.stop()
        os.chdir(self.previous)
        self.temp.cleanup()

    def fake_gh(self, *args):
        args = list(map(str, args))
        self.calls.append(args)
        operation, tag = args[1:3]
        folder = self.remote / tag
        if operation == 'create':
            folder.mkdir()
        elif operation == 'upload':
            source = Path(args[3])
            if (folder / source.name).exists():
                raise subprocess.CalledProcessError(1, args)
            shutil.copyfile(source, folder / source.name)
        elif operation == 'download':
            name = args[args.index('--pattern') + 1]
            dest = Path(args[args.index('--dir') + 1]) / name
            if not (folder / name).exists():
                raise subprocess.CalledProcessError(1, args)
            shutil.copyfile(folder / name, dest)
        else:
            raise AssertionError(args)
        return ''

    def test_roundtrip_restores_exact_generation_and_discards_stale_json(self):
        manifest = state.prepare({}, {}, part_bytes=65536)
        expected = state.sha256(Path('seen_db.sqlite3'))
        Path('seen_db.sqlite3').write_bytes(b'bad cache')
        Path('seen_db.json').write_text('{"stale": true}')
        state.restore()
        self.assertEqual(state.sha256(Path('seen_db.sqlite3')), expected)
        self.assertFalse(Path('seen_db.json').exists())
        self.assertEqual(state.read_manifest()['tag'], manifest['tag'])
        self.assertFalse(any('--clobber' in call for call in self.calls))

    def test_failed_upload_preserves_previous_pointer_and_pending_ledger(self):
        state.prepare({}, {}, part_bytes=65536)
        previous = state.MANIFEST.read_bytes()
        pending = Path('state/watchlist_expired_history_upload.json')
        pending.write_text('{"entries":{"new":{"last":"2026-09-12"}}}')
        def failure(*args):
            if args[1] in ('upload', 'download'):
                raise subprocess.CalledProcessError(1, args)
            return self.fake_gh(*args)
        with patch.object(state, 'gh', side_effect=failure), self.assertRaises(subprocess.CalledProcessError):
            state.prepare({}, {}, part_bytes=65536)
        self.assertEqual(state.MANIFEST.read_bytes(), previous)
        self.assertTrue(pending.is_file())

    def test_corrupt_remote_part_changes_no_local_state(self):
        manifest = state.prepare({}, {}, part_bytes=65536)
        item = manifest['files']['active_ledger']['parts'][0]
        (self.remote / manifest['tag'] / item['name']).write_bytes(b'corrupt')
        before = {key: path.read_bytes() for key, path in state.FILES.items()}
        with self.assertRaises(ValueError):
            state.restore()
        self.assertEqual({key: path.read_bytes() for key, path in state.FILES.items()}, before)

    def test_missing_remote_part_never_falls_back_to_cache(self):
        manifest = state.prepare({}, {}, part_bytes=65536)
        part = manifest['files']['database']['parts'][0]['name']
        (self.remote / manifest['tag'] / part).unlink()
        Path('seen_db.sqlite3').write_bytes(b'unrelated cache')
        with self.assertRaises(subprocess.CalledProcessError):
            state.restore()
        self.assertEqual(Path('seen_db.sqlite3').read_bytes(), b'unrelated cache')

    def test_pending_ledger_is_visible_to_both_json_and_multipart_consumers(self):
        Path('state/watchlist_expired_history_upload.json').write_text('{"entries":{"fresh":{}}}')
        state.promote_pending()
        path = state.FILES['watchlist_ledger']
        self.assertEqual(json.loads(path.read_text())['entries'], {'fresh': {}})
        with gzip.open(str(path) + '.gz.part000', 'rt') as stream:
            self.assertEqual(json.load(stream)['entries'], {'fresh': {}})

    def test_cleanup_retains_current_previous_and_unrelated_releases(self):
        first = state.prepare({}, {}, part_bytes=65536)
        current = state.prepare({}, {}, part_bytes=65536)
        old = state.PREFIX + 'orphan'
        records = [{'tagName': tag, 'createdAt': '2000-01-01T00:00:00Z'}
                   for tag in (first['tag'], current['tag'], old, 'seen-db-sqlite-backup')]
        with patch.object(state, 'gh', return_value=json.dumps(records)) as fake:
            state.cleanup()
        deletions = [call.args[2] for call in fake.call_args_list if call.args[1] == 'delete']
        self.assertEqual(deletions, [old])


class PipelineRelationshipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name, values in {
            'combined_threat_blacklist_ipv4_part1.txt': '45.1.0.1\n',
            'combined_threat_blacklist_ipv4_part2.txt': '45.1.0.2\n',
            'blacklist_confidence40_ipv4_part1.txt': '45.1.0.1\n',
            'blacklist_confidence40_ipv4_part2.txt': '45.1.0.2\n',
            'active_blacklist_ipv4.txt': '45.1.0.1\n',
            'watchlist_confidence25to39_ipv4.txt': '# valid empty watchlist\n',
        }.items():
            (self.root / name).write_text(values)

    def tearDown(self):
        self.temp.cleanup()

    def test_empty_watchlist_can_be_a_valid_generation(self):
        self.assertEqual(check(self.root)['watch'], 0)

    def test_confidence_outside_combined_is_rejected(self):
        (self.root / 'blacklist_confidence40_ipv4_part2.txt').write_text('45.2.0.1\n')
        with self.assertRaises(ValueError):
            check(self.root)

    def test_extra_parts_are_rejected(self):
        (self.root / 'combined_threat_blacklist_ipv4_part3.txt').write_text('45.2.0.1\n')
        with self.assertRaises(ValueError):
            check(self.root)

    def test_overlap_is_rejected(self):
        (self.root / 'watchlist_confidence25to39_ipv4.txt').write_text('45.1.0.1\n')
        with self.assertRaises(ValueError):
            check(self.root)


@unittest.skipUnless(shutil.which('bash') and shutil.which('git'), 'Git and Bash required')
class GitPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.remote = self.root / 'remote.git'
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '--bare', str(self.remote), cwd=self.root)
        self.git('init', '-b', 'main')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.repo / '.gitignore').write_text('__pycache__/\n')
        (self.repo / 'input.json').write_text('{"version":1}')
        (self.repo / 'README.md').write_text('Initial documentation\n')
        (self.repo / 'scripts').mkdir()
        for name in ('publish_generation.sh', 'netshield_generation.py', 'netshield_release_state.py', 'netshield_common.py'):
            shutil.copyfile(ROOT / 'scripts' / name, self.repo / 'scripts' / name)
        self.git('add', '.')
        self.git('commit', '-m', 'base')
        self.git('remote', 'add', 'origin', str(self.remote))
        self.git('push', '-u', 'origin', 'main')
        self.base = self.git('rev-parse', 'HEAD').stdout.strip()
        self.epoch = 1789190000
        (self.repo / 'state').mkdir()
        (self.repo / 'reports').mkdir()
        files = {'active_blacklist_ipv4.txt': '45.1.0.1\n',
                 'watchlist_confidence25to39_ipv4.txt': '# empty\n',
                 'state/seen_db_meta.json': '{}', 'state/watchlist_daily_cap_state.json': '{}',
                 'state/confidence_generation.json': json.dumps({'generated_at_epoch': self.epoch}),
                 'reputation_blacklist.txt': '# empty\n',
                 'reports/combined_threat_blacklist_report.md': 'Complete generation\n'}
        for stem in ('combined_threat_blacklist_ipv4', 'blacklist_confidence40_ipv4'):
            for part in (1, 2):
                files[f'{stem}_part{part}.txt'] = f'45.1.0.{part}\n'
        for name, body in files.items():
            (self.repo / name).write_text(body, encoding='utf-8')
        outputs = {str(Path(name)): state.sha256(self.repo / name) for name in files
                   if name not in ('reputation_blacklist.txt', 'reports/combined_threat_blacklist_report.md')}
        manifest = {'schema': 1, 'tag': state.PREFIX + 'test', 'inputs': {'epoch': self.epoch},
                    'outputs': outputs, 'files': {key: {'sha256': 'a' * 64, 'size': 1,
                     'parts': [{'name': key + '.gz.part000', 'sha256': 'a' * 64, 'size': 1}]}
                     for key in state.FILES}}
        (self.repo / state.MANIFEST).write_text(json.dumps(manifest))

    def tearDown(self):
        # tempfile handles Git's read-only object files in this known temp root.
        self.temp.cleanup()

    def git(self, *args, cwd=None):
        return subprocess.run(['git', *args], cwd=cwd or self.repo, capture_output=True,
                              text=True, check=True)

    def publish(self):
        env = {**os.environ, 'NETSHIELD_BASE_COMMIT': self.base, 'GITHUB_REF_NAME': 'main',
               'NETSHIELD_TEST_PY': Path(sys.executable).as_posix()}
        return subprocess.run(['bash', '-c', 'python3() { "$NETSHIELD_TEST_PY" "$@"; }; export -f python3; bash scripts/publish_generation.sh'],
                              cwd=self.repo, env=env, capture_output=True, text=True)

    def concurrent_change(self, file, body):
        other = self.root / 'other'
        self.git('clone', '-b', 'main', str(self.remote), str(other), cwd=self.root)
        self.git('config', 'user.name', 'Other', cwd=other)
        self.git('config', 'user.email', 'other@example.invalid', cwd=other)
        (other / file).write_text(body)
        self.git('add', file, cwd=other)
        self.git('commit', '-m', 'concurrent change', cwd=other)
        self.git('push', cwd=other)
        return self.git('rev-parse', 'HEAD', cwd=other).stdout.strip()

    def test_all_lists_and_manifest_reach_remote_in_one_commit(self):
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name in ('blacklist_confidence40_ipv4_part1.txt', 'blacklist_confidence40_ipv4_part2.txt',
                     'watchlist_confidence25to39_ipv4.txt', 'state/release_state.json'):
            actual = self.git('--git-dir', str(self.remote), 'show', 'main:' + name).stdout
            self.assertEqual(actual, (self.repo / name).read_text())

    def test_changed_inputs_reject_publication_and_preserve_remote(self):
        before = self.concurrent_change('input.json', '{"version":2}')
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Build inputs changed', result.stdout)
        after = self.git('--git-dir', str(self.remote), 'rev-parse', 'main').stdout.strip()
        self.assertEqual(after, before)

    def test_unrelated_documentation_can_advance_without_mixing_generation(self):
        self.concurrent_change('README.md', 'Changed documentation\n')
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        actual = self.git('--git-dir', str(self.remote), 'show', 'main:README.md').stdout
        self.assertEqual(actual, 'Changed documentation\n')

    def test_modified_output_after_preparation_cannot_be_published(self):
        (self.repo / 'watchlist_confidence25to39_ipv4.txt').write_text('45.2.0.1\n')
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('hashes do not match', result.stderr)
        self.assertEqual(self.git('--git-dir', str(self.remote), 'rev-parse', 'main').stdout.strip(), self.base)
