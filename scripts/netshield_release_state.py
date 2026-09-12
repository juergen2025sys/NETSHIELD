"""Immutable release assets, activated only by a committed generation manifest.

An upload, download, or push failure never replaces assets of a published
generation. Restores use exact asset names and verify every part and payload.
Large payloads remain outside Git. Requires Python 3.11+ and authenticated gh.
"""
import argparse
from contextlib import closing
from datetime import datetime, timezone, timedelta
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
import uuid

from netshield_common import write_json_atomic

MANIFEST = Path('state/release_state.json')
PREFIX = 'netshield-state-'
FILES = {
    'database': Path('seen_db.sqlite3'),
    'watchlist_ledger': Path('state/watchlist_expired_history.json'),
    'active_ledger': Path('state/active_expired_history.json'),
    'queue': Path('state/aufnahme_warteliste.json'),
    'cap': Path('state/watchlist_daily_cap_state.json'),
}
LEGACY = {
    'database': ('seen-db-sqlite-backup', 'seen_db.sqlite3.gz'),
    'watchlist_ledger': ('anti-churn-ledger-backup', 'watchlist_expired_history.json.gz.part'),
    'active_ledger': ('anti-churn-ledger-backup', 'active_expired_history.json.gz.part'),
    'queue': ('aufnahme-warteliste-backup', 'aufnahme_warteliste.json.gz.part'),
}
PART_BYTES = 95 * 1024 * 1024


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def gh(*args):
    return subprocess.run(['gh', *map(str, args), '--repo', os.environ['GITHUB_REPOSITORY']],
                          check=True, text=True, capture_output=True, timeout=300).stdout


def checked_payload(path, key, minimum=100000):
    if key == 'database':
        with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as db:
            if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise ValueError('State database quick_check failed')
            count = db.execute('SELECT COUNT(*) FROM seen_db').fetchone()[0]
            if count < minimum:
                raise ValueError(f'State database too small: {count}')
        return count
    with Path(path).open(encoding='utf-8') as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError(f'Invalid state object: {key}')
    if key != 'cap' and not isinstance(data.get('entries'), dict):
        raise ValueError(f'Missing state entries: {key}')
    if key == 'cap' and data.get('letzter_lauf'):
        datetime.strptime(data['letzter_lauf'], '%Y-%m-%d')


def read_manifest(path=MANIFEST):
    manifest = json.loads(Path(path).read_text(encoding='utf-8'))
    if manifest.get('schema') != 1 or set(manifest.get('files', {})) != set(FILES):
        raise ValueError('Invalid or incomplete state manifest')
    if not re.fullmatch(PREFIX + r'[A-Za-z0-9-]+', manifest.get('tag', '')):
        raise ValueError('Invalid generation tag')
    names = set()
    for key, item in manifest['files'].items():
        if not item.get('parts') or not re.fullmatch(r'[0-9a-f]{64}', item.get('sha256', '')):
            raise ValueError(f'Missing hashes or parts: {key}')
        for index, part in enumerate(item['parts']):
            expected = f'{key}.gz.part{index:03d}'
            if part.get('name') != expected or expected in names:
                raise ValueError(f'Invalid or duplicate part: {key}')
            if not re.fullmatch(r'[0-9a-f]{64}', part.get('sha256', '')) or part.get('size', 0) <= 0:
                raise ValueError(f'Invalid part metadata: {key}')
            names.add(expected)
    return manifest


def _download(tag, name, directory, expected=None):
    target = Path(directory) / name
    for attempt in range(3):
        target.unlink(missing_ok=True)
        try:
            gh('release', 'download', tag, '--pattern', name, '--dir', directory)
            if not target.is_file():
                raise ValueError(f'Missing downloaded asset: {name}')
            if expected and (target.stat().st_size != expected['size'] or sha256(target) != expected['sha256']):
                raise ValueError(f'Asset checksum mismatch: {name}')
            return target
        except (subprocess.SubprocessError, ValueError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def _expand(parts, compressed, payload):
    # allow-nonatomic: temporary staging files are never public outputs.
    with compressed.open('wb') as stream:
        for part in parts:
            with part.open('rb') as source:
                shutil.copyfileobj(source, stream)
    # allow-nonatomic: temporary staging files are verified before os.replace.
    with gzip.open(compressed, 'rb') as source, payload.open('wb') as target:
        shutil.copyfileobj(source, target)


def _install(staged, keys):
    # All requested files are checked BEFORE replacing any local work file.
    # A killed restore fails its workflow step; the build cannot start.
    for key in keys:
        destination = FILES[key]
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged / key, destination)
        if key not in ('database', 'cap'):
            # Existing consumers read multipart gzip, others read plain JSON.
            for old in destination.parent.glob(destination.name + '.gz.part*'):
                old.unlink()
            os.replace(staged / (key + '.gz'), Path(str(destination) + '.gz.part000'))


def restore(keys=None):
    keys = list(keys or FILES)
    Path('state').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.state-restore-', dir='state') as temp:
        staged = Path(temp)
        if MANIFEST.exists():
            manifest = read_manifest()
            for key in keys:
                item = manifest['files'][key]
                parts = [_download(manifest['tag'], part['name'], staged, part) for part in item['parts']]
                payload = staged / key
                _expand(parts, staged / (key + '.gz'), payload)
                if sha256(payload) != item['sha256'] or payload.stat().st_size != item['size']:
                    raise ValueError(f'Payload checksum mismatch: {key}')
                checked_payload(payload, key)
        else:
            # One-time migration: never convert an API failure into an empty
            # ledger or mix a latest cache with unrelated release backups.
            bootstrap = Path('state/seen_db_erstlauf_ok').is_file()
            for key in keys:
                payload = staged / key
                if key == 'cap':
                    if FILES[key].exists():
                        shutil.copyfile(FILES[key], payload)
                    elif bootstrap:
                        # allow-nonatomic: temporary migration payload.
                        payload.write_text('{}', encoding='utf-8')
                    else:
                        raise ValueError('Missing committed daily cap state for migration')
                elif bootstrap:
                    if key == 'database':
                        # The explicit fresh-start marker delegates DB creation
                        # to Combined. It is never used when a manifest exists.
                        continue
                    # allow-nonatomic: temporary migration payload.
                    payload.write_text('{"entries":{}}', encoding='utf-8')
                    with payload.open('rb') as source, gzip.open(staged / (key + '.gz'), 'wb') as target:
                        shutil.copyfileobj(source, target)
                else:
                    tag, prefix = LEGACY[key]
                    listing = json.loads(gh('release', 'view', tag, '--json', 'assets'))
                    names = sorted(a['name'] for a in listing['assets'] if
                                   a['name'] == prefix or re.fullmatch(re.escape(prefix) + r'\d{3}', a['name']))
                    if not names or (key != 'database' and names != [f'{prefix}{i:03d}' for i in range(len(names))]):
                        raise ValueError(f'Missing or incomplete legacy assets: {key}')
                    parts = [_download(tag, name, staged) for name in names]
                    _expand(parts, staged / (key + '.gz'), payload)
                checked_payload(payload, key)
            if 'database' in keys and not bootstrap:
                meta = json.loads(Path('state/seen_db_meta.json').read_text(encoding='utf-8'))
                if checked_payload(staged / 'database', 'database') != meta.get('total_ips'):
                    raise ValueError('Legacy DB and committed metadata differ; recover a matching backup before migration')
            if bootstrap and 'database' in keys:
                keys.remove('database')
        _install(staged, keys)
        if 'database' in keys:
            Path('seen_db.json').unlink(missing_ok=True)
    print('Restored one verified state generation: ' + ', '.join(keys))


def promote_pending():
    """Make today's updated ledgers visible to the in-job Confidence build."""
    for key, path in FILES.items():
        if key in ('database', 'cap'):
            continue
        pending = path.with_name(path.stem + '_upload.json')
        if pending.exists():
            checked_payload(pending, key)
            # Retain the pending source until the publication succeeds.
            with tempfile.TemporaryDirectory(prefix='.ledger-stage-', dir='state') as temp:
                staged = Path(temp)
                shutil.copyfile(pending, staged / key)
                with pending.open('rb') as source, gzip.open(staged / (key + '.gz'), 'wb') as target:
                    shutil.copyfileobj(source, target)
                _install(staged, [key])


def prepare(outputs, inputs, *, part_bytes=PART_BYTES):
    previous = read_manifest()['tag'] if MANIFEST.exists() else None
    manifest = {'schema': 1, 'tag': PREFIX + uuid.uuid4().hex,
                'previous_tag': previous, 'created_utc': datetime.now(timezone.utc).isoformat(),
                'files': {}, 'outputs': outputs, 'inputs': inputs}
    promote_pending()
    Path('state').mkdir(exist_ok=True)
    # Staging remains available for diagnostics when upload fails.
    staging = Path('state/.release-upload') / manifest['tag']
    staging.mkdir(parents=True)
    for key, source in FILES.items():
        checked_payload(source, key)
        compressed = staging / (key + '.gz')
        with source.open('rb') as stream, gzip.open(compressed, 'wb', compresslevel=6) as target:
            shutil.copyfileobj(stream, target)
        parts = []
        with compressed.open('rb') as stream:
            while block := stream.read(part_bytes):
                part = staging / f'{key}.gz.part{len(parts):03d}'
                # allow-nonatomic: immutable temporary part, verified before upload.
                part.write_bytes(block)
                parts.append({'name': part.name, 'size': len(block), 'sha256': sha256(part)})
        compressed.unlink()
        manifest['files'][key] = {'sha256': sha256(source), 'size': source.stat().st_size, 'parts': parts}
    gh('release', 'create', manifest['tag'], '--title', 'NETSHIELD state generation',
       '--prerelease', '--latest=false', '--target', os.environ.get('GITHUB_SHA', 'main'),
       '--notes', 'Prepared state assets. Authoritative only when referenced by state/release_state.json on the default branch.')
    with tempfile.TemporaryDirectory(prefix='.upload-verify-', dir='state') as temp:
        for item in manifest['files'].values():
            for part in item['parts']:
                # Each name is immutable. If a response is lost after a
                # successful upload, verify the existing asset before retrying.
                for attempt in range(3):
                    try:
                        gh('release', 'upload', manifest['tag'], staging / part['name'])
                    except subprocess.SubprocessError:
                        pass
                    try:
                        _download(manifest['tag'], part['name'], temp, part)
                        break
                    except (subprocess.SubprocessError, ValueError):
                        if attempt == 2:
                            raise
                print(f"Verified release asset: {part['name']}")
    # This pointer is still local; a single successful Git push activates it
    # together with all list outputs. No cache is allowed to supersede it.
    write_json_atomic(MANIFEST, manifest, indent=2)
    read_manifest()
    return manifest


def cleanup():
    manifest = read_manifest()
    keep = {manifest['tag'], manifest.get('previous_tag')}
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    releases = json.loads(gh('release', 'list', '--limit', '200', '--json', 'tagName,createdAt'))
    for release in releases:
        tag = release['tagName']
        created = datetime.fromisoformat(release['createdAt'].replace('Z', '+00:00'))
        if tag.startswith(PREFIX) and tag not in keep and created < cutoff:
            gh('release', 'delete', tag, '--yes', '--cleanup-tag')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['restore', 'promote', 'prepare', 'cleanup'])
    parser.add_argument('--only', nargs='+', choices=list(FILES))
    args = parser.parse_args()
    if args.operation == 'restore':
        restore(args.only)
    elif args.operation == 'promote':
        promote_pending()
    elif args.operation == 'prepare':
        from netshield_generation import generation_files
        outputs = {str(path): sha256(path) for path in generation_files()}
        prepare(outputs=outputs, inputs={'commit': os.environ['NETSHIELD_BASE_COMMIT'],
                                        'epoch': int(os.environ['NETSHIELD_GENERATION_EPOCH'])})
    else:
        cleanup()


if __name__ == '__main__':
    main()
