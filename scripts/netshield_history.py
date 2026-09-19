"""Replace release histories without deleting their last complete generation.

Data assets are uploaded under unique names. A small immutable manifest commits
the complete generation by asset ID. Only then are the usual filenames restored
for existing consumers. Renaming does not change asset IDs. Interrupted uploads
leave the preceding generation intact; interrupted renames remain recoverable.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


GROUPS = {
    'aufnahme-warteliste-backup': ('aufnahme_warteliste',),
    'anti-churn-ledger-backup': ('watchlist_expired_history', 'active_expired_history'),
}
MANIFEST_PREFIX = 'netshield-history-v1-'
BOOTSTRAP = 'NETSHIELD history v1 initial generation pending'
MANIFEST_RE = re.compile(r'^netshield-history-v1-[a-f0-9]{32}\.json$')
CANONICAL_RE = re.compile(r'^(aufnahme_warteliste|watchlist_expired_history|active_expired_history)\.json\.gz\.part(\d{3})$')


class HistoryError(RuntimeError):
    pass


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header('Authorization')
        return redirected


class GitHub:
    def __init__(self, repo, token):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
            raise HistoryError('Invalid repository name')
        self.base = 'https://api.github.com/repos/' + repo
        self.token = token
        self.opener = urllib.request.build_opener(SafeRedirect())

    def request(self, method, url, *, payload=None, file=None, binary=False):
        headers = {'Accept': 'application/octet-stream' if binary else 'application/vnd.github+json',
                   'Authorization': 'Bearer ' + self.token,
                   'User-Agent': 'NETSHIELD-history', 'X-GitHub-Api-Version': '2022-11-28'}
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(',', ':')).encode()
            headers['Content-Type'] = 'application/json'
        if file is not None:
            data = file
            headers['Content-Type'] = 'application/octet-stream'
            headers['Content-Length'] = str(os.fstat(file.fileno()).st_size)

        # GitHub occasionally resets long-lived HTTPS connections while reading
        # release metadata/assets. Retrying GET is safe and prevents a transient
        # network hiccup from failing the complete blacklist build. Mutating
        # requests are deliberately NOT retried here because a lost response
        # after POST/PATCH could otherwise create duplicate release assets.
        retry_delays = (5, 15, 30, 60) if method == 'GET' and payload is None and file is None else ()
        attempt = 0
        while True:
            request = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                return self.opener.open(request, timeout=120)
            except urllib.error.HTTPError as error:
                retryable = error.code in (429, 500, 502, 503, 504)
                if not retryable or attempt >= len(retry_delays):
                    raise
                delay = retry_delays[attempt]
                attempt += 1
                print(f'::warning::GitHub GET returned HTTP {error.code}; retry {attempt}/{len(retry_delays)} in {delay}s')
                time.sleep(delay)
            except (urllib.error.URLError, ConnectionResetError, TimeoutError, socket.timeout) as error:
                if attempt >= len(retry_delays):
                    raise
                delay = retry_delays[attempt]
                attempt += 1
                print(f'::warning::GitHub GET failed transiently ({error}); retry {attempt}/{len(retry_delays)} in {delay}s')
                time.sleep(delay)

    def json_request(self, method, url, **kwargs):
        with self.request(method, url, **kwargs) as response:
            body = response.read()
        return json.loads(body) if body else None

    def release(self, tag, create=False):
        try:
            release = self.json_request('GET', self.base + '/releases/tags/' + urllib.parse.quote(tag, safe=''))
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            # A repository read distinguishes a missing release from a masked
            # authentication/repository failure. Only a real first run is empty.
            self.json_request('GET', self.base)
            if not create:
                return None
            release = self.json_request('POST', self.base + '/releases',
                                        payload={'tag_name': tag, 'name': tag, 'draft': False, 'body': BOOTSTRAP})
        assets = release.get('assets', [])
        if len(assets) >= 30:
            assets, page = [], 1
            while True:
                batch = self.json_request('GET', self.base + f'/releases/{release["id"]}/assets?per_page=100&page={page}')
                assets.extend(batch)
                if len(batch) < 100:
                    break
                page += 1
        release['assets'] = assets
        return release

    def download(self, asset_id, path):
        with self.request('GET', self.base + f'/releases/assets/{asset_id}', binary=True) as response:
            with Path(path).open('wb') as output:  # allow-nonatomic: caller supplies an unpublished temporary path
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)

    def upload(self, release, name, path):
        endpoint = release['upload_url'].split('{', 1)[0]
        if urllib.parse.urlsplit(endpoint).hostname != 'uploads.github.com':
            raise HistoryError('Unexpected release upload host')
        with Path(path).open('rb') as stream:
            return self.json_request('POST', endpoint + '?name=' + urllib.parse.quote(name, safe=''), file=stream)

    def rename(self, asset_id, name):
        return self.json_request('PATCH', self.base + f'/releases/assets/{asset_id}', payload={'name': name})

    def delete(self, asset_id):
        self.json_request('DELETE', self.base + f'/releases/assets/{asset_id}')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def manifest_assets(release):
    return sorted((a for a in release['assets'] if MANIFEST_RE.fullmatch(a['name'])
                   and a.get('state', 'uploaded') == 'uploaded'),
                  key=lambda a: (a.get('created_at', ''), a['id']), reverse=True)


def validate_entries(entries, tag):
    if not isinstance(entries, dict) or set(entries) != set(GROUPS[tag]):
        raise HistoryError('History manifest has missing or unexpected groups')
    ids = set()
    for prefix, records in entries.items():
        if not isinstance(records, list):
            raise HistoryError('History manifest group is not a list')
        for index, record in enumerate(records):
            expected = f'{prefix}.json.gz.part{index:03d}'
            if (not isinstance(record, dict) or record.get('name') != expected
                    or type(record.get('id')) is not int or record['id'] <= 0
                    or record['id'] in ids or type(record.get('size')) is not int
                    or record['size'] <= 0):
                raise HistoryError('Invalid or non-contiguous history parts')
            if record.get('sha256') is not None and not re.fullmatch(r'[a-f0-9]{64}', record['sha256']):
                raise HistoryError('Invalid history digest')
            ids.add(record['id'])
    return entries


def read_manifest(client, asset, tag):
    with tempfile.TemporaryDirectory(prefix='netshield-manifest-') as directory:
        path = Path(directory)/'manifest.json'
        client.download(asset['id'], path)
        if path.stat().st_size > 4 * 1024 * 1024:
            raise HistoryError('History manifest is unexpectedly large')
        data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('format') != 1 or data.get('tag') != tag:
        raise HistoryError('Invalid history manifest identity')
    return validate_entries(data.get('entries'), tag)


def current_entries(client, release, tag, *, fresh=False):
    manifests = manifest_assets(release)
    if manifests:
        # A malformed committed generation is an error, never a fresh start.
        entries = read_manifest(client, manifests[0], tag)
        by_id = {a['id']: a for a in release['assets']}
        for records in entries.values():
            for record in records:
                asset = by_id.get(record['id'])
                if not asset or asset.get('state', 'uploaded') != 'uploaded' or asset['size'] != record['size']:
                    raise HistoryError('Committed history asset is missing or incomplete')
        release['_loaded_manifest_entries'] = entries
        return {prefix: list(records) for prefix, records in entries.items()}
    fresh = fresh or release.get('body') == BOOTSTRAP
    entries = {}
    for prefix in GROUPS[tag]:
        assets = sorted((a for a in release['assets'] if CANONICAL_RE.fullmatch(a['name'])
                         and a['name'].startswith(prefix + '.')), key=lambda a: a['name'])
        if not assets and not fresh:
            raise HistoryError(f'Existing release has no {prefix} backup; refusing empty history')
        entries[prefix] = [dict(id=a['id'], name=a['name'], size=a['size'],
                               sha256=(a.get('digest') or '').removeprefix('sha256:') or None)
                           for a in assets]
    return validate_entries(entries, tag)


def restore(client, tag, directory):
    release = client.release(tag)
    if release is None:
        print(f'Release {tag} does not exist; first run.')
        return
    entries = current_entries(client, release, tag)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    # Download and verify the entire generation before exposing any local part.
    with tempfile.TemporaryDirectory(prefix='netshield-restore-', dir=directory) as temporary:
        for records in entries.values():
            for record in records:
                path = Path(temporary)/record['name']
                client.download(record['id'], path)
                if path.stat().st_size != record['size'] or (record.get('sha256') and digest(path) != record['sha256']):
                    raise HistoryError('Downloaded history size or digest mismatch')
        for prefix in GROUPS[tag]:
            for stale in directory.glob(prefix + '.json.gz.part*'):
                stale.unlink()
        for path in Path(temporary).iterdir():
            os.replace(path, directory/path.name)
    if manifest_assets(release):
        reconcile_names(client, release, entries)
    print(f'{tag}: complete history generation restored')


def reconcile_names(client, release, entries):
    expected = {record['name']: record['id'] for records in entries.values() for record in records}
    assets = {asset['id']: asset for asset in release['assets']}
    for asset in list(assets.values()):
        if CANONICAL_RE.fullmatch(asset['name']) and expected.get(asset['name']) != asset['id']:
            retired = f'netshield-retired-{asset["id"]}.bin'
            client.rename(asset['id'], retired)
            asset['name'] = retired
    for canonical, asset_id in expected.items():
        if assets[asset_id]['name'] != canonical:
            client.rename(asset_id, canonical)
            assets[asset_id]['name'] = canonical


def publish(client, tag, paths):
    paths = [Path(p) for p in paths]
    if not paths:
        return
    release = client.release(tag)
    fresh = release is None
    if fresh:
        release = client.release(tag, create=True)
    entries = current_entries(client, release, tag, fresh=fresh)
    previous_manifests = manifest_assets(release)
    generation = uuid.uuid4().hex
    grouped = {}
    for path in sorted(paths):
        match = CANONICAL_RE.fullmatch(path.name)
        if not match or match[1] not in GROUPS[tag]:
            raise HistoryError('Unexpected history upload filename')
        grouped.setdefault(match[1], []).append(path)
    staged = []
    for prefix, files in grouped.items():
        records = []
        for index, path in enumerate(files):
            if path.name != f'{prefix}.json.gz.part{index:03d}':
                raise HistoryError('Non-contiguous upload parts')
            checksum = digest(path)
            # Opaque backup names must not match other workflows' legacy globs.
            asset = client.upload(release, f'netshield-stage-{generation}-{prefix}-{index:03d}.bin', path)
            if asset.get('state', 'uploaded') != 'uploaded' or asset['size'] != path.stat().st_size:
                raise HistoryError('Incomplete staged history upload')
            server_digest = asset.get('digest')
            if server_digest and server_digest != 'sha256:' + checksum:
                raise HistoryError('Staged history digest mismatch')
            records.append(dict(id=asset['id'], name=path.name, size=asset['size'], sha256=checksum))
            staged.append((asset, path.name))
        entries[prefix] = records
    validate_entries(entries, tag)
    # Uploading this new immutable object is the commit point. No existing
    # canonical asset has been deleted or renamed before this succeeds.
    with tempfile.TemporaryDirectory(prefix='netshield-publish-') as temporary:
        path = Path(temporary)/'manifest.json'
        path.write_text(json.dumps({'format': 1, 'tag': tag, 'entries': entries}, separators=(',', ':')), encoding='utf-8')  # allow-nonatomic: new private temporary manifest, uploaded only after close
        committed = client.upload(release, MANIFEST_PREFIX + generation + '.json', path)
        if committed.get('state', 'uploaded') != 'uploaded' or committed['size'] != path.stat().st_size:
            raise HistoryError('History manifest upload did not complete')
    # Preserve the public filenames. The committed manifest always finds every
    # new part by immutable asset ID, even if the process stops between renames.
    old_assets = list(release['assets'])
    release['assets'] = old_assets + [asset for asset, _ in staged]
    reconcile_names(client, release, entries)
    # Keep the current and preceding complete generation. Cleanup never changes
    # the outcome of an already committed upload and never deletes their parts.
    keep = {committed['id']} | {record['id'] for records in entries.values() for record in records}
    try:
        if previous_manifests:
            keep.add(previous_manifests[0]['id'])
            previous = release['_loaded_manifest_entries']
            keep.update(record['id'] for records in previous.values() for record in records)
        for asset in old_assets:
            managed = (asset['name'].startswith(('netshield-stage-', 'netshield-retired-'))
                       or MANIFEST_RE.fullmatch(asset['name'])
                       or CANONICAL_RE.fullmatch(asset['name']))
            if managed and asset['id'] not in keep:
                client.delete(asset['id'])
    except Exception as error:
        print(f'::warning::Old history assets could not be cleaned up: {error}')
    print(f'{tag}: history safely published ({len(staged)} parts)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('restore', 'publish'))
    parser.add_argument('--tag', choices=tuple(GROUPS), required=True)
    parser.add_argument('--directory', default='state')
    parser.add_argument('--parts', nargs='+', default=[])
    args = parser.parse_args()
    client = GitHub(os.environ['GITHUB_REPOSITORY'], os.environ['GH_TOKEN'])
    if args.operation == 'restore':
        restore(client, args.tag, args.directory)
    else:
        publish(client, args.tag, args.parts)


if __name__ == '__main__':
    main()
