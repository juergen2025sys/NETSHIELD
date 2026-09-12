"""Verify that the committed release pointer describes every public output."""
import json
from pathlib import Path

from netshield_release_state import read_manifest, sha256


def generation_files():
    paths = [
        Path('active_blacklist_ipv4.txt'), Path('watchlist_confidence25to39_ipv4.txt'),
        Path('state/seen_db_meta.json'), Path('state/watchlist_daily_cap_state.json'),
        Path('state/confidence_generation.json'),
    ]
    for stem in ('combined_threat_blacklist_ipv4', 'blacklist_confidence40_ipv4'):
        parts = sorted(Path('.').glob(stem + '_part*.txt'))
        expected = [Path(f'{stem}_part{i}.txt') for i in (1, 2)]
        if parts != expected:
            raise ValueError(f'Expected exactly two canonical parts for {stem}')
        paths.extend(parts)
    if any(not path.is_file() for path in paths):
        raise ValueError('A required generation output is missing')
    return paths


def verify():
    manifest = read_manifest()
    actual = {str(path): sha256(path) for path in generation_files()}
    if actual != manifest.get('outputs'):
        raise ValueError('Generation output hashes do not match the release manifest')
    confidence = json.loads(Path('state/confidence_generation.json').read_text(encoding='utf-8'))
    if confidence['generated_at_epoch'] != manifest['inputs']['epoch']:
        raise ValueError('Scoring time differs from the prepared generation')
    print('All public generation output hashes verified')


if __name__ == '__main__':
    verify()
