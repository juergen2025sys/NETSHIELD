"""Fail closed when the four public blacklist outputs come from different runs."""
from contextlib import closing
import sqlite3
import sys
import tempfile
from pathlib import Path


def sources(base, required=None):
    base = Path(base)
    parts = sorted(base.parent.glob(base.stem + '_part*.txt'))
    if required:
        wanted = {base.parent / f'{base.stem}_part{i}.txt' for i in required}
        if wanted != set(parts):
            raise ValueError(f'{base.name}: missing or unexpected parts')
        return sorted(wanted)
    return parts or ([base] if base.is_file() else [])


def rows(paths):
    for path in paths:
        with path.open(encoding='utf-8') as stream:
            for line in stream:
                value = line.strip()
                if value and not value.startswith('#'):
                    yield value.removesuffix('/32')


def check(root='.'):
    root = Path(root)
    files = {
        'combined': (root / 'combined_threat_blacklist_ipv4.txt', (1, 2)),
        'active': (root / 'active_blacklist_ipv4.txt', None),
        'confidence': (root / 'blacklist_confidence40_ipv4.txt', (1, 2)),
        'watch': (root / 'watchlist_confidence25to39_ipv4.txt', None),
    }
    # Millions of addresses must not all live in RAM on the hosted runner.
    with tempfile.TemporaryDirectory(prefix='netshield-consistency-') as temp, closing(sqlite3.connect(str(Path(temp) / 'check.sqlite3'))) as db:
        db.execute('PRAGMA journal_mode=OFF')
        db.execute('PRAGMA synchronous=OFF')
        db.execute('PRAGMA cache_size=-32768')
        db.execute('CREATE TABLE ips(kind TEXT, ip TEXT, PRIMARY KEY(kind, ip)) WITHOUT ROWID')
        counts = {}
        for kind, (base, required) in files.items():
            path_list = sources(base, required)
            if not path_list:
                raise ValueError(f'{base.name}: no published source')
            db.executemany('INSERT INTO ips VALUES (?,?)',
                           ((kind, ip) for ip in rows(path_list)))
            counts[kind] = db.execute('SELECT COUNT(*) FROM ips WHERE kind=?', (kind,)).fetchone()[0]
            if not counts[kind] and kind in ('combined', 'confidence'):
                raise ValueError(f'{base.name}: empty publication')
        missing_active = db.execute('''
            SELECT COUNT(*) FROM ips a LEFT JOIN ips c ON c.kind='confidence' AND c.ip=a.ip
            WHERE a.kind='active' AND c.ip IS NULL''').fetchone()[0]
        missing_watch = db.execute('''
            SELECT COUNT(*) FROM ips w LEFT JOIN ips c ON c.kind='combined' AND c.ip=w.ip
            WHERE w.kind='watch' AND c.ip IS NULL''').fetchone()[0]
        missing_confidence = db.execute('''
            SELECT COUNT(*) FROM ips c LEFT JOIN ips b ON b.kind='combined' AND b.ip=c.ip
            WHERE c.kind='confidence' AND b.ip IS NULL''').fetchone()[0]
        overlap = db.execute('''
            SELECT COUNT(*) FROM ips c JOIN ips w ON w.kind='watch' AND w.ip=c.ip
            WHERE c.kind='confidence' ''').fetchone()[0]
    if missing_active or missing_watch or missing_confidence or overlap:
        raise ValueError(f'inconsistent generation: active\u2209confidence={missing_active}, '
                         f'watch\u2209combined={missing_watch}, confidence\u2209combined={missing_confidence}, confidence\u2229watch={overlap}')
    return counts


if __name__ == '__main__':
    try:
        print('Pipeline consistency: ' + repr(check()))
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f'::error::Pipeline consistency check failed: {exc}')
        sys.exit(1)
