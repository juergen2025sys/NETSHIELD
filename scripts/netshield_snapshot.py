"""One validation policy for Auto-Feed producers and consumers."""
import sqlite3
import time
from contextlib import closing
from pathlib import Path


def validate_snapshot(path, *, now=None, refresh_max_age=3600, minimum=50000):
    now = int(time.time() if now is None else now)
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
            raise ValueError('Snapshot quick_check failed')
        count, unique = db.execute('SELECT COUNT(*),COUNT(DISTINCT entry) FROM hits').fetchone()
        if count < minimum or unique < minimum:
            raise ValueError(f'Snapshot too small: {count} hits / {unique} unique')
        meta = dict(db.execute('SELECT key,value FROM meta'))
        refreshed = int(meta.get('refresh_run_at_epoch', 0))
        generated = int(meta.get('generated_at_epoch', 0))
        if not 0 <= now - refreshed <= refresh_max_age:
            raise ValueError('Snapshot refresh timestamp is stale or in the future')
        actual = dict(db.execute('SELECT feed,COUNT(*) FROM hits GROUP BY feed'))
        epochs = []
        fresh_hits = fresh_feeds = fallbacks = 0
        for feed, entries, status, stamp in db.execute(
                'SELECT feed,entries,status,last_success_epoch FROM feed_stats'):
            if entries != actual.pop(feed, 0):
                raise ValueError(f'Snapshot feed count mismatch: {feed}')
            if entries <= 0:
                continue
            stamp = int(stamp)
            age = now - stamp
            limit = refresh_max_age if status == 'ok' else 6 * 3600
            if status not in ('ok', 'fallback_previous') or not 0 <= age <= limit:
                raise ValueError(f'Invalid snapshot evidence: {feed} / {status} / age={age}')
            if stamp > refreshed:
                raise ValueError(f'Evidence timestamp exceeds refresh timestamp: {feed}')
            epochs.append(stamp)
            if status == 'ok':
                fresh_hits += entries
                fresh_feeds += 1
            else:
                fallbacks += 1
        if actual or not epochs or generated != min(epochs):
            raise ValueError('Snapshot has missing feed statistics or inconsistent generation time')
    return dict(meta=meta, hits=count, unique=unique, fresh_hits=fresh_hits,
                fresh_feeds=fresh_feeds, fallbacks=fallbacks, age=now - generated)
