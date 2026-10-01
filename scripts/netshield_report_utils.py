"""Resolve published list parts consistently across report and README steps."""
from pathlib import Path
import re

from netshield_common import TIMESTAMP_RE


def published_list_sources(filepath):
    path = Path(filepath)
    pattern = re.compile(re.escape(path.stem) + r"_part([1-9][0-9]*)" + re.escape(path.suffix))
    parts = []
    for candidate in path.parent.glob(f"{path.stem}_part*{path.suffix}"):
        match = pattern.fullmatch(candidate.name)
        if match and candidate.is_file():
            parts.append((int(match[1]), candidate))
    # Parts are canonical. An ignored legacy main file can be stale/truncated.
    return [p for _, p in sorted(parts)] if parts else ([path] if path.is_file() else [])


def count_published_ips(filepath, missing=0):
    sources = published_list_sources(filepath)
    if not sources:
        return missing
    seen = set()
    for source in sources:
        with source.open(encoding="utf-8") as stream:
            seen.update(line for raw in stream if (line := raw.strip()) and not line.startswith("#"))
    return len(seen)


def published_list_updated(filepath):
    stamps = []
    for source in published_list_sources(filepath):
        stamp = "–"
        with source.open(encoding="utf-8") as stream:
            for _ in range(10):
                match = TIMESTAMP_RE.search(stream.readline())
                if match:
                    suffix = " (Europe/Berlin)" if match[2] in ("CET", "CEST") else ""
                    stamp = f"{match[1]} {match[2]}{suffix}"
                    break
        stamps.append(stamp)
    if len(set(stamps)) > 1:
        return "Uneinheitliche Part-Zeitstempel"
    return stamps[0] if stamps else "–"
