#!/usr/bin/env python3
"""Read-only release gate: threat lists may contain only public IPv4 hosts.

Run from any directory; optional arguments select files for targeted validation.
Blacklist /32 entries are allowed. Broader networks and invalid addresses fail.
"""
import argparse
from pathlib import Path

from netshield_common import is_valid_public_cidr, is_valid_public_ipv4

ROOT = Path(__file__).resolve().parents[1]
THREAT_LIST_PATTERNS = (
    "*_blacklist*.txt", "blacklist_confidence*_ipv4*.txt",
    "watchlist_confidence*_ipv4*.txt", "*_ips.txt",
)


def check_file(path):
    entries = rejected = 0
    samples = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            entries += 1
            valid = is_valid_public_cidr(value) if "/" in value else is_valid_public_ipv4(value)
            if not valid:
                rejected += 1
                if len(samples) < 10:
                    samples.append((line_number, value))
    return entries, rejected, samples


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args(argv)
    # Geographic allocation tables deliberately contain CIDRs. They are not
    # threat lists and must not be subjected to the threat-list /32 policy.
    paths = args.files or sorted({path for pattern in THREAT_LIST_PATTERNS
                                 for path in ROOT.glob(pattern)})
    if not paths:
        parser.error("No published lists found")
    failed = False
    for path in paths:
        try:
            entries, rejected, samples = check_file(path)
        except (OSError, UnicodeError) as error:
            print(f"FAIL {path}: {error}", flush=True)
            failed = True
            continue
        failed |= bool(rejected)
        print(f"{'FAIL' if rejected else 'PASS'} {path.name}: {entries} entries, {rejected} rejected", flush=True)
        for number, value in samples:
            print(f"  line {number}: {value!r}")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
