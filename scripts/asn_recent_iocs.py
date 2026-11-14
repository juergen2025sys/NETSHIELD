#!/usr/bin/env python3
"""Publish recently reported malware and C2 IPs with BGP attribution."""
import argparse
import csv
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

from asn_drop_build import fetch

FEED = 'https://raw.githubusercontent.com/Jam0k/Public-Feeds-IOCs/HEAD/feeds/ips.csv'
NETWORK_INFO = 'https://stat.ripe.net/data/network-info/data.json?resource='
CATEGORIES = {'c2', 'malware', 'botnet', 'ransomware'}


def select_iocs(raw, now):
    reader = csv.DictReader(StringIO(raw))
    required = {'value', 'confidence', 'last_seen', 'categories'}
    if not required <= set(reader.fieldnames or []):
        raise ValueError('Unexpected ThreatCluster CSV schema')
    selected = set()
    rows = 0
    for row in reader:
        rows += 1
        if row['confidence'] != 'high' or not CATEGORIES.intersection(
            part.lower() for part in re.split(r'[|,;\s]+', row['categories'])
        ):
            continue
        last_seen = datetime.fromisoformat(row['last_seen'].replace('Z', '+00:00'))
        address = ipaddress.ip_address(row['value'])
        if address.is_global and not address.is_multicast and now - timedelta(days=7) <= last_seen <= now:
            selected.add(address)
    if not rows:
        raise ValueError('ThreatCluster returned no rows')
    return sorted(selected, key=lambda ip: (ip.version, int(ip)))


def attribute(address):
    response = json.loads(fetch(NETWORK_INFO + str(address), timeout=12, tries=2))
    if response.get('status') != 'ok':
        raise ValueError(f'RIPEstat lookup failed for {address}')
    data = response['data']
    prefix = data.get('prefix')
    if prefix and address not in ipaddress.ip_network(prefix):
        raise ValueError(f'RIPEstat returned an unrelated prefix for {address}')
    asns = ','.join(f'AS{int(asn)}' for asn in sorted(data.get('asns') or [], key=int))
    return address, asns, prefix or ''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    addresses = select_iocs(fetch(FEED), datetime.now(timezone.utc))
    with ThreadPoolExecutor(max_workers=6) as pool:
        records = list(pool.map(attribute, addresses))

    args.output.mkdir(parents=True, exist_ok=True)
    report = StringIO()
    writer = csv.writer(report, delimiter='\t', lineterminator='\n')
    writer.writerow(('ip', 'origin_asns', 'announced_prefix'))
    writer.writerows(records)
    outputs = {'asn_recent_iocs.tsv': report.getvalue()}
    for version in (4, 6):
        # Collapse only adjacent observed addresses. No unobserved IP is added.
        networks = ipaddress.collapse_addresses(ip for ip in addresses if ip.version == version)
        outputs[f'asn_recent_iocs_ipv{version}.txt'] = (
            '# Source: ThreatCluster | high confidence | last seen within 7 days\n'
            + ''.join(f'{network}\n' for network in networks)
        )
    for name, content in outputs.items():
        target = args.output / name
        temporary = target.with_suffix(target.suffix + '.tmp')
        temporary.write_text(content, encoding='utf-8', newline='\n')
        temporary.replace(target)
    print(f'{len(records)} recent IPs, {sum(bool(row[1]) for row in records)} with origin ASN')


if __name__ == '__main__':
    main()

