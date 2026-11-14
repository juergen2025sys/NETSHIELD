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
THREAT_LIVE = 'https://list.threat.live/'
CATEGORIES = {'c2', 'malware', 'botnet', 'ransomware'}


def select_iocs(raw, now, days=7):
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
        if address.is_global and not address.is_multicast and now - timedelta(days=days) <= last_seen <= now:
            selected.add(address)
    if not rows:
        raise ValueError('ThreatCluster returned no rows')
    return sorted(selected, key=lambda ip: (ip.version, int(ip)))


def attribute(address):
    response = json.loads(fetch(NETWORK_INFO + str(address), timeout=20, tries=3))
    if response.get('status') != 'ok':
        raise ValueError(f'RIPEstat lookup failed for {address}')
    data = response['data']
    prefix = data.get('prefix')
    if prefix and address not in ipaddress.ip_network(prefix):
        raise ValueError(f'RIPEstat returned an unrelated prefix for {address}')
    asns = ','.join(f'AS{int(asn)}' for asn in sorted(data.get('asns') or [], key=int))
    return address, asns, prefix or ''


def threat_live_prefixes(records):
    listed = {ipaddress.ip_address(value) for line in fetch(THREAT_LIVE).splitlines()
              if (value := line.partition('#')[0].strip())}
    if not listed:
        raise ValueError('Threat.live returned no IPs')

    networks = set()
    for address, asns, prefix in records:
        if asns and prefix:
            announced = ipaddress.ip_network(prefix)
            minimum = 24 if address.version == 4 else 48
            networks.add(ipaddress.ip_network((address, max(minimum, announced.prefixlen)), strict=False))
    additional = listed - {address for address, _, _ in records}
    candidates = [
        network for network in networks
        if sum(ip.version == network.version and ip in network for ip in additional) >= 2
    ]
    print(f'Threat.live: {len(candidates)} prefixes included in blocklists')
    return candidates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    raw = fetch(FEED)
    now = datetime.now(timezone.utc)
    addresses = select_iocs(raw, now)
    prefix_seeds = select_iocs(raw, now, days=30)
    with ThreadPoolExecutor(max_workers=6) as pool:
        records = list(pool.map(attribute, prefix_seeds))

    args.output.mkdir(parents=True, exist_ok=True)
    report = StringIO()
    writer = csv.writer(report, delimiter='\t', lineterminator='\n')
    writer.writerow(('ip', 'origin_asns', 'announced_prefix'))
    recent_addresses = set(addresses)
    writer.writerows(row for row in records if row[0] in recent_addresses)
    outputs = {'asn_recent_iocs.tsv': report.getvalue()}
    prefixes = threat_live_prefixes(records)
    for version in (4, 6):
        entries = [ip for ip in addresses if ip.version == version]
        entries.extend(network for network in prefixes if network.version == version)
        networks = ipaddress.collapse_addresses(entries)
        outputs[f'asn_recent_iocs_ipv{version}.txt'] = (
            '# Sources: ThreatCluster IPs (7 days) and BGP prefixes corroborated by Threat.live (30-day ThreatCluster window)\n'
            + ''.join(f'{network}\n' for network in networks)
        )
    for name, content in outputs.items():
        target = args.output / name
        temporary = target.with_suffix(target.suffix + '.tmp')
        temporary.write_text(content, encoding='utf-8', newline='\n')
        temporary.replace(target)
    print(f'{len(addresses)} recent IPs, {len(records)} IPs checked for prefix matches')


if __name__ == '__main__':
    main()



