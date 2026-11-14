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


def threat_live_report(records, coverage=None):
    listed = set()
    for line in fetch(THREAT_LIVE).splitlines():
        value = line.partition('#')[0].strip()
        if value:
            listed.add(ipaddress.ip_address(value))
    if not listed:
        raise ValueError('Threat.live returned no IPs')

    grouped = {}
    for address, asns, prefix in records:
        if asns and prefix:
            key = ipaddress.ip_network(prefix)
            group = grouped.setdefault(key, (set(), set()))
            group[0].add(address)
            group[1].update(asns.split(','))

    output = StringIO()
    writer = csv.writer(output, delimiter='\t', lineterminator='\n')
    writer.writerow(('announced_prefix', 'origin_asns', 'threatcluster_ips',
                     'threat_live_ips', 'additional_threat_live_ips', 'firewall_coverage'))
    candidates = 0
    for network, (iocs, asns) in grouped.items():
        hits = {ip for ip in listed if ip.version == network.version and ip in network}
        additional = hits - iocs
        if len(additional) < 2:
            continue
        status = 'not_checked'
        if coverage is not None:
            same_version = coverage[network.version]
            status = ('full' if any(network.subnet_of(n) for n in same_version)
                      else 'partial' if any(network.overlaps(n) for n in same_version)
                      else 'none')
        writer.writerow((network, ','.join(sorted(asns)), len(iocs), len(hits),
                         len(additional), status))
        candidates += 1
    print(f'Threat.live: {candidates} candidate prefixes')
    return output.getvalue()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--firewall-prefixes', type=Path,
                        help='Optional text export of active firewall block prefixes')
    args = parser.parse_args()
    coverage = None
    if args.firewall_prefixes:
        networks = [ipaddress.ip_network(line) for raw in args.firewall_prefixes.read_text().splitlines()
                    if (line := raw.partition('#')[0].strip())]
        coverage = {v: list(ipaddress.collapse_addresses(n for n in networks if n.version == v))
                    for v in (4, 6)}
    addresses = select_iocs(fetch(FEED), datetime.now(timezone.utc))
    with ThreadPoolExecutor(max_workers=6) as pool:
        records = list(pool.map(attribute, addresses))

    args.output.mkdir(parents=True, exist_ok=True)
    report = StringIO()
    writer = csv.writer(report, delimiter='\t', lineterminator='\n')
    writer.writerow(('ip', 'origin_asns', 'announced_prefix'))
    writer.writerows(records)
    outputs = {
        'asn_recent_iocs.tsv': report.getvalue(),
        'threat_live_asns.tsv': threat_live_report(records, coverage),
    }
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






