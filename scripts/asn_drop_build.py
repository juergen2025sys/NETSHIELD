#!/usr/bin/env python3
"""
NETSHIELD - Spamhaus ASN-DROP -> IP-Netzlisten

Holt die Spamhaus ASN-DROP-Liste (Netzbetreiber, die laut Spamhaus von
Kriminellen kontrolliert werden / Bulletproof-Hoster), loest jede ASN ueber
ipverse/as-ip-blocks (CC0, taeglich aktualisierte BGP-Ankuendigungen) in ihre
IP-Netze auf und schreibt:

  asn_drop_ipv4.txt   - zusammengefasste IPv4-Netze (fuer Firewall-URL-Tabellen)
  asn_drop_ipv6.txt   - zusammengefasste IPv6-Netze
  asn_drop_asns.txt   - die verwendeten ASNs mit Name/Land (zur Kontrolle)

Schutz gegen kaputte Laeufe (alte Dateien bleiben dann unveraendert, Exit 1):
  - weniger als MIN_ASNS ASNs in der Spamhaus-Liste
  - mehr als MAX_FAIL_RATIO der ipverse-Abrufe fehlgeschlagen
  - weniger als MIN_V4 IPv4-Netze im Ergebnis
Nur oeffentliche Adressen (is_global) werden uebernommen.
"""
import datetime
import ipaddress
import json
import os
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

SPAMHAUS_URL = 'https://www.spamhaus.org/drop/asndrop.json'
IPVERSE_URL = 'https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/%d/aggregated.json'
UA = {'User-Agent': 'NETSHIELD-ASN-DROP/1.0 (+https://github.com/juergen2025sys/NETSHIELD)'}
OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else '.'
MIN_ASNS = 100
MAX_FAIL_RATIO = 0.10
MIN_V4 = 1000


def fetch(url, timeout=60, tries=3):
    last = None
    for _ in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
                if r.status == 200:
                    return r.read().decode('utf-8')
                last = 'HTTP %s' % r.status
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ''          # ASN ohne aktive Netze bei ipverse - kein Fehler
            last = str(e)
        except Exception as e:     # Netzwerkfehler -> erneut versuchen
            last = str(e)
    raise IOError('%s: %s' % (url, last))


def main():
    raw = fetch(SPAMHAUS_URL)
    asns, meta = {}, {}
    for line in raw.splitlines():
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get('type') == 'metadata':
            meta = o
        elif isinstance(o.get('asn'), int):
            asns[o['asn']] = o
    print('Spamhaus ASN-DROP: %d ASNs (records laut Metadaten: %s)' % (len(asns), meta.get('records')))
    if len(asns) < MIN_ASNS:
        print('::error::Nur %d ASNs von Spamhaus - behalte bestehende Dateien' % len(asns))
        return 1

    def resolve(asn):
        try:
            txt = fetch(IPVERSE_URL % asn)
            return asn, (json.loads(txt).get('prefixes', {}) if txt else {}), None
        except Exception as e:
            return asn, None, str(e)

    with ThreadPoolExecutor(8) as ex:
        results = list(ex.map(resolve, sorted(asns)))

    failed = [a for a, p, err in results if p is None]
    if len(failed) > MAX_FAIL_RATIO * len(asns):
        print('::error::%d von %d ipverse-Abrufen fehlgeschlagen - behalte bestehende Dateien' % (len(failed), len(asns)))
        return 1
    if failed:
        print('::warning::%d ipverse-Abrufe fehlgeschlagen: %s' % (len(failed), failed[:20]))

    v4, v6, active = [], [], 0
    for asn, pref, err in results:
        if not pref:
            continue
        got = False
        for key, store in (('ipv4', v4), ('ipv6', v6)):
            for p in pref.get(key, []):
                try:
                    n = ipaddress.ip_network(p, strict=False)
                except ValueError:
                    continue
                if n.is_global:
                    store.append(n)
                    got = True
        active += got

    v4 = list(ipaddress.collapse_addresses(v4))
    v6 = list(ipaddress.collapse_addresses(v6))
    print('ASNs mit aktiven Netzen: %d | IPv4-Netze: %d (%d Adressen) | IPv6-Netze: %d'
          % (active, len(v4), sum(n.num_addresses for n in v4), len(v6)))
    if len(v4) < MIN_V4:
        print('::error::Nur %d IPv4-Netze - behalte bestehende Dateien' % len(v4))
        return 1

    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    head = ('# NETSHIELD - Spamhaus ASN-DROP (Bulletproof-/Kriminellen-Netzbetreiber)\n'
            '# Quelle ASNs: %s (Stand Spamhaus: %s)\n'
            '# Quelle Netze: github.com/ipverse/as-ip-blocks (CC0)\n'
            '# Aktualisiert: %s | ASNs: %d (aktiv: %d)\n'
            % (SPAMHAUS_URL, meta.get('timestamp'), now, len(asns), active))

    def write(name, body):
        tmp = os.path.join(OUT_DIR, name + '.tmp')
        with open(tmp, 'w') as f:
            f.write(body)
        os.replace(tmp, os.path.join(OUT_DIR, name))

    write('asn_drop_ipv4.txt', head + '# IPv4-Netze: %d\n\n' % len(v4) + '\n'.join(map(str, v4)) + '\n')
    write('asn_drop_ipv6.txt', head + '# IPv6-Netze: %d\n\n' % len(v6) + '\n'.join(map(str, v6)) + '\n')
    write('asn_drop_asns.txt', head + '\n' + '\n'.join(
        'AS%d\t%s\t%s\t%s' % (a, asns[a].get('cc', ''), asns[a].get('asname', ''), asns[a].get('domain', ''))
        for a in sorted(asns)) + '\n')
    print('FERTIG')
    return 0


if __name__ == '__main__':
    sys.exit(main())
