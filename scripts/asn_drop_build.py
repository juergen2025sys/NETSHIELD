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

Zusatzquelle (seit 2026-11-15): crimsonvector/BPH_Research (MIT) - Forschungs-
Datenbank zu Bulletproof-Hostern. Uebernommen werden nur eindeutige Faelle:
risk_tier T1 ("Confirmed BPH") oder T2 ("High Risk"), KEINE Upstream-Enabler,
Status nicht dissolved/seized/dormant. Neue Eintraege dort kommen beim naechsten
Lauf automatisch dazu. Faellt diese Quelle aus, laeuft der Build mit Spamhaus
allein weiter (nur Warnung) - die Spamhaus-Guards oben gelten unveraendert.

Zweite Zusatzquelle (seit 2026-11-15, Nutzerentscheidung): stamparm/maltrail
data/worst_asns.txt. Die Datei hat zwei Teile: zuerst 16 grosse Hoster mit viel
Missbrauch (Linode, Vultr, OVH, Hetzner, DigitalOcean, Leaseweb, ... bis
einschliesslich AS9009 M247) - diese werden NICHT uebernommen, weil sie sonst
grosse Teile des Internets sperren. Uebernommen wird nur der zweite Teil
(ueberwiegend Bulletproof-/Graue Hoster) ab dem Eintrag NACH AS9009. Fehlt die
Markierung AS9009 (Dateiaufbau geaendert), wird Maltrail komplett ausgelassen.
"""
import csv
import datetime
import io
import re
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

BPH_URL = 'https://raw.githubusercontent.com/crimsonvector/BPH_Research/main/BPH_Master.csv'
BPH_SKIP_STATUS = ('dissolved', 'seized', 'dormant')
# "AS12345" nur als eigenstaendiges Token - verhindert Treffer in Namen wie "LD007-AS"
BPH_ASN_RE = re.compile(r'(?<![A-Za-z0-9-])AS(\d{1,10})\b')
# Bewusst KEINE Ausnahmeliste (Nutzerentscheidung 2026-11-15): was Spamhaus oder
# BPH_Research (T1/T2) als kriminell fuehrt, wird gesperrt - ohne Sonderregeln.


MALTRAIL_URL = 'https://raw.githubusercontent.com/stamparm/maltrail/master/data/worst_asns.txt'
MALTRAIL_SPLIT_AFTER = 9009   # letzter Eintrag des "grosse Hoster"-Blocks (M247)
MALTRAIL_HDR_RE = re.compile(r'^#\s*AS\s?(\d{1,10})\b(.*)$')


def load_maltrail():
    """ASNs aus Maltrail worst_asns (nur Teil 2): {asn: name}; {} bei Fehler."""
    try:
        heads = []
        for line in fetch(MALTRAIL_URL).splitlines():
            m = MALTRAIL_HDR_RE.match(line.strip())
            if m:
                heads.append((int(m.group(1)), m.group(2).strip(' ,')))
        idx = [i for i, (a, _) in enumerate(heads) if a == MALTRAIL_SPLIT_AFTER]
        if not idx:
            print('::warning::Maltrail: Markierung AS%d fehlt - Dateiaufbau geaendert, Maltrail ausgelassen'
                  % MALTRAIL_SPLIT_AFTER)
            return {}
        return {a: n for a, n in heads[idx[0] + 1:] if 0 < a < 4200000000}
    except Exception as e:
        print('::warning::Maltrail nicht ladbar (%s) - ohne Maltrail weiter' % e)
        return {}


def load_bph():
    """ASNs aus BPH_Research: {asn: (provider, risk_tier, status)}; {} bei Fehler."""
    try:
        rows = csv.DictReader(io.StringIO(fetch(BPH_URL)))
        out = {}
        for r in rows:
            tier = (r.get('risk_tier') or '').strip()
            status = (r.get('status') or '').strip().lower()
            if not tier.startswith(('T1', 'T2')) or 'upstream' in tier.lower() \
                    or status in BPH_SKIP_STATUS:
                continue
            text = '%s %s' % (r.get('primary_asn') or '', r.get('additional_asns') or '')
            for m in BPH_ASN_RE.finditer(text):
                a = int(m.group(1))
                if 0 < a < 4200000000:
                    out.setdefault(a, ((r.get('provider_name') or '').strip(), tier, status))
        return out
    except Exception as e:
        print('::warning::BPH_Research nicht ladbar (%s) - nur Spamhaus' % e)
        return {}


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
    n_spamhaus = len(asns)

    bph = load_bph()
    bph_new = {a: v for a, v in bph.items() if a not in asns}
    for a, (name, tier, status) in bph_new.items():
        asns[a] = {'asn': a, 'cc': '', 'asname': name, 'domain': 'BPH_Research %s / %s' % (tier, status)}
    print('BPH_Research: %d ASNs (T1/T2, ohne Upstream/aufgeloest) | davon neu ggue. Spamhaus: %d'
          % (len(bph), len(bph_new)))

    mt = load_maltrail()
    mt_new = {a: n for a, n in mt.items() if a not in asns}
    for a, name in mt_new.items():
        asns[a] = {'asn': a, 'cc': '', 'asname': name, 'domain': 'Maltrail worst_asns'}
    print('Maltrail worst_asns: %d ASNs (Teil 2) | davon neu ggue. Spamhaus+BPH: %d'
          % (len(mt), len(mt_new)))

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
    head = ('# NETSHIELD - Spamhaus ASN-DROP + BPH_Research + Maltrail (Bulletproof-/Kriminellen-Netzbetreiber)\n'
            '# Quelle ASNs: %s (Stand Spamhaus: %s)\n'
            '# Zusatz-ASNs: %s (MIT; T1/T2, ohne Upstream/aufgeloest)\n'
            '# Zusatz-ASNs: %s (nur Teil 2, ohne grosse Hoster)\n'
            '# Quelle Netze: github.com/ipverse/as-ip-blocks (CC0)\n'
            '# Aktualisiert: %s | ASNs: %d (Spamhaus %d + BPH %d + Maltrail %d, aktiv: %d)\n'
            % (SPAMHAUS_URL, meta.get('timestamp'), BPH_URL, MALTRAIL_URL, now, len(asns),
               n_spamhaus, len(bph_new), len(mt_new), active))

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
