#!/usr/bin/env python3
"""
NETSHIELD - Offene Proxies (seit 2026-11-16, Nutzerentscheidung)

Holt oeffentliche Listen offener Proxy-Server (HTTP/SOCKS4/SOCKS5), zieht
daraus die einzelnen IPv4-Adressen (Format "ip:port" -> nur ip) und schreibt
sie als reine Einzel-IP-Liste nach proxy/offene_proxies.txt - keine
Netzbereiche (NETSHIELD-Regel: nur einzelne IPs).

Quellen:
  - TheSpeedX/PROXY-List   (http.txt, socks4.txt, socks5.txt)
  - monosans/proxy-list    (proxies/all.txt)
  - seit 2026-11-16 abends 11 weitere: hookzof, KangProxy, mmpx12,
    dpangestuw, hideip.me, VPSLab, elliottophellia, iplocate, sunny9577,
    roosterkid, Zaeem20, ProxyScrape (siehe SOURCES)

Bewusst NICHT dabei: proxifly/free-proxy-list - traf im NetFlow-Abgleich
(16.11.2026) einen WordPress-Hoster (WP Engine), also echte Webseiten.

Schutz:
  - Whitelist (.github/workflows/whitelist.json) und Fehlalarm-Liste
    (state/false_positives_set.json) aus netshield_common werden beachtet.
  - Faellt eine Quelle aus -> Warnung, die anderen laufen weiter.
  - Weniger als MIN_IPS IPs insgesamt -> alte Datei bleibt, Exit 1.
"""
import datetime
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netshield_common import (  # noqa: E402
    load_whitelist, load_fp_set, is_in_fp_set, is_whitelisted,
    is_protected_entry, is_valid_public_ipv4, write_ip_list,
)

SOURCES = {
    'TheSpeedX http':   'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
    'TheSpeedX socks4': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
    'TheSpeedX socks5': 'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
    'monosans':         'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt',
}
# Seit 2026-11-16 abends: weitere taeglich gepflegte Listen offener Proxies.
# Alle wurden vorher gegen 10 Tage NetFlow geprueft (0 Kontakte zu eigenen
# Geraeten). Bewusst NICHT dabei: vakhov/fresh-proxy-list (traf WP Engine) und
# Thordata (V2Ray-Server, oft hinter Cloudflare).
_GH = 'https://raw.githubusercontent.com/'
for _name, _paths in {
    'hookzof':      ['hookzof/socks5_list/HEAD/proxy.txt'],
    'KangProxy':    ['officialputuid/KangProxy/HEAD/%s/%s.txt' % (p, p) for p in ('http', 'https', 'socks4', 'socks5')],
    'mmpx12':       ['mmpx12/proxy-list/HEAD/proxies.txt'],
    'dpangestuw':   ['dpangestuw/Free-Proxy/HEAD/All_proxies.txt'],
    'hideip.me':    ['zloi-user/hideip.me/HEAD/%s.txt' % p for p in ('http', 'https', 'socks4', 'socks5')],
    'VPSLab':       ['VPSLabCloud/VPSLab-Free-Proxy-List/HEAD/all_proxies.txt'],
    'elliottophellia': ['elliottophellia/proxylist/HEAD/results/%s/global/%s_checked.txt' % (p, p)
                        for p in ('http', 'socks4', 'socks5')],
    'iplocate':     ['iplocate/free-proxy-list/HEAD/all-proxies.txt'],
    'sunny9577':    ['sunny9577/proxy-scraper/HEAD/proxies.txt'],
    'roosterkid':   ['roosterkid/openproxylist/HEAD/%s_RAW.txt' % p for p in ('HTTPS', 'SOCKS4', 'SOCKS5')],
    'Zaeem20':      ['Zaeem20/FREE_PROXIES_LIST/HEAD/%s.txt' % p for p in ('http', 'https', 'socks4', 'socks5')],
    # 2026-11-16 abends (Nutzerwunsch): ProxyScrape-GitHub-Spiegel, laufend aktualisiert
    'ProxyScrape':  ['proxyscrape/free-proxy-list/HEAD/proxies/all/data.txt'],
}.items():
    for _i, _p in enumerate(_paths):
        SOURCES['%s %d' % (_name, _i + 1) if len(_paths) > 1 else _name] = _GH + _p
UA = {'User-Agent': 'NETSHIELD-OpenProxies/1.0 (+https://github.com/juergen2025sys/NETSHIELD)'}
OUT = sys.argv[1] if len(sys.argv) > 1 else 'proxy/offene_proxies.txt'
MIN_IPS = 500
IP_RE = re.compile(r'(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])')


def fetch(url, timeout=60, tries=3):
    last = None
    for _ in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
                return r.read().decode('utf-8', 'ignore')
        except Exception as e:  # Netzwerkfehler -> erneut versuchen
            last = e
    raise IOError('%s: %s' % (url, last))


def main():
    load_whitelist()
    load_fp_set()
    ips, per_source = set(), {}
    for name, url in SOURCES.items():
        try:
            text = fetch(url)
        except IOError as e:
            print('::warning::Quelle %s nicht ladbar (%s) - ohne sie weiter' % (name, e))
            continue
        found = set()
        for line in text.splitlines():
            m = IP_RE.search(line)
            if m and is_valid_public_ipv4(m.group(1)):
                found.add(m.group(1))
        per_source[name] = len(found)
        ips |= found
    raw = len(ips)
    ips = {ip for ip in ips
           if not is_whitelisted(ip) and not is_protected_entry(ip) and not is_in_fp_set(ip)}
    for name, n in per_source.items():
        print('%-17s %6d IPs' % (name, n))
    print('Gesamt: %d IPs (vor Whitelist/Fehlalarm-Filter: %d)' % (len(ips), raw))
    if len(ips) < MIN_IPS:
        print('::error::Nur %d IPs - behalte bestehende %s' % (len(ips), OUT))
        return 1
    os.makedirs(os.path.dirname(OUT) or '.', exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    write_ip_list(OUT, ips, header_lines=[
        'NETSHIELD - offene Proxy-Server (nur Einzel-IPs, ohne Port)',
        'Quellen: TheSpeedX/PROXY-List, monosans/proxy-list + %d weitere Proxy-Listen (siehe Skript)'
        % len({k.split(' ')[0] for k in per_source} - {'TheSpeedX', 'monosans'}),
        'Aktualisiert: %s | IPs: %d' % (now, len(ips)),
    ])
    print('FERTIG -> %s' % OUT)
    return 0


if __name__ == '__main__':
    sys.exit(main())
