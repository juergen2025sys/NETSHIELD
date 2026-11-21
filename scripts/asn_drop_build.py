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

Dritte Zusatzquelle (seit 2026-11-15): Bulletproof Hosting Watch (ai.rud.is),
woechentlicher Bericht - die ASN-Tabelle des jeweils neuesten Berichts.
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
# Ersatzquelle (seit 2026-11-18), falls ipverse fuer eine ASN nicht erreichbar ist
RIPESTAT_URL = 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d&sourceapp=netshield-asn-drop'
HOLD_DAYS = 14
UA = {'User-Agent': 'NETSHIELD-ASN-DROP/1.0 (+https://github.com/juergen2025sys/NETSHIELD)'}
OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else '.'
HOLD_FILE = os.path.join(OUT_DIR, 'asn_dichte_haltezeit.json')
MIN_ASNS = 100
MAX_FAIL_RATIO = 0.10
MIN_V4 = 1000

BPH_URL = 'https://raw.githubusercontent.com/crimsonvector/BPH_Research/main/BPH_Master.csv'
BPH_SKIP_STATUS = ('dissolved', 'seized', 'dormant')
# "AS12345" nur als eigenstaendiges Token - verhindert Treffer in Namen wie "LD007-AS"
BPH_ASN_RE = re.compile(r'(?<![A-Za-z0-9-])AS(\d{1,10})\b')
# Bewusst KEINE Ausnahmeliste (Nutzerentscheidung 2026-11-15): was Spamhaus oder
# BPH_Research (T1/T2) als kriminell fuehrt, wird gesperrt - ohne Sonderregeln.


# Dritte Zusatzquelle (seit 2026-11-15, Nutzerentscheidung): "Bulletproof
# Hosting Watch" (ai.rud.is) - woechentlicher Bericht ueber beobachtete
# Bulletproof-Hoster. Uebernommen wird die Tabelle des NEUESTEN Berichts
# (erste Spalte = ASN). Erscheint ein neuer Bericht, wird er automatisch
# genommen. Faellt die Seite aus -> Warnung, Build laeuft ohne sie weiter.
BPHW_INDEX = 'https://ai.rud.is/posts/'
BPHW_POST_RE = re.compile(r'/posts/(\d{4}-\d{2}-\d{2}-weekly-bulletproof-report)/?')
BPHW_ROW_RE = re.compile(r'(?s)<tr>\s*<td[^>]*>\s*(?:<[^>]+>\s*)*AS(\d{1,10})\b(.*?)</tr>')
BPHW_MIN_ROWS = 5            # weniger Zeilen -> Seitenaufbau geaendert, Quelle auslassen


def load_bph_watch():
    """ASNs aus dem neuesten Bulletproof-Hosting-Watch-Bericht: ({asn: name}, datum); ({}, None) bei Fehler."""
    try:
        posts = sorted(set(BPHW_POST_RE.findall(fetch(BPHW_INDEX))), reverse=True)
        if not posts:
            print('::warning::Bulletproof Hosting Watch: kein Bericht gefunden - ausgelassen')
            return {}, None
        html = fetch(BPHW_INDEX + posts[0] + '/')
        out = {}
        for m in BPHW_ROW_RE.finditer(html):
            cells = [c.strip() for c in re.sub(r'<[^>]+>', '|', m.group(2)).split('|') if c.strip()]
            a = int(m.group(1))
            if 0 < a < 4200000000:
                out.setdefault(a, cells[0] if cells else '')
        if len(out) < BPHW_MIN_ROWS:
            print('::warning::Bulletproof Hosting Watch: nur %d ASNs - Seitenaufbau geaendert, ausgelassen' % len(out))
            return {}, None
        return out, posts[0][:10]
    except Exception as e:
        print('::warning::Bulletproof Hosting Watch nicht ladbar (%s) - ohne diese Quelle weiter' % e)
        return {}, None


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


# Eigene Auswertung (2026-11-15): kleine Hoster mit sehr hoher Dichte an
# Malware-IPs, die (noch) bei keiner der drei Quellen stehen. Feste Liste,
# wird NICHT automatisch aktualisiert. Tor-Betreiber und Internet-Scanner
# (Censys, Modat, BitSight) sind bewusst nicht dabei.
# ThreatFox-Auswertung (2026-11-15): dns_list_mirror.py legt die C2-IPs aus
# dem ThreatFox-Export (CC0) in dns/threatfox_c2_ips.txt ab. Hier wird jede IP
# ihrem Netzbetreiber zugeordnet (ip-location-db, Quelle RouteViews/iptoasn).
# Kandidat ist ein Netzbetreiber, wenn er KLEIN ist (<= TF_MAX_ADDR Adressen,
# damit Clouds/Provider wie Amazon, Hetzner oder Telekom nie erfasst werden),
# mindestens TF_MIN_IPS verschiedene C2-Server hat und die Dichte (C2-IPs je
# Adresse) mindestens TF_MIN_DENSITY betraegt.
# TF_MODE = 'report': nur Kandidatenliste asn/threatfox_asn_kandidaten.txt
#                     schreiben, NICHT sperren (erst pruefen).
# TF_MODE = 'block':  Kandidaten zusaetzlich in die Sperrliste aufnehmen.
TF_MODE = 'block'   # Nutzerentscheidung 2026-11-15: direkt automatisch sperren
TF_IPS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'dns', 'threatfox_c2_ips.txt')
# Seit 2026-11-16 (Nutzerentscheidung): zweite Datenquelle fuer dieselbe
# Dichte-Auswertung - reputation_blacklist.txt im Repo-Hauptordner. Die legt
# update_combined_blacklist.yml taeglich aus der AbuseIPDB-API ab (Top 10.000,
# Score >= 50). Es werden KEINE zusaetzlichen API-Abfragen gemacht. Jede Quelle
# wird einzeln mit denselben Kriterien bewertet.
AB_IPS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'reputation_blacklist.txt')
# Seit 2026-11-16 abends (Nutzerentscheidung, bewusst ohne Filter):
# threat.live (rund 51.000 Einzel-IPs, taeglich) als dritte Dichte-Quelle.
# Wird direkt per URL geladen; faellt sie aus -> Warnung, Rest laeuft weiter.
TL_URL = 'https://list.threat.live/'
# Seit 2026-11-17 (Nutzerentscheidung, ohne Filter): dataplane.org - 17
# Signal-Listen (SSH, Telnet, VNC, SIP, DNS, NTP, SMTP, Proto41) mit rund
# 130.000 Angreifer-IPs. Format: "ASN | Name | IP | Zeit | Kategorie".
DP_URLS = tuple('https://dataplane.org/signals/%s.txt' % f for f in (
    'sshclient', 'sshpwauth', 'vncrfb', 'telnetlogin', 'dnsrd', 'dnsrdany', 'dnsversion', 'dnstcp',
    'smtpdata', 'smtpgreet', 'proto41', 'ntpmode3', 'ntpmode6', 'ntpmode7',
    'sipinvitation', 'sipquery', 'sipregistration'))
# honeypot_ips.txt wurde am 2026-11-17 kurz als Dichte-Quelle getestet und
# wieder entfernt: 2,15 Mio. IPs (v.a. infizierte Heimgeraete) ergaben 7.356
# zusaetzliche ASNs / 34 Mio. Adressen und haetten Minecraft-, Xbox/CoD- und
# GTA-Server getroffen. Fuer Einzel-IPs bleibt sie in der Combined-Liste.
# Seit 2026-11-18 (Nutzerentscheidung): 7 kleine Feeds aus dem Honeypot Monitor,
# die in der Vorauswertung nur wenige zusaetzliche ASNs brachten (zusammen ~50).
# Die grossen Feeds (ipblocklist_eu, ipinsights, configserverapps, kamalmjt)
# sind bewusst NICHT dabei - sie haetten tausende Heim-ISPs gesperrt.
IPV4_ANY_RE = re.compile(r'(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d./])')
HPF_URLS = (
    'https://api.tarpit.pro/v1/feed/blocklist.txt',
    'https://siberkapan.org/api/v1/list/txt',
    'https://api.carpathian.ai/public/threat-intel/blocklist.txt',
    'https://api.ismalicious.com/blocklist/download/blocklist-ips-critical.txt',
    'https://opendbl.net/lists/opendbl-darknet.list',
    'https://feeds.offseq.com/mirage-feed/latest/ipv4-30d.txt',
    'https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv',
)
# Seit 2026-11-18 (Nutzerwunsch): honigtopf_ips.txt im Repo-Hauptordner (vom
# Honigtopf-Workflow erstellt, bereits gegen die Whitelist gefiltert).
# NICHT verwechseln mit honeypot_ips.txt (2 Mio. IPs, am 17.11. wieder entfernt).
HT_IPS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'honigtopf_ips.txt')
# Seit 2026-11-18 (Nutzerwunsch): monatliche ASN-Risiko-Bewertung (Top 250),
# vom Honigtopf-Workflow als asn/asn_risiko.txt abgelegt (nur Nummern).
# Uebernommen werden (Nutzerentscheidung 2026-11-18):
#   - ALLE Netzbetreiber bis RISK_MAX_ADDR IPv4-Adressen (auch kleine Heim-ISPs)
#   - mittelgrosse bis RISK_MAX_HOSTER Adressen nur, wenn sie Hoster/VPS-Anbieter
#     sind: ipverse-Kategorie "hosting", InsightFlare-Hosting-Liste oder ein
#     Name mit HOST/VPS/SERVER/CLOUD/DATACENTER/DEDICATED/COLO
#     (seit 2026-11-20 zusaetzlich VDS/RDP/IDC/PROXY/BULLETPROOF, Nutzerwunsch;
#     VDS/RDP/IDC nur als ganzes Wort, damit z. B. "MIDCO" nicht trifft)
#   - nie die Netze aus RISK_NEVER (grosse Clouds/CDNs, Contabo = Minecraft-
#     Server, Starlink/FiberLink = GTA-Mitspieler, Scanner).
RISK_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         'asn', 'asn_risiko.txt')
RISK_MAX_ADDR = 65536
RISK_MAX_HOSTER = 1000000
RISK_HOSTING_URL = 'https://raw.githubusercontent.com/InsightFlare/asn-blocklist/main/dist/hosting.txt'
RISK_HOSTER_RE = re.compile(r'HOST|VPS|\bVDS\b|RDP(?![A-Z])|SERVER|CLOUD|DATA ?CENT|DEDI(?:C|PATH)|\bIDC\b'
                            r'|PROX(?:Y|IES)|BULLETPROOF|COLO(?!MBIA|R)', re.I)
RISK_NEVER = {13335, 14061, 58224, 63949, 197207, 51167, 14593, 6939, 56673, 22168, 393406,
              14789,   # Cloudflare (zweites Netz)
              52468}   # UFINET Panama - Transit fuer lateinamerikanische ISPs (GTA)


def load_risk():
    """ASN-Nummern aus asn/asn_risiko.txt: (liste, monat); ([], None) wenn nicht da."""
    if not os.path.exists(RISK_FILE):
        print('::warning::%s fehlt - ASN-Risiko uebersprungen' % RISK_FILE)
        return [], None
    with open(RISK_FILE, encoding='utf-8') as fh:
        txt = fh.read()
    m = re.search(r'^# Monat: ([^|\n]*)', txt, re.M)
    out = [int(l) for l in (x.strip() for x in txt.splitlines()) if l.isdigit()]
    return [a for a in out if 0 < a < 4200000000 and a not in RISK_NEVER], ((m.group(1).strip() if m else '') or 'Monat ?')


# Seit 2026-11-19 (Nutzerwunsch): FireHOL abusers_30d (Sammelliste mehrerer
# Missbrauchs-Feeds der letzten 30 Tage, ~170.000 IPs). Gezaehlt werden nur
# Einzel-IPs, keine CIDR-Bloecke. Test: +342 ASNs, ueberwiegend VPS-/Hoster.
FH_URLS = ('https://iplists.firehol.org/files/firehol_abusers_30d.netset',)
# Seit 2026-11-20 (Nutzerwunsch): cve_exploit_ips.txt im Repo-Hauptordner
# (CVE-to-IP-Mapper: Exploit- und C2-Server, ~30.000 IPs). Test: +16 ASNs,
# fast nur kleine Hoster, 0 NetFlow-Kontakte.
CVE_IPS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'cve_exploit_ips.txt')
# Seit 2026-11-21 (Nutzerwunsch): bitwire-it outbound (kuratierte Ziele fuer
# ausgehende Sperren: Malware/C2/Phishing, alle 2 h, ~97.000 Einzel-IPs).
# Test: +84 ASNs / 245.760 Adressen, ueberwiegend VPS-/Anonym-Hoster,
# 0 NetFlow-Kontakte. Gezaehlt werden nur Einzel-IPs (keine CIDR-Bloecke).
BW_URLS = ('https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt',)
# Seit 2026-11-21 (Nutzerwunsch): USOM (tuerkische Cyber-Behoerde, via
# Tagoletta-Spiegel, ~16.500 Einzel-IPs, stuendlich aktualisiert).
# Test: +33 ASNs / 107.008 Adressen, kleine Hoster/VPS, 0 NetFlow-Kontakte.
USOM_URLS = ('https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/full-ips.txt',)
# Netzbetreiber, die die Dichte-Auswertung NIE sperren darf (Kontakt eigener
# Geraete laut NetFlow bzw. wichtige Infrastruktur). Gilt fuer alle Dichte-Quellen.
DENSITY_NEVER = set()
DENSITY_SOURCES = (('ThreatFox C2-Dichte', TF_IPS_FILE), ('AbuseIPDB-Dichte', AB_IPS_FILE),
                   ('threat.live-Dichte', TL_URL), ('Dataplane-Dichte', DP_URLS),
                   ('Honeypot-Feeds-Dichte', HPF_URLS), ('Honigtopf-Dichte', HT_IPS_FILE),
                   ('FireHOL-Abusers-Dichte', FH_URLS), ('CVE-Exploit-Dichte', CVE_IPS_FILE),
                   ('Bitwire-Outbound-Dichte', BW_URLS), ('USOM-Dichte', USOM_URLS))
TF_ASNDB_URLS = ('https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv4.csv',
                 'https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-asn/dbip-asn-ipv4.csv')
# 2026-11-18 (Nutzerentscheidung): von 65.536 auf 1.000.000 erhoeht. Test: nur
# +6 ASNs / +1 Mio. Adressen, 0 Kontakte in 10 Tagen NetFlow. Grosse Clouds und
# Provider (Amazon, Microsoft, Hetzner, Telekom ... je viele Mio.) bleiben aussen vor.
TF_MAX_ADDR = 1000000
TF_MIN_IPS = 5
TF_MIN_DENSITY = 0.0025   # mind. 1 C2-Server je 400 Adressen


def threatfox_candidates():
    """{asn: (name, ips, adressen, dichte, quelle)} aus allen DENSITY_SOURCES - {} wenn Daten fehlen."""
    sources = []
    for label, path in DENSITY_SOURCES:
        if isinstance(path, tuple):
            # mehrere URLs: Dataplane-Format "ASN | Name | IP | ..." oder
            # einfache Listen/CSV (erste IPv4-Adresse der Zeile)
            lines, ok = [], 0
            for u in path:
                try:
                    for l in fetch(u, timeout=120).splitlines():
                        if not l.strip() or l.lstrip().startswith(('#', ';', '//')):
                            continue
                        if '|' in l:
                            p = [x.strip() for x in l.split('|')]
                            if len(p) >= 3:
                                lines.append(p[2])
                        else:
                            m = IPV4_ANY_RE.search(l)
                            if m:
                                lines.append(m.group(1))
                    ok += 1
                except Exception as e:
                    print('::warning::%s nicht ladbar (%s)' % (u, e))
            if not ok:
                print('::warning::%s: keine Liste ladbar - uebersprungen' % label)
                continue
            sources.append((label, lines))
            continue
        if path.startswith('http'):
            try:
                lines = fetch(path, timeout=120).splitlines()
            except Exception as e:
                print('::warning::%s nicht ladbar (%s) - %s uebersprungen' % (path, e, label))
                continue
        elif not os.path.exists(path):
            print('::warning::%s fehlt - %s uebersprungen' % (path, label))
            continue
        else:
            with open(path, encoding='utf-8') as handle:
                lines = handle.read().splitlines()
        sources.append((label, [l.split('#')[0].strip() for l in lines
                                if l.strip() and not l.lstrip().startswith('#')]))
    if not sources:
        return {}
    db = None
    for url in TF_ASNDB_URLS:
        try:
            db = fetch(url, timeout=120)
            break
        except Exception as e:
            print('::warning::ASN-Datenbank %s nicht ladbar (%s)' % (url, e))
    if not db:
        print('::warning::keine ASN-Datenbank erreichbar - ThreatFox-Auswertung uebersprungen')
        return {}
    import bisect
    iv, size, name = [], {}, {}
    for r in csv.reader(io.StringIO(db)):
        try:
            a = int(ipaddress.ip_address(r[0])); b = int(ipaddress.ip_address(r[1])); s = int(r[2])
        except (ValueError, IndexError):
            continue
        iv.append((a, b, s)); size[s] = size.get(s, 0) + (b - a + 1); name[s] = r[3] if len(r) > 3 else ''
    iv.sort(); starts = [x[0] for x in iv]
    out = {}
    for label, ips in sources:
        hits = {}
        for ip in ips:
            try:
                a = int(ipaddress.ip_address(ip))
            except ValueError:
                continue
            i = bisect.bisect_right(starts, a) - 1
            if i >= 0 and iv[i][0] <= a <= iv[i][1]:
                hits.setdefault(iv[i][2], set()).add(ip)
        found = 0
        for s, h in hits.items():
            n, sz = len(h), size.get(s, 0)
            if s in DENSITY_NEVER:
                continue
            if sz and sz <= TF_MAX_ADDR and n >= TF_MIN_IPS and n / sz >= TF_MIN_DENSITY:
                found += 1
                if s not in out or n / sz > out[s][3]:
                    out[s] = (name.get(s, ''), n, sz, n / sz, label)
        print('%s: %d IPs in %d Netzbetreibern -> %d Kandidaten (<= %d Adressen, >= %d IPs, Dichte >= %.2f%%)'
              % (label, len(ips), len(hits), found, TF_MAX_ADDR, TF_MIN_IPS, TF_MIN_DENSITY * 100))
    return out


MANUAL_ASNS = {
    198075: 'BounceZero Ltd', 270353: 'Tyna Host', 60567: 'SIA RixHost',
    203557: 'SIA RixHost', 48721: 'Flyservers S.A.', 197194: 'Kayan Establishment',
    208690: 'JeskeSolutions LTDA', 272547: 'Servicos de Infraestrutura e Datacenter',
    48874: 'HOSTMAZE INC SRL-D', 40861: 'Paradise Networks LLC',
    215929: 'Data Campus Limited', 212512: 'Detai Prosperous Technologies',
    61254: 'ESTOXY OU', 214218: 'PE Mironova Lyudmila', 64107: 'RACK SPHERE HOSTING',
    401739: 'RedLuff LLC',
    # 2026-11-17 (Nutzerwunsch): niederlaendische Hoster, dauerhaft gesperrt.
    # Die IP-Bereiche werden bei jedem Lauf neu ueber ipverse aufgeloest.
    49305: 'Alsycon B.V.', 39572: 'DataWeb Global Group B.V.',
    # 2026-11-18 (Nutzerwunsch): US-Hoster mit viel Missbrauch, bisher nur ueber
    # Maltrail drin - fest, damit er bleibt (USA kann per GeoIP nicht gesperrt werden).
    19318: 'Interserver, Inc',
}


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

    bw, bw_date = load_bph_watch()
    bw_new = {a: n for a, n in bw.items() if a not in asns}
    for a, name in bw_new.items():
        asns[a] = {'asn': a, 'cc': '', 'asname': name, 'domain': 'Bulletproof Hosting Watch %s' % bw_date}
    print('Bulletproof Hosting Watch (%s): %d ASNs | davon neu: %d' % (bw_date, len(bw), len(bw_new)))

    man_new = {a: n for a, n in MANUAL_ASNS.items() if a not in asns}
    for a, name in man_new.items():
        asns[a] = {'asn': a, 'cc': '', 'asname': name, 'domain': 'feste eigene Liste'}
    print('Feste eigene Liste: %d ASNs | davon neu: %d' % (len(MANUAL_ASNS), len(man_new)))


    tf = threatfox_candidates()
    tf_new = {a: v for a, v in tf.items() if a not in asns}
    if tf:
        lines = ['# NETSHIELD - Netzbetreiber mit auffaellig vielen ThreatFox-C2-Servern / AbuseIPDB-IPs',
                 '# Modus: %s (report = nur Liste, block = wird mitgesperrt)' % TF_MODE,
                 '# Kriterien je Quelle: <= %d Adressen, >= %d IPs, Dichte >= %.2f%%' % (TF_MAX_ADDR, TF_MIN_IPS, TF_MIN_DENSITY * 100),
                 '# Spalten: ASN | IPs | Adressen | Dichte | schon gesperrt | Name | Quelle', '']
        for a, (nm, n, sz, d, why) in sorted(tf.items(), key=lambda x: -x[1][3]):
            lines.append('AS%d\t%d\t%d\t%.2f%%\t%s\t%s\t%s' % (a, n, sz, d * 100, 'ja' if a in asns else 'nein', nm, why))
        tmp = os.path.join(OUT_DIR, 'threatfox_asn_kandidaten.txt.tmp')
        with open(tmp, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        os.replace(tmp, os.path.join(OUT_DIR, 'threatfox_asn_kandidaten.txt'))
        print('Dichte-Kandidaten: %d (davon noch nicht gesperrt: %d, ThreatFox %d / AbuseIPDB %d / threat.live %d'
              ' / Dataplane %d / Honeypot-Feeds %d / Honigtopf %d / FireHOL %d / CVE-Exploit %d / Bitwire %d) -> asn/threatfox_asn_kandidaten.txt'
              % (len(tf), len(tf_new), sum(1 for v in tf_new.values() if v[4].startswith('ThreatFox')),
                 sum(1 for v in tf_new.values() if v[4].startswith('AbuseIPDB')),
                 sum(1 for v in tf_new.values() if v[4].startswith('threat.live')),
                 sum(1 for v in tf_new.values() if v[4].startswith('Dataplane')),
                 sum(1 for v in tf_new.values() if v[4].startswith('Honeypot-Feeds')),
                 sum(1 for v in tf_new.values() if v[4].startswith('Honigtopf')),
                 sum(1 for v in tf_new.values() if v[4].startswith('FireHOL')),
                 sum(1 for v in tf_new.values() if v[4].startswith('CVE-Exploit')),
                 sum(1 for v in tf_new.values() if v[4].startswith('Bitwire'))))
    # Haltezeit (seit 2026-11-18): Netzbetreiber aus der Dichte-Auswertung bleiben
    # HOLD_DAYS Tage nach ihrem letzten Auftauchen gesperrt - auch wenn eine Quelle
    # kurz ausfaellt oder der Taeter ein paar Tage still ist. Zustand liegt in
    # asn/asn_dichte_haltezeit.json (wird vom Workflow mit committet).
    today = datetime.date.today()
    state = {}
    if os.path.exists(HOLD_FILE):
        try:
            with open(HOLD_FILE, encoding='utf-8') as fh:
                state = json.load(fh)
        except (OSError, ValueError) as e:
            print('::warning::Haltezeit-Datei unlesbar (%s) - beginne neu' % e)
            state = {}
    for a, (nm, n, sz, d, why) in tf.items():
        state[str(a)] = {'name': nm, 'why': why, 'density': round(d * 100, 2), 'last_seen': today.isoformat()}
    held = {}
    for k in list(state):
        e = state[k]
        try:
            age = (today - datetime.date.fromisoformat(e.get('last_seen', ''))).days
        except ValueError:
            age = HOLD_DAYS + 1
        if age > HOLD_DAYS:
            del state[k]
            continue
        a = int(k)
        if a not in tf and a not in asns:
            held[a] = (e, age)
    tmp = HOLD_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(state, fh, indent=0, sort_keys=True)
    os.replace(tmp, HOLD_FILE)
    print('Haltezeit %d Tage: %d Netzbetreiber gemerkt, davon %d nur noch ueber die Haltezeit gesperrt'
          % (HOLD_DAYS, len(state), len(held)))

    if TF_MODE == 'block':
        for a, (nm, n, sz, d, why) in tf_new.items():
            asns[a] = {'asn': a, 'cc': '', 'asname': nm, 'domain': '%s %.2f%%' % (why, d * 100)}
        for a, (e, age) in held.items():
            asns[a] = {'asn': a, 'cc': '', 'asname': e.get('name', ''),
                       'domain': '%s (Haltezeit, zuletzt auffaellig %s)' % (e.get('why', ''), e.get('last_seen', ''))}
        tf_new = {**tf_new, **{a: None for a in held}}
    else:
        tf_new = {}
    # ASN-Risiko zuletzt: steht ein ASN schon ueber eine andere Quelle drin,
    # gelten deren Regeln (keine Groessengrenze aus RISK_MAX_ADDR)
    risk, risk_month = load_risk()
    risk_new = {a for a in risk if a not in asns}
    for a in risk_new:
        asns[a] = {'asn': a, 'cc': '', 'asname': '', 'domain': 'ASN-Risiko %s' % risk_month}
    print('ASN-Risiko (%s): %d ASNs | davon noch nicht gesperrt: %d (Groessenpruefung nach Aufloesung)'
          % (risk_month, len(risk), len(risk_new)))

    meta_info = {}   # asn -> ipverse-metadata (Kategorie, Name) fuer die Hoster-Pruefung

    def resolve(asn):
        # 1. ipverse (CC0, BGP-Daten); 2. Ersatz: RIPEstat announced-prefixes
        try:
            txt = fetch(IPVERSE_URL % asn)
            js = json.loads(txt) if txt else {}
            meta_info[asn] = js.get('metadata') or {}
            return asn, js.get('prefixes', {}), None
        except Exception as e:
            err = str(e)
        try:
            data = json.loads(fetch(RIPESTAT_URL % asn, timeout=60, tries=2)).get('data', {})
            pref = {'ipv4': [], 'ipv6': []}
            for p in data.get('prefixes', []):
                pfx = p.get('prefix', '')
                pref['ipv6' if ':' in pfx else 'ipv4'].append(pfx)
            return asn, pref, 'ripestat'
        except Exception as e2:
            return asn, None, '%s / RIPEstat: %s' % (err, e2)

    with ThreadPoolExecutor(8) as ex:
        results = list(ex.map(resolve, sorted(asns)))
    via_ripe = [a for a, p, err in results if p is not None and err == 'ripestat']
    if via_ripe:
        print('::warning::%d ASNs ueber RIPEstat statt ipverse aufgeloest: %s' % (len(via_ripe), via_ripe[:20]))

    failed = [a for a, p, err in results if p is None]
    if len(failed) > MAX_FAIL_RATIO * len(asns):
        print('::error::%d von %d ipverse-Abrufen fehlgeschlagen - behalte bestehende Dateien' % (len(failed), len(asns)))
        return 1
    if failed:
        print('::warning::%d ipverse-Abrufe fehlgeschlagen: %s' % (len(failed), failed[:20]))

    # ASN-Risiko: kleine immer, mittelgrosse nur als Hoster
    hosting_list = set()
    try:
        hosting_list = {int(m) for m in re.findall(r'AS(\d+)', fetch(RISK_HOSTING_URL))}
    except Exception as e:
        print('::warning::Hosting-Liste nicht ladbar (%s) - nur ipverse-Kategorie und Name' % e)
    risk_big, risk_hoster = [], []
    for asn, pref, err in results:
        if asn in risk_new and pref:
            sz = 0
            for p in pref.get('ipv4', []):
                try:
                    sz += ipaddress.ip_network(p, strict=False).num_addresses
                except ValueError:
                    # ungueltiger Prefix aus ipverse/RIPEstat: zaehlt nicht zur Groesse
                    print('::warning::AS%d: ungueltiger Prefix %r uebersprungen' % (asn, p))
            if sz <= RISK_MAX_ADDR:
                continue
            md = meta_info.get(asn, {})
            nm = '%s %s' % (md.get('handle', ''), md.get('description', ''))
            hoster = (md.get('category') == 'hosting' or asn in hosting_list
                      or bool(RISK_HOSTER_RE.search(nm)))
            if hoster and sz <= RISK_MAX_HOSTER:
                risk_hoster.append(asn)
                asns[asn]['asname'] = ''
                asns[asn]['domain'] += ' (Hoster, %d Adressen)' % sz
            else:
                risk_big.append(asn)
    for a in risk_big:
        del asns[a]
        risk_new.discard(a)
    results = [r for r in results if r[0] in asns]
    print('ASN-Risiko: %d mittelgrosse Hoster uebernommen (%s), %d zu gross/kein Hoster ausgelassen -> %d neu gesperrt'
          % (len(risk_hoster), ','.join(map(str, risk_hoster)), len(risk_big), len(risk_new)))

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
            '# Zusatz-ASNs: %s (Bulletproof Hosting Watch, Bericht %s)\n'
            '# Quelle Netze: github.com/ipverse/as-ip-blocks (CC0)\n'
            '# Aktualisiert: %s | ASNs: %d (Spamhaus %d + BPH %d + Maltrail %d + BPH-Watch %d + eigene %d'
            ' + Dichte ThreatFox/AbuseIPDB/threat.live/Dataplane/Honeypot-Feeds/Honigtopf/FireHOL/CVE-Exploit/Bitwire %d + ASN-Risiko %d, aktiv: %d)\n'
            % (SPAMHAUS_URL, meta.get('timestamp'), BPH_URL, MALTRAIL_URL, BPHW_INDEX, bw_date, now, len(asns),
               n_spamhaus, len(bph_new), len(mt_new), len(bw_new), len(man_new), len(tf_new), len(risk_new), active))

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
