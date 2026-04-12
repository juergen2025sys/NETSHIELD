import ipaddress, json, os, re, sys, urllib.request
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

# orjson: im vorherigen Step per pip installiert, 5-10x schneller als stdlib json
try:
    import orjson as _orjson
    def _db_load(path):
        with open(path, "rb") as _f: return _orjson.loads(_f.read())
    def _db_dump(db, path):
        with open(path, "wb") as _f: _f.write(_orjson.dumps(db))
    print("JSON-Backend: orjson")
except ImportError:
    def _db_load(path):
        with open(path, encoding="utf-8") as _f: return json.load(_f)
    def _db_dump(db, path):
        with open(path, "w", encoding="utf-8") as _f:
            json.dump(db, _f, separators=(",", ":"))
    print("JSON-Backend: stdlib json (Fallback)")

now        = datetime.now(timezone.utc)
now_day    = now.strftime("%Y-%m-%d")
now_stamp  = now.strftime("%Y-%m-%d %H:%M UTC")
EXPIRY_DAYS = 180
DB_FILE     = "seen_db.json"
READ_LIMIT  = 25 * 1024 * 1024   # 25 MB pro Feed

IPV4_RE = re.compile(r'(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)')

DNS_WHITELIST = {
    "192.168.13.1", "192.168.14.1",
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "208.67.222.222", "208.67.220.220", "9.9.9.9",
    "149.112.112.112", "149.112.112.10", "149.112.112.11",
    "94.140.14.14", "94.140.15.15",
}

# ── Whitelist: IPs/CIDRs die NIE auf die Blacklist kommen ─────────
# Spiegelidentisch mit false_positive_checker.yml – hier gefiltert
# beim seen_db-Eintrag, damit sie gar nicht erst aufgenommen werden.
# Änderungen immer in BEIDEN Dateien synchron halten.
# ── Whitelist: IPs/CIDRs die NIE auf die Blacklist kommen ─────────
# Single Source of Truth: whitelist.json (synchron mit false_positive_checker)
with open(".github/workflows/whitelist.json", encoding="utf-8") as _wl_f:
    WHITELIST_ENTRIES = json.load(_wl_f)["entries"]

_whitelist_networks = []
for _entry in list(WHITELIST_ENTRIES):
    try:
        _whitelist_networks.append(ipaddress.ip_network(_entry, strict=False))
    except Exception:
        pass

def is_whitelisted(ip_str):
    """True wenn IP in einer der Whitelist-Ranges liegt (IPs + CIDRs)."""
    try:
        addr = ipaddress.ip_address(ip_str.split('/')[0])
        return any(addr in net for net in _whitelist_networks)
    except Exception:
        return False

PROTECTED_CIDRS = [
    "192.168.13.0/24", "192.168.14.0/24",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
]
_protected_networks = []
for _entry in (list(DNS_WHITELIST) + PROTECTED_CIDRS):
    try:
        _protected_networks.append(ipaddress.ip_network(_entry, strict=False))
    except Exception:
        pass

def is_protected_entry(value):
    """True wenn eine IP/ein CIDR niemals in Listen landen darf."""
    try:
        candidate = value.strip()
        if not candidate:
            return True
        if '/' in candidate:
            net = ipaddress.ip_network(candidate, strict=False)
            if net.version != 4 or net.prefixlen < 8:
                return True
            if (net.is_private or net.is_loopback or net.is_multicast or
                net.is_reserved or net.is_link_local or net.is_unspecified):
                return True
            return any(net.overlaps(protected) for protected in _protected_networks)
        addr = ipaddress.ip_address(candidate)
        if addr.version != 4:
            return True
        if (addr.is_private or addr.is_loopback or addr.is_multicast or
            addr.is_reserved or addr.is_link_local or addr.is_unspecified):
            return True
        return any(addr in protected for protected in _protected_networks)
    except Exception:
        return True

HIGH_QUALITY = {
    "cinsscore", "cinsarmy", "greensnow", "feodo_aggressive", "feodo_recommended",
    "threatfox_ioc", "binary_defense", "crowdsec_ssh",
    "danger_bruteforce", "threatview_high_conf", "firehol_cybercrime",
    "firehol_anonymous", "dshield", "cloudzy",
    "urlhaus_ips", "firehol_level1", "firehol_level2", "firehol_level3",
    "firehol_webclient", "firehol_webserver", "firehol_proxies", "firehol_abusers_1d",
    "et_block", "et_compromised", "spamhaus_drop",
    "blocklist_de_all", "blocklist_de_export", "blocklist_de_strongips",
    "blocklist_de_ssh", "c2_tracker", "c2_iplist",
    "ipsum_level5", "ipsum_level7", "abuseipdb_s100_30d", "abuseipdb_s100_7d",
    "abuseipdb_score100", "turris_greylist",
    # FIX BUG-DP1: DataPlane-Feeds hatten hq=True in SOURCES, fehlten aber
    # in HIGH_QUALITY. Effekt: ip_in_hq wurde nie befüllt → strongly_confirmed_today
    # blieb False → das "last"-Feld wurde nie aktualisiert → IPs alterten still
    # nach 180 Tagen aus, obwohl DataPlane sie täglich frisch liefert.
    # Alle 8 DataPlane-Feeds hier ergänzt, damit sie wieder HQ-Semantik erhalten.
    "dataplane_sshclient", "dataplane_sshpwauth", "dataplane_vncrfb",
    "dataplane_telnetlogin", "dataplane_dnsrd", "dataplane_smtpdata",
    "dataplane_dnsrdany", "dataplane_dnsversion",
}

# ══════════════════════════════════════════════════════════════════
# SOURCES – erweitert um die vom User gelieferten Links
# Format: "name": ("url", hq_bool)
# ══════════════════════════════════════════════════════════════════
SOURCES = {
    # ── Kern-Feeds ────────────────────────────────────────────────
    "cinsscore":                  ("https://cinsscore.com/list/ci-badguys.txt", True),
    "cinsarmy":                   ("https://cinsarmy.com/list/ci-badguys.txt", True),
    "greensnow":                  ("https://blocklist.greensnow.co/greensnow.txt", True),
    "feodo_aggressive":           ("https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt", True),
    "feodo_recommended":          ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", True),
    "threatfox_ioc":              ("https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/refs/heads/main/ips.txt", True),
    "l7_ddos":                    ("https://raw.githubusercontent.com/Tizian-Maxime-Weigt/L7-HTTP-DDoS-Flood-IP-Signature-IP-List/refs/heads/main/ddos-signatures.txt", False),  # Einzelperson-Repo, kein verifizierter Betreiber
    "binary_defense":             ("https://binarydefense.com/banlist.txt", True),
    "data_shield":                ("https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt", False),  # Einzelperson-Repo, kein verifizierter Betreiber
    "interserver":                ("https://sigs.interserver.net/ip.txt", False),
    "crowdsec_ssh":               ("https://raw.githubusercontent.com/Y3ll0w/CrowdSec-CAPI-Decisions/refs/heads/main/ssh-bf.json.txt", True),
    "trcert_malware":             ("https://raw.githubusercontent.com/cenk/trcert-malware/refs/heads/main/trcert-ips.txt", False),  # Einzelperson-Repo, kein verifizierter Betreiber
    "danger_bruteforce":          ("https://danger.rulez.sk/projects/bruteforceblocker/blist.php", True),
    "threatview_high_conf":       ("https://threatview.io/Downloads/IP-High-Confidence-Feed.txt", True),
    "florent_banned":             ("https://raw.githubusercontent.com/florentvinai/bad-ips-on-my-vps/refs/heads/main/banned_ips.txt", False),
    "firehol_cybercrime":         ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/cybercrime.ipset", True),
    "firehol_anonymous":          ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset", True),
    "dshield":                    ("https://www.dshield.org/block.txt", True),
    "cloudzy":                    ("https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/cloudzy.txt", True),
    "bbcan177":                   ("https://gist.githubusercontent.com/BBcan177/d7105c242f17f4498f81/raw", False),
    "kevinmarx":                  ("https://kevinmarx.org/malicious-ip-list.txt", False),
    # "honeypot_blocklist" entfernt: yuexuana521/honeypot-blocklist Repo gelöscht
    "edanwong":                   ("https://raw.githubusercontent.com/EdanWong/ip_list/refs/heads/main/my_ips.txt", False),
    "nixbear_malicious":          ("https://raw.githubusercontent.com/nixbear/malicious_ips/refs/heads/main/malicious_ips.txt", False),
    "ufukart_blacklist":          ("https://raw.githubusercontent.com/ufukart/Blacklist/main/blacklist.txt", False),
    "f3csystems":                 ("https://raw.githubusercontent.com/f3csystems/BlockList_IP/refs/heads/main/blacklist.txt", False),
    "fortigate_azure":            ("https://raw.githubusercontent.com/IT3ngineer/FortigateBlockList/refs/heads/main/AzureBlockListIPs.txt", False),
    "romainmarcoux_aa":           ("https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-300k-aa.txt", False),
    "romainmarcoux_ab":           ("https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-300k-ab.txt", False),
    # "romainmarcoux_ac" entfernt: full-300k-ac.txt existiert nicht mehr (HTTP 200, leerer Body)
    "4ip_high_security":          ("https://raw.githubusercontent.com/4IP-Solutions/threat-feeds/refs/heads/main/blocklist-incoming-ip-high-security.txt", False),
    "cyna_malicious":             ("https://raw.githubusercontent.com/cybersecurity-cyna/Malicious_IP/refs/heads/main/ip-list.txt", False),
    "black_mirror":               ("https://github.com/T145/black-mirror/releases/download/latest/BLOCK_IPV4.txt", False),
    # "alienvault" entfernt: OTX/AlienVault laut Ausschluss-Policy deaktiviert
    "bitwire_ipblocklist":        ("https://raw.githubusercontent.com/bitwire-it/ipblocklist/refs/heads/main/inbound.txt", False),
    "littlejake_all_blacklist":   ("https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/all_blacklist.txt", False),
    "shadowwhisperer_hackers":    ("https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Malware/Hackers", False),
    "netmountains_blocklist":     ("https://raw.githubusercontent.com/NETMOUNTAINS/Curated-IP-Blocklist/main/ip-blacklist.list", False),  # Community-Repo, kein verifizierter Betreiber
    "bluetack_blacklist":         ("https://raw.githubusercontent.com/actuallymentor/bluetack-ip-blacklist-generator/refs/heads/master/blacklist", False),
    "rtbh_output":                ("https://list.rtbh.com.tr/output.txt", False),
    "sefinek_malicious":          ("https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt", False),
    "magicteamc_bad_ips":         ("https://raw.githubusercontent.com/MagicTeaMC/bad-ips/refs/heads/main/bad-ips.txt", False),
    "ddrimus_http_threats":       ("https://raw.githubusercontent.com/ddrimus/http-threat-blocklist/refs/heads/main/blocklist.txt", False),
    "blacksnowdot_packets":       ("https://raw.githubusercontent.com/BlacKSnowDot0/packetsdatabase-db/refs/heads/main/ip_list.txt", False),
    "freakuency_threatfeed":      ("https://raw.githubusercontent.com/FreakuencyFive/Public-IP-ThreatFeed/refs/heads/main/blacklist.txt", False),
    "ultimate_hosts_ips0":        ("https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/refs/heads/master/ips/ips0.list", False),
    "amitambekar_threats":        ("https://raw.githubusercontent.com/amitambekar510/Malicious-IP-Threat-List/refs/heads/main/Malicious-IP-Threat-List.txt", False),
    "amitambekar_threats_aa":     ("https://raw.githubusercontent.com/amitambekar510/Malicious-IP-Threat-List/main/Malicious-IP-Threat-List_aa", False),
    "dolutech_blacklist":         ("https://raw.githubusercontent.com/dolutech/blacklist-dolutech/refs/heads/main/Black-list-semanal-dolutech.txt", False),
    "zerof_ipextractor":          ("https://raw.githubusercontent.com/ZEROF/ipextractor/refs/heads/main/ipexdbl.txt", False),
    "subnet_blocklist_new":       ("https://raw.githubusercontent.com/coyote-nl/blocklist/refs/heads/main/subnet-blocklist-new", False),
    "bdix_prefix_ipv4":           ("https://raw.githubusercontent.com/tushroy/bdix-isp-blocks/refs/heads/master/bdix-prefix_ipv4.txt", False),

    # ── Abuse.ch ──────────────────────────────────────────────────
    # bazaar_c2 entfernt: Endpunkt liefert Hash-Listen, keine IPs → 0 Treffer
    "urlhaus_ips":                ("https://urlhaus.abuse.ch/downloads/text/", True),

    # ── FireHOL & Emerging Threats ────────────────────────────────
    "firehol_level1":             ("https://iplists.firehol.org/files/firehol_level1.netset", True),
    "firehol_level2":             ("https://iplists.firehol.org/files/firehol_level2.netset", True),
    "firehol_level3":             ("https://iplists.firehol.org/files/firehol_level3.netset", True),
    "firehol_level4":             ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level4.netset", False),
    "firehol_webclient":          ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset", True),
    "firehol_webserver":          ("https://iplists.firehol.org/files/firehol_webserver.netset", True),
    "firehol_proxies":            ("https://iplists.firehol.org/files/firehol_proxies.netset", True),
    "firehol_abusers_1d":         ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_abusers_1d.netset", True),
    "et_block":                   ("https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", True),
    "et_compromised":             ("https://rules.emergingthreats.net/blockrules/compromised-ips.txt", True),
    "spamhaus_drop":              ("https://www.spamhaus.org/drop/drop.txt", True),
    # "spamhaus_edrop" entfernt: seit 10.04.2024 in DROP konsolidiert, edrop.txt ist leer
    "blocklist_de_all":           ("https://lists.blocklist.de/lists/all.txt", True),
    "blocklist_de_export":        ("https://www.blocklist.de/downloads/export-ips_all.txt", True),
    "blocklist_de_strongips":     ("https://lists.blocklist.de/lists/strongips.txt", True),
    "blocklist_de_getlast":       ("https://api.blocklist.de/getlast.php?time=43200", False),
    "blocklist_de_ssh":           ("https://lists.blocklist.de/lists/ssh.txt", True),
    "blocklist_de_mail":          ("https://lists.blocklist.de/lists/mail.txt", False),
    "blocklist_de_apache":        ("https://lists.blocklist.de/lists/apache.txt", False),
    "blocklist_de_imap":          ("https://lists.blocklist.de/lists/imap.txt", False),
    "blocklist_de_ftp":           ("https://lists.blocklist.de/lists/ftp.txt", False),

    # ── C2 / Botnet ───────────────────────────────────────────────
    "c2_tracker":                 ("https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt", True),
    "c2_iplist":                  ("https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv", True),
    # "cobalt_strike_ips" entfernt: Gi7w0rm/CobaltStrikeC2Tracker Repo gelöscht – C2 abgedeckt durch c2_tracker

    # ── SSH / Brute-Force ─────────────────────────────────────────
    "stopforumspam_toxic":        ("https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt", False),

    # ── Honeypot / Sensor Networks ───────────────────────────────
    # DataPlane.org – betriebenes Sensor/Honeypot-Netzwerk
    # Erfasst echte Angriffe auf SSH, VNC, Telnet, DNS, SMTP u.a.
    # Format: ASN | ASname | ipaddr | lastseen | category
    # parse_entries() extrahiert IPs korrekt per Fallback-Regex.
    # Kein API-Key, freie nicht-kommerzielle Nutzung.
    "dataplane_sshclient":        ("https://dataplane.org/sshclient.txt", True),
    "dataplane_sshpwauth":        ("https://dataplane.org/sshpwauth.txt", True),
    "dataplane_vncrfb":           ("https://dataplane.org/vncrfb.txt", True),
    "dataplane_telnetlogin":      ("https://dataplane.org/telnetlogin.txt", True),
    "dataplane_dnsrd":            ("https://dataplane.org/dnsrd.txt", True),
    "dataplane_smtpdata":         ("https://dataplane.org/smtpdata.txt", True),
    "dataplane_smtpgreet":        ("https://dataplane.org/smtpgreet.txt", False),
    # smtpgreet: HQ=False – enthält auch harmlose SMTP-Scanner/Surveyor-IPs
    "dataplane_dnsrdany":         ("https://dataplane.org/dnsrdany.txt", True),
    "dataplane_dnsversion":       ("https://dataplane.org/dnsversion.txt", True),

    # ThreatHive – Community-Honeypot-Netzwerk, 146k+ IPs, alle 15 Min aktualisiert.
    # Plain-Text-Feed, kein API-Key, kein Rate-Limit.
    "threathive_blocklist":       ("https://threathive.net/hiveblocklist.txt", False),

    # ── Scanning / Recon ──────────────────────────────────────────
    "ipsum_level3":               ("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", False),
    "ipsum_level5":               ("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt", True),
    "ipsum_level7":               ("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt", True),
    "ipsum_master":               ("https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt", False),
    # "shodan_scanners" entfernt: jgamblin/Shodan-Malware-Scanning-IPs Repo gelöscht – Shodan via binaryedge_scanners
    "binaryedge_scanners":        ("https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt", False),
    # "normshield_ssh" entfernt: normshield_all_ssh.ipset bei firehol nicht mehr verfügbar

    # ── Spam / Phishing ───────────────────────────────────────────
    # "spamhaus_pbl" entfernt: elliotwutingfeng/Spamhaus-DNSBL-IPs pbl-aggressive.txt → HTTP 404
    # "phishing_army" entfernt: enthält Domains, keine IPs → liefert immer 0 IPs
    # "openphish" entfernt: liefert URLs, keine IPs → immer 0 nutzbare Einträge
    "pgl_yoyo_adservers":         ("https://pgl.yoyo.org/adservers/iplist.php?format=&showintro=0", False),

    # ── AbuseIPDB ─────────────────────────────────────────────────
    "abuseipdb_s100_30d":         ("https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-30d.ipv4", True),
    "abuseipdb_s100_7d":          ("https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-7d.ipv4", True),  # ersetzt abuseipdb_s90_30d
    "abuseipdb_tmiland":          ("https://abuseipdb.tmiland.com/abuseipdb.txt", False),
    "abuseipdb_score75":          ("https://raw.githubusercontent.com/LittleJake/ip-blacklist/refs/heads/main/abuseipdb_blacklist_ip_score_75.txt", False),
    "abuseipdb_score100":         ("https://raw.githubusercontent.com/LittleJake/ip-blacklist/refs/heads/main/abuseipdb_blacklist_ip_score_100.txt", True),
    "abuseipdb_scriptzteam":      ("https://raw.githubusercontent.com/scriptzteam/AbuseIPDB-BlackList/refs/heads/main/abuseipdb_blacklist.txt", False),
    "abuseipdb_axllent":          ("https://raw.githubusercontent.com/axllent/iplists/master/lists/abuseipdb-30d.txt", False),

    # ── Community / GitHub ────────────────────────────────────────
    # "mrlooker_threats" entfernt: mrlooker/Suspicious-IPs Repo gelöscht
    # "gridinsoft" entfernt: GridinSoft/IP-Blocklist Repo gelöscht
    # "duggytuxy_agr" entfernt: Dateiname geändert – abgedeckt durch data_shield (gleiches Repo-Netz)
    "turris_greylist":            ("https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv", True),
    # "talos_intelligence" entfernt: URL zu snort.org umgezogen, Terms-Accept required – nicht automatisierbar
    # "eset_apr" entfernt: elliotwutingfeng/ESET-APR-IPs Repo gelöscht
    "romainmarcoux_outgoing_aa":  ("https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/main/full-outgoing-ip-aa.txt", False),
    "romainmarcoux_outgoing_ab":  ("https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/main/full-outgoing-ip-ab.txt", False),
    # "fullbogons_ipv4" entfernt: team-cymru.org/fullbogons-ipv4.txt enthält ausschließlich
    # Bogon-Ranges (nicht-routbar/reserviert) – is_valid_public_ipv4() filtert 100% heraus
    # → 0 nutzbare IPs, ~3 MB sinnloser Download pro Lauf (analog zu honeypot_monitor.yml)

    # ── Tor Exit Nodes ────────────────────────────────────────────
    # tor_* entfernt: tor_exit_monitor Workflow wurde entfernt
}

# ── seen_db laden ──────────────────────────────────────────────────
db = {}
if os.path.exists(DB_FILE):
    try:
        import time as _t; _t0 = _t.monotonic()
        _db_mb = os.path.getsize(DB_FILE) / 1024 / 1024
        print(f"seen_db laden: {_db_mb:.1f} MB ...")
        db = _db_load(DB_FILE)
        print(f"seen_db geladen: {len(db)} IPs in {_t.monotonic()-_t0:.1f}s")
    except Exception as _e:
        print(f"WARNUNG: seen_db nicht lesbar ({_e}) – starte neu.")
        db = {}
else:
    print("Keine seen_db gefunden – starte neu.")

# ── FIX #1: false_positives_set.json einlesen ─────────────────────
# false_positive_checker schreibt diese Datei; combined liest sie hier
# und schließt die IPs beim Feed-Ingest aus – kein direktes Schreiben
# in combined_threat_blacklist_ipv4.txt durch den FP-Checker mehr.
FP_SET_FILE = "false_positives_set.json"
_fp_networks = []
_fp_ips      = set()
if os.path.exists(FP_SET_FILE):
    try:
        with open(FP_SET_FILE) as _f:
            _fp_data = json.load(_f)
        for _e in _fp_data.get("ips", []):
            try:
                if "/" in _e:
                    _fp_networks.append(ipaddress.ip_network(_e, strict=False))
                else:
                    _fp_ips.add(_e)
            except Exception:
                pass
        print(f"false_positives_set.json: {len(_fp_ips)} IPs + {len(_fp_networks)} CIDRs als FP geladen")
    except Exception as _ex:
        print(f"WARNUNG: false_positives_set.json nicht lesbar: {_ex}")

def is_in_fp_set(ip_str):
    """True wenn IP im False-Positive-Set steht."""
    if ip_str in _fp_ips:
        return True
    try:
        _addr = ipaddress.ip_address(ip_str.split("/")[0])
        return any(_addr in _net for _net in _fp_networks)
    except Exception:
        return False

def is_valid_public_ipv4(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return obj.version == 4 and not is_protected_entry(str(obj))
    except Exception:
        return False

CIDR_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\b')

def is_valid_public_cidr(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net.version == 4 and net.prefixlen >= 8 and not is_protected_entry(str(net))
    except Exception:
        return False

removed_preexisting_protected = 0
# Collect-then-delete: explicit two-pass to satisfy dict-mutation linter
_protected_old = [ip for ip in db if is_protected_entry(ip)]
for ip in _protected_old:
    db.pop(ip, None)
    removed_preexisting_protected += 1
if removed_preexisting_protected:
    print(f"Geschützte Alt-Einträge aus seen_db entfernt: {removed_preexisting_protected}")

def parse_feed_entries(text):
    """Universeller Parser: plain IPv4, CIDR, ip:port, ipset, FortiGate,
    Spamhaus DROP, URLhaus, CSV erste Spalte. DNS-Whitelist + private gefiltert."""
    entries = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or line.startswith(';') or line.startswith('//'):
            continue
        # FortiGate: "set subnet 1.2.3.4 ..."
        fg = re.match(r'set\s+subnet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if fg:
            ip = fg.group(1)
            if is_valid_public_ipv4(ip):
                entries.add(ip)
            continue
        # ipset: "add setname 1.2.3.4" oder "add setname 1.2.3.0/24"
        ipset_m = re.match(r'add\s+\S+\s+(\S+)', line)
        if ipset_m:
            val = ipset_m.group(1).split(';')[0].strip()
            if '/' in val:
                if is_valid_public_cidr(val): entries.add(str(ipaddress.ip_network(val, strict=False)))
            else:
                if is_valid_public_ipv4(val):
                    entries.add(val)
            continue
        # Inline-Kommentar abschneiden (Spamhaus DROP: "1.2.3.0/24 ; SBLxxx")
        line = re.split(r'\s*[;#]', line)[0].strip()
        if not line: continue
        # CSV: nur erste Spalte pruefen
        first_col = line.split(',')[0].strip()
        # CIDR?
        cidr_m = CIDR_RE.match(first_col)
        if cidr_m:
            if is_valid_public_cidr(cidr_m.group(1)): entries.add(str(ipaddress.ip_network(cidr_m.group(1), strict=False)))
            continue
        # ip:port?
        ip_port = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+', first_col)
        if ip_port:
            ip = ip_port.group(1)
            if is_valid_public_ipv4(ip):
                entries.add(ip)
            continue
        # Plain IP in erster Spalte?
        ip_m = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', first_col)
        if ip_m:
            ip = ip_m.group(1)
            if is_valid_public_ipv4(ip):
                entries.add(ip)
            continue
        # Fallback: alle IPs/CIDRs in der Zeile (URLhaus, JSON-Felder etc.)
        for cidr in CIDR_RE.findall(line):
            if is_valid_public_cidr(cidr):
                entries.add(str(ipaddress.ip_network(cidr, strict=False)))
        for m in IPV4_RE.finditer(line):
            ip = m.group(1)
            if is_valid_public_ipv4(ip):
                entries.add(ip)
    return entries

def fetch_ips(name, url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NETSHIELD/3.0"})
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
        with opener.open(req, timeout=25) as r:
            raw = r.read(READ_LIMIT).decode("utf-8", errors="ignore")
        found = parse_feed_entries(raw)
        ips   = len([e for e in found if '/' not in e])
        cidrs = len([e for e in found if '/' in e])
        print(f"OK  {name}: {ips} IPs" + (f" + {cidrs} CIDRs" if cidrs else ""))
        return name, found
    except Exception as e:
        print(f"ERR {name}: {e}")
        return name, set()

# ── Alle Feeds parallel laden ──────────────────────────────────────
ip_in_hq      = set()
feed_stats    = []

ip_feeds_today = {}   # ip → set(feed_namen) für diesen Run

with ThreadPoolExecutor(max_workers=25) as executor:
    futures = {executor.submit(fetch_ips, n, u): n for n, (u, _) in SOURCES.items()}
    try:
        for future in as_completed(futures, timeout=600):
            name, ips = future.result()
            for ip in ips:
                if name in HIGH_QUALITY:
                    ip_in_hq.add(ip)
                # Feed-Name pro IP merken
                if ip not in ip_feeds_today:
                    ip_feeds_today[ip] = set()
                ip_feeds_today[ip].add(name)
            feed_stats.append((name, len(ips)))
    except TimeoutError:
        pending = sorted(n for f, n in futures.items() if not f.done())
        for f in futures:
            if not f.done():
                f.cancel()
        print(f"::warning file=update_combined_blacklist.yml::Haupt-Feed-Timeout nach 600s – {len(pending)} Feed(s) abgebrochen: {', '.join(pending[:10])}{'…' if len(pending) > 10 else ''}")
        print(f"WARNUNG: Haupt-Feed-Block Timeout – {len(pending)} Feed(s) abgebrochen, bereits geladene Feeds werden weiterverarbeitet")

# ── Lokale Sub-Workflow-Dateien einlesen ───────────────────────────
LOCAL_FEEDS = {
    # tor_exit_nodes.txt entfernt
    "cve_exploit_ips.txt":             True,
    "bot_detector_blacklist_ipv4.txt": False,
    "honeypot_ips.txt":                True,
    "honeydb_ips.txt":                 True,   # HoneyDB Community Honeypot Network (API)
    "abuseipdb_api_blacklist.txt":     True,   # AbuseIPDB API (Round-Robin, HQ)
    # FIX CACHE-LOSS: Community-gemeldete IPs werden von community_ip_report.yml
    # in diese Datei geschrieben und hier als LOCAL_FEED eingelesen.
    # HQ=False: Einzelne Community-Meldungen sind keine vertrauenswürdige Quelle;
    # HQ-Promotion erfolgt erst bei community_count >= 3 (in community_ip_report.yml).
    "community_reported_ips.txt":      False,
}
# FIX: Lokale HQ-Dateinamen für hq_feed_names_today-Berechnung.
# Dateinamen wie "honeydb_ips.txt" sind nicht in HIGH_QUALITY (Feed-Namen),
# werden aber als HQ-Quelle behandelt → müssen separat erfasst werden damit
# hq_feeds-Zähler in seen_db die lokalen HQ-Dateien korrekt mitzählt.
LOCAL_HQ_NAMES = {name for name, is_hq in LOCAL_FEEDS.items() if is_hq}
# FIX STALE1: Alters-Check für lokale Feed-Dateien.
# Sub-Workflows schreiben einen "# Aktualisiert: YYYY-MM-DD HH:MM UTC"-Header.
# Bei > 48h Alter (sub-workflow ausgefallen) GitHub Warning ausgeben.
#
# FIX STALE2: update_confidence_blacklist fehlte im Alters-Check.
# blacklist_confidence40_ipv4.txt und watchlist_confidence25to39_ipv4.txt
# sind keine LOCAL_FEEDS (werden nicht als IP-Quelle eingelesen), wurden
# deshalb nie auf Aktualität geprüft. Fehlt ein confidence-Run, merkt
# combined das nicht. Beide Dateien werden jetzt separat überwacht.
_LOCAL_FEED_MAX_AGE_HOURS = 48
_ts_re = re.compile(r'#\s*Aktualisiert:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s*UTC')
_EXTRA_AGE_CHECK_FILES = [
    "blacklist_confidence40_ipv4.txt",       # update_confidence_blacklist
    "watchlist_confidence25to39_ipv4.txt",   # update_confidence_blacklist
]
for _extra_file in _EXTRA_AGE_CHECK_FILES:
    if not os.path.exists(_extra_file):
        continue
    with open(_extra_file) as _ef:
        _extra_raw = _ef.read(4096)  # Header reicht, kein vollständiges Lesen nötig
    _ts_m_extra = _ts_re.search(_extra_raw)
    if _ts_m_extra:
        try:
            _extra_dt = datetime.strptime(_ts_m_extra.group(1), "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
            _extra_age_h = (now - _extra_dt).total_seconds() / 3600
            if _extra_age_h > _LOCAL_FEED_MAX_AGE_HOURS:
                _extra_msg = (f"{_extra_file} ist {_extra_age_h:.0f}h alt "
                              f"(letztes Update: {_ts_m_extra.group(1)} UTC) – "
                              f"update_confidence_blacklist möglicherweise ausgefallen")
                print(f"::warning file=update_combined_blacklist.yml::{_extra_msg}")
                print(f"WARNUNG: {_extra_msg}")
        except Exception:
            pass
for local_file, is_hq_local in LOCAL_FEEDS.items():
    if not os.path.exists(local_file):
        print(f"  SKIP (nicht vorhanden): {local_file}")
        continue
    with open(local_file) as lf:
        raw_local = lf.read()
    # Alters-Check
    _ts_m = _ts_re.search(raw_local)
    if _ts_m:
        try:
            _file_dt = datetime.strptime(_ts_m.group(1), "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
            _age_h = (now - _file_dt).total_seconds() / 3600
            if _age_h > _LOCAL_FEED_MAX_AGE_HOURS:
                _stale_msg = (f"{local_file} ist {_age_h:.0f}h alt "
                              f"(letztes Update: {_ts_m.group(1)} UTC) – "
                              f"Sub-Workflow möglicherweise ausgefallen")
                print(f"::warning file=update_combined_blacklist.yml::{_stale_msg}")
                print(f"WARNUNG: {_stale_msg}")
        except Exception:
            pass
    local_ips = parse_feed_entries(raw_local)
    for entry in local_ips:
        if is_hq_local:
            ip_in_hq.add(entry)
        if entry not in ip_feeds_today:
            ip_feeds_today[entry] = set()
        ip_feeds_today[entry].add(local_file)
    ips_l   = len([e for e in local_ips if '/' not in e])
    cidrs_l = len([e for e in local_ips if '/' in e])
    feed_stats.append((local_file, len(local_ips)))
    print(f"  Lokal: {local_file} → {ips_l} IPs" + (f" + {cidrs_l} CIDRs" if cidrs_l else "") + f" (HQ={is_hq_local})")


# ── Auto-discovered Feeds einlesen ─────────────────────────────────
AUTO_FEEDS_FILE = "auto_discovered_feeds.json"
if os.path.exists(AUTO_FEEDS_FILE):
    try:
        with open(AUTO_FEEDS_FILE) as af:
            auto_data = json.load(af)
        auto_feeds = auto_data.get("feeds", [])
        print(f"  Auto-discovered Feeds: {len(auto_feeds)}")

        def fetch_auto(feed):
            return fetch_ips(feed["name"], feed["url"])

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(fetch_auto, f): f["name"] for f in auto_feeds}
            try:
                for future in as_completed(futures, timeout=120):
                    name, ips = future.result()
                    for ip in ips:
                        # Auto-discovered Feeds sind nicht HQ
                        if ip not in ip_feeds_today:
                            ip_feeds_today[ip] = set()
                        ip_feeds_today[ip].add(name)
                    feed_stats.append((name, len(ips)))
            except TimeoutError:
                pending = sorted(name for future, name in futures.items() if not future.done())
                for future in futures:
                    if not future.done():
                        future.cancel()
                print(f"  WARNUNG: Auto-Feeds Timeout – {len(pending)} Feed(s) abgebrochen: {', '.join(pending[:8])}{'…' if len(pending) > 8 else ''}")
    except Exception as e:
        print(f"  WARNUNG: auto_discovered_feeds.json Fehler: {e}")
else:
    print(f"  SKIP: {AUTO_FEEDS_FILE} nicht vorhanden")

# ── seen_db aktualisieren ─────────────────────────────────────────
#
# Felder pro IP:
#   first        – erster Sichttag (unveränderlich)
#   last         – letzter Tag an dem die IP "stark bestätigt" war:
#                  >= 2 verschiedene Feeds HEUTE oder mindestens 1 HQ-Feed HEUTE
#                  Statische Mega-Listen (romainmarcoux 300k etc.) die sich
#                  nicht täglich ändern, aktualisieren "last" NICHT alleine.
#   hq           – True wenn IP je in einem HQ-Feed gesehen wurde
#   feeds        – akkumulierte Feed-Namen (für Persistenz-Score)
#   hq_feeds     – Anzahl verschiedener HQ-Feeds die diese IP je gemeldet haben
#   today_count  – Anzahl Feeds die diese IP im LETZTEN RUN gemeldet haben
#                  (wird bei jedem Run überschrieben, kein Akkumulieren)
#   today_hq     – True wenn mindestens 1 HQ-Feed diese IP heute gemeldet hat
#   days_seen    – Anzahl verschiedener Tage an denen "stark bestätigt" wurde
#                  (echter Multi-Tag-Bestätigungszähler)
#
# "last" NUR aktualisieren wenn heute durch HQ-Feed bestätigt:
# Non-HQ Feeds setzen "last" nie → statische Listen halten IPs nicht am Leben

for ip, today_feeds in ip_feeds_today.items():
    # Whitelist-Check + FP-Set-Check: diese IPs kommen NIE auf die Blacklist
    if is_whitelisted(ip) or is_in_fp_set(ip):
        continue
    today_count = len(today_feeds)
    today_is_hq = ip in ip_in_hq

    # HQ-Feed-Anzahl für diese IP heute (benannte Feeds + lokale HQ-Dateien)
    # FIX: LOCAL_HQ_NAMES ergänzt – Dateinamen wie "honeydb_ips.txt" sind
    # nicht in HIGH_QUALITY, müssen aber als HQ-Quelle mitzählen.
    # WICHTIG: Muss VOR strongly_confirmed_today berechnet werden.
    hq_feed_names_today = today_feeds & (HIGH_QUALITY | LOCAL_HQ_NAMES)

    # FIX AGGREGATOR1: "Stark bestätigt" = mindestens 2 verschiedene HQ-Feeds HEUTE.
    # Vorher: 1 HQ-Feed reichte → Aggregator-Feeds wie firehol_level1 hielten
    # IPs ewig am Leben, auch wenn kein anderer Feed sie noch meldete.
    # Jetzt: Einzelne HQ-Feeds setzen hq=True und erhöhen feed_count,
    # aber nur 2+ unabhängige HQ-Quellen refreshen "last".
    # Für NEUE IPs (nicht in db) bleibt 1 HQ-Feed ausreichend für den
    # Ersteintrag – siehe "last": now_day if today_is_hq weiter unten.
    # Non-HQ Feeds dürfen "last" weiterhin NICHT aktualisieren.
    strongly_confirmed_today = len(hq_feed_names_today) >= 2

    if ip in db:
        existing_feeds = set(db[ip].get("feeds", []))

        if strongly_confirmed_today:
            prev_last = db[ip].get("last", "2000-01-01")
            if prev_last != now_day:
                # Neuer Bestätigungstag → days_seen erhöhen (startet bei 0)
                db[ip]["days_seen"] = db[ip].get("days_seen", 0) + 1
            db[ip]["last"] = now_day

        db[ip]["feeds"]       = sorted(existing_feeds | today_feeds)
        db[ip]["today_count"] = today_count
        db[ip]["today_hq"]    = today_is_hq
        if today_is_hq:
            db[ip]["hq"] = True
        # FIX Bug3: hq_feeds als Set einzigartiger Feed-Namen akkumulieren.
        # Vorher: rohe Addition pro Lauf → unbegrenztes Wachstum (8 Läufe/Tag × 40 HQ-Feeds).
        # Jetzt: Zählt jede HQ-Feed-Quelle nur einmal, egal wie oft sie gemeldet hat.
        existing_hq_names = set(db[ip].get("hq_feed_names", []))
        existing_hq_names.update(hq_feed_names_today)
        db[ip]["hq_feed_names"] = sorted(existing_hq_names)
        db[ip]["hq_feeds"]      = len(existing_hq_names)
    else:
        db[ip] = {
            "first":          now_day,
            # FIX AGGREGATOR1: Neue IPs bekommen last=heute bei 1+ HQ-Feed.
            # Nur das REFRESHEN von last bei bestehenden IPs braucht 2+ HQ-Feeds
            # (strongly_confirmed_today). So kommen frische Feodo/ThreatFox-IPs
            # sofort in active, altern aber nach 30 Tagen raus wenn nur 1
            # Aggregator-Feed sie weitermeldet.
            "last":           now_day if today_is_hq else "2000-01-01",
            "hq":             today_is_hq,
            "feeds":          sorted(today_feeds),
            "hq_feed_names":  sorted(hq_feed_names_today),   # FIX Bug3: auch bei Neu-Einträgen
            "hq_feeds":       len(hq_feed_names_today),
            "today_count":    today_count,
            "today_hq":       today_is_hq,
            "days_seen":      1 if today_is_hq else 0,
        }

protected_removed_runtime = 0
# Collect-then-delete: explicit two-pass to satisfy dict-mutation linter
_protected_runtime = [ip for ip in db if is_protected_entry(ip)]
for ip in _protected_runtime:
    db.pop(ip, None)
    protected_removed_runtime += 1
if protected_removed_runtime:
    print(f"Geschützte Einträge nach Feed-Ingest entfernt: {protected_removed_runtime}")

# Aufnahme-Filter: mindestens 2 verschiedene Feeds (gesamt) oder HQ.
# AUSNAHME: Community-Reports (feeds=['community_report']) werden NICHT
# sofort gelöscht – sie leben bis zum Watchlist-Expiry (30 Tage nach first).
# Hintergrund: auto_feed_discovery hatte denselben Bug (dort als FIX Bug2
# behoben). Community-IPs haben nur 1 Feed-Eintrag ('community_report') und
# hq=False solange community_count < 3 → würden ohne diese Ausnahme beim
# nächsten Run sofort gelöscht, obwohl der Issue-Kommentar 'Added to Watchlist'
# verspricht.
current_valid = {
    ip for ip, data in db.items()
    if not is_protected_entry(ip) and (
        len(data.get("feeds", [])) >= 2
        or data.get("hq")
        or "community_report" in data.get("feeds", [])
    )
}
# Collect-then-delete: explicit two-pass to satisfy dict-mutation linter
_invalid_ips = [ip for ip in db if ip not in current_valid]
for ip in _invalid_ips:
    db.pop(ip, None)

# ── 180-Tage-Ablauf ────────────────────────────────────────────────
# Watchlist-IPs (last="2000-01-01", hq=False) haben nie eine HQ-Bestätigung
# erhalten. Für sie wird das Ablaufdatum vom first-Datum berechnet, damit
# Community-Reports nicht sofort beim nächsten Lauf gelöscht werden.
# Reguläre IPs laufen weiterhin nach ihrem last-Datum ab (180 Tage).
WATCHLIST_EXPIRY_DAYS = 30   # Watchlist-IPs ohne HQ nach 30 Tagen entfernen
expired = []
cutoff      = now - timedelta(days=EXPIRY_DAYS)
cutoff_wl   = now - timedelta(days=WATCHLIST_EXPIRY_DAYS)
# Collect-then-delete: two-pass avoids RuntimeError and satisfies dict-mutation linter
_to_expire = []
for ip in list(db.keys()):
    try:
        entry     = db[ip]
        last_str  = entry.get("last",  "2000-01-01")
        first_str = entry.get("first", last_str)
        is_hq     = entry.get("hq", False)
        last_seen  = datetime.strptime(last_str,  "%Y-%m-%d").replace(tzinfo=timezone.utc)
        first_seen = datetime.strptime(first_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)

        if last_str == "2000-01-01" and not is_hq:
            # Watchlist-IP: Ablauf nach first-Datum (30 Tage)
            if first_seen < cutoff_wl:
                _to_expire.append(ip)
        else:
            # Normale IP: Ablauf nach last-Datum (180 Tage)
            if last_seen < cutoff:
                _to_expire.append(ip)
    except Exception:
        _to_expire.append(ip)
for ip in _to_expire:
    expired.append(ip)
    db.pop(ip, None)
print(f"Abgelaufen (>{EXPIRY_DAYS} Tage / Watchlist >{WATCHLIST_EXPIRY_DAYS} Tage): {len(expired)} IPs entfernt")

# ── Whitelist-/FP-Altlasten aus seen_db bereinigen ───────────────
# IPs, die vor Einführung eines neuen Whitelist-/FP-Eintrags bereits
# in seen_db lagen, würden sonst beim Schreiben der Combined-Datei
# wieder auftauchen. Deshalb hier vor dem Persistieren aktiv entfernen.
_wl_cleanup = [ip for ip in db if is_whitelisted(ip) or is_in_fp_set(ip)]
for ip in _wl_cleanup:
    db.pop(ip, None)
if _wl_cleanup:
    print(f"Whitelist-Bereinigung seen_db: {len(_wl_cleanup)} IPs entfernt")

# ── community_reported_ips.txt Stale-Bereinigung ─────────────────
# FIX STALE-COMMUNITY2: community_ip_report.yml nutzt append-only
# (Race-Condition-Fix). Stale IPs werden hier bereinigt, nachdem
# seen_db-Expiry gelaufen ist. Nur IPs behalten die noch in seen_db
# sind – abgelaufene (30-Tage-Watchlist / 180-Tage-Ablauf) entfernen.
_COMMUNITY_FILE = "community_reported_ips.txt"
if os.path.exists(_COMMUNITY_FILE):
    with open(_COMMUNITY_FILE, encoding="utf-8") as _cf:
        _community_all = {
            l.strip() for l in _cf
            if l.strip() and not l.startswith("#")
        }
    _community_active = _community_all & set(db.keys())
    _community_stale = _community_all - _community_active
    if _community_stale:
        _community_sorted = sorted(
            _community_active,
            key=lambda x: (tuple(int(o) for o in x.split('/')[0].split('.')), x),
        )
        with open(_COMMUNITY_FILE, "w", encoding="utf-8") as _cf:
            _cf.write("# NETSHIELD Community Reported IPs\n")
            _cf.write(f"# Aktualisiert: {now_stamp}\n")
            _cf.write("# Quelle: GitHub Issues (community-report Label)\n\n")
            if _community_sorted:
                _cf.write("\n".join(_community_sorted) + "\n")
        print(f"community_reported_ips.txt: {len(_community_stale)} veraltete IPs entfernt, "
              f"{len(_community_active)} aktive behalten")

# ── seen_db speichern ──────────────────────────────────────────────
# feeds-Liste kappen: stoppt unbegrenztes Wachstum der seen_db (war Ursache des Timeouts)
_MAX_FEEDS = 30
_capped = 0
for _e in db.values():
    if len(_e.get("feeds", [])) > _MAX_FEEDS:
        _e["feeds"] = _e["feeds"][:_MAX_FEEDS]
        _capped += 1
if _capped:
    print(f"feeds-Liste auf {_MAX_FEEDS} gekürzt: {_capped} IPs")
_db_dump(db, DB_FILE)

# ── Stufe 1: combined_threat_blacklist_ipv4.txt (alle DB-IPs) ─────
# FIX Bug6: Numerische IP-Sortierung (1.2.3.4 vor 10.0.0.1),
# konsistent mit active_blacklist und allen anderen Ausgabedateien.
# Zusätzlicher Guard: Whitelist-/FP-Treffer dürfen auch als Altlasten
# aus früheren seen_db-Ständen nie mehr in die Combined-Ausgabe.
try:
    sorted_ips = sorted(
        [ip for ip in db.keys()
         if not is_protected_entry(ip)
         and not is_whitelisted(ip)
         and not is_in_fp_set(ip)],
        key=lambda e: (tuple(int(x) for x in e.split('/')[0].split('.')), e)
    )
except Exception:
    sorted_ips = sorted(
        [ip for ip in db.keys()
         if not is_protected_entry(ip)
         and not is_whitelisted(ip)
         and not is_in_fp_set(ip)]
    )
feed_stats.sort(key=lambda x: -x[1])

# ── Leerungsschutz combined ───────────────────────────────────────
# Verhindert das Überschreiben der Blacklist wenn seen_db leer/korrupt
# ist oder alle Feeds gleichzeitig ausgefallen sind (z.B. Runner-Netzwerkausfall).
# Schwelle: 1000 IPs – bei normalbetrieb sind stets >10.000 IPs vorhanden.
MIN_COMBINED = 1000
if len(sorted_ips) < MIN_COMBINED:
    msg = (f"Nur {len(sorted_ips)} IPs in combined (< {MIN_COMBINED}) – "
           f"Leerungsschutz aktiv, combined_threat_blacklist_ipv4.txt wird NICHT überschrieben.")
    print(f"::error file=update_combined_blacklist.yml::{msg}")
    print(f"FEHLER: {msg}")
    sys.exit(1)

with open("combined_threat_blacklist_ipv4.txt", "w", encoding="utf-8") as f:
    f.write("# NETSHIELD Combined Threat Blacklist (IPv4) – Stufe 1\n")
    f.write(f"# Aktualisiert: {now_stamp}\n")
    f.write(f"# Feeds: {len(SOURCES) + len(LOCAL_FEEDS)}\n")
    f.write(f"# Eintraege: {len(sorted_ips)}\n")
    f.write(f"# Abgelaufen entfernt: {len(expired)}\n\n")
    f.write("\n".join(sorted_ips) + "\n")

# ── Stufe 2: active_blacklist_ipv4.txt (30 Tage + Confidence >= 65) ──
# Kriterien kombiniert:
#   1. last_seen <= 30 Tage  (nur HQ-Feeds setzen last → echte Aktualität)
#   2. Confidence-Score >= 65 (gleiche Schwelle wie active_blacklist-Header)
# Ziel: kleine, qualitativ hochwertige OPNsense-Liste ohne statischen Ballast.
cutoff_30 = now - timedelta(days=30)
active_ips = []
active_skipped_score = 0   # besteht Recency, aber Score < 65
active_skipped_old   = 0   # zu alt (last_dt > 30 Tage)

for ip, data in db.items():
    if is_protected_entry(ip):
        continue
    # FIX: Watchlist-IPs haben last="2000-01-01" als Sentinel-Wert (keine echte
    # HQ-Bestätigung). Sie würden durch cutoff_30 korrekt gefiltert, aber das
    # Verhalten hängt implizit am Sentinel-Datum. Explizit überspringen ist robuster.
    if data.get("last", "") == "2000-01-01":
        continue
    try:
        last_dt  = datetime.strptime(data["last"],  "%Y-%m-%d").replace(tzinfo=timezone.utc)
        first_dt = datetime.strptime(data.get("first", data["last"]), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        continue

    if last_dt < cutoff_30:
        active_skipped_old += 1
        continue

    is_hq       = data.get("hq", False)
    feed_count  = len(data.get("feeds", []))
    today_count = data.get("today_count", 0)
    days_seen   = data.get("days_seen", 1)
    days_since_last = (now - last_dt).days
    days_known      = (now - first_dt).days + 1

    if is_hq:                  score_a = 40
    elif today_count >= 5:     score_a = 35
    elif today_count >= 3:     score_a = 28
    elif today_count >= 2:     score_a = 20
    elif feed_count >= 5:      score_a = 15
    elif feed_count >= 3:      score_a = 10
    elif feed_count >= 2:      score_a = 5
    else:                      score_a = 0

    if days_since_last <= 1:   score_b = 30
    elif days_since_last <= 3: score_b = 25
    elif days_since_last <= 7: score_b = 20
    elif days_since_last <= 14:score_b = 12
    elif days_since_last <= 30:score_b = 6
    else:                      score_b = 0

    if days_seen >= 14:        score_c = 20
    elif days_seen >= 7:       score_c = 15
    elif days_seen >= 3:       score_c = 10
    elif days_seen >= 2:       score_c = 6
    else:                      score_c = 2

    if days_known >= 90:       score_d = 10
    elif days_known >= 30:     score_d = 6
    elif days_known >= 14:     score_d = 3
    else:                      score_d = 0

    conf = min(score_a + score_b + score_c + score_d, 100)

    if conf >= 65:
        active_ips.append(ip)
    else:
        active_skipped_score += 1

try:
    active_ips.sort(key=lambda e: (tuple(int(x) for x in e.split('/')[0].split('.')), e))
except Exception:
    active_ips.sort()

# ── Leerungsschutz active ─────────────────────────────────────────
# active_blacklist kann bei einem frischen Repo (noch keine HQ-Daten) oder
# nach einem Cache-Miss leer sein – in dem Fall die bestehende Datei behalten.
# Kein sys.exit(1): combined wurde bereits geschrieben, nur active überspringen.
MIN_ACTIVE = 100
if len(active_ips) < MIN_ACTIVE:
    msg = (f"Nur {len(active_ips)} aktive IPs (< {MIN_ACTIVE}) – "
           f"active_blacklist_ipv4.txt wird NICHT überschrieben (behalte vorherigen Stand).")
    print(f"::warning file=update_combined_blacklist.yml::{msg}")
    print(f"WARNUNG: {msg}")
else:
    with open("active_blacklist_ipv4.txt", "w", encoding="utf-8") as f:
        f.write("# NETSHIELD Active Blacklist (IPv4) – Stufe 2\n")
        f.write(f"# Aktualisiert: {now_stamp}\n")
        f.write(f"# Kriterien: last_seen <= 30 Tage UND Confidence-Score >= 65/100\n")
        f.write(f"# Eintraege: {len(active_ips)}\n")
        f.write(f"# Herausgefiltert (zu alt >30T): {active_skipped_old} | (Score <65): {active_skipped_score}\n\n")
        f.write("\n".join(active_ips) + "\n")

# ── Report ─────────────────────────────────────────────────────────
with open("combined_threat_blacklist_report.md", "w", encoding="utf-8") as f:
    f.write("# Combined Threat Blacklist Report\n\n")
    f.write(f"- Aktualisiert: **{now_stamp}**\n")
    f.write(f"- Feeds gesamt: **{len(SOURCES) + len(LOCAL_FEEDS)}** (davon {len(LOCAL_FEEDS)} lokale Sub-Workflow-Feeds)\n")
    f.write(f"- Stufe 1 (combined): **{len(sorted_ips)}** IPs\n")
    f.write(f"- Stufe 2 (active, 30T + Conf≥65): **{len(active_ips)}** IPs | herausgefiltert: {active_skipped_old} zu alt, {active_skipped_score} Score<65\n")
    f.write(f"- Abgelaufen & entfernt: **{len(expired)}**\n\n")
    f.write("## Feed-Statistik\n\n| Feed | IPs |\n|---|---:|\n")
    for name, count in feed_stats:
        hq_mark = " ⭐" if name in HIGH_QUALITY else ""
        f.write(f"| `{name}`{hq_mark} | {count} |\n")

print(f"\nFertig! combined: {len(sorted_ips)} IPs | active: {len(active_ips)} IPs | zu alt: {active_skipped_old} | Score<65: {active_skipped_score} | Feeds: {len(SOURCES) + len(LOCAL_FEEDS)}")
