#!/usr/bin/env python3
"""
NETSHIELD Shared Utilities
==========================
Single Source of Truth für alle gemeinsam genutzten Funktionen.
Wird von allen Workflows importiert statt Code-Duplikation.

Verwendung in Workflows:
    import sys; sys.path.insert(0, "scripts")
    from netshield_common import (
        load_whitelist, load_fp_set, is_in_fp_set,
        is_valid_public_ipv4, is_valid_public_cidr,
        is_protected_entry, is_whitelisted,
        parse_entries,
    )
"""

import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone

# ═══════════════════════════════════════════════════════════════
# Kompilierte Regex-Patterns (Modul-Ebene, einmalig)
# ═══════════════════════════════════════════════════════════════

IPV4_RE = re.compile(r'(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])')
CIDR_RE = re.compile(r'(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})(?!\d)')
TIMESTAMP_RE = re.compile(r'#\s*Aktualisiert:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s*UTC')

# RFC1918 + Loopback + Multicast + Reserved
_RFC_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


# ═══════════════════════════════════════════════════════════════
# Whitelist (Single Source of Truth: whitelist.json)
# ═══════════════════════════════════════════════════════════════

_whitelist_networks = []
_protected_networks = []


def load_whitelist(path=".github/workflows/whitelist.json", min_entries=50):
    """Lädt whitelist.json und baut Netzwerk-Listen.

    Returns:
        list[ipaddress.IPv4Network]: Liste der Whitelist-Netzwerke.

    Raises:
        SystemExit: Wenn Datei nicht ladbar oder zu wenig Einträge.
    """
    global _whitelist_networks, _protected_networks
    try:
        with open(path, encoding="utf-8") as f:
            entries = json.load(f)["entries"]
        if len(entries) < min_entries:
            msg = f"whitelist.json hat nur {len(entries)} Einträge (<{min_entries}) – möglicherweise korrupt"
            print(f"::error ::{msg}", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        msg = f"whitelist.json nicht ladbar: {e}"
        print(f"::error ::{msg}", file=sys.stderr)
        sys.exit(1)

    _whitelist_networks = []
    for entry in entries:
        try:
            _whitelist_networks.append(ipaddress.ip_network(entry, strict=False))
        except Exception:
            pass

    # Protected = Whitelist + RFC1918
    _protected_networks = list(_whitelist_networks) + list(_RFC_PRIVATE_NETS)

    print(f"whitelist.json geladen: {len(_whitelist_networks)} Einträge")
    return _whitelist_networks


def is_whitelisted(ip_str):
    """True wenn IP in einer der Whitelist-Ranges liegt."""
    try:
        addr = ipaddress.ip_address(ip_str.split('/')[0])
        return any(addr in net for net in _whitelist_networks)
    except Exception:
        return False


def is_protected_entry(value):
    """True wenn eine IP/ein CIDR niemals in Listen landen darf.

    Prüft: Whitelist, RFC1918, Loopback, Multicast, Reserved, Link-Local,
    Unspecified, IPv6, zu große CIDRs (< /8).
    """
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


# ═══════════════════════════════════════════════════════════════
# False-Positive Set
# ═══════════════════════════════════════════════════════════════

_fp_ips = set()
_fp_networks = []


def load_fp_set(path="false_positives_set.json"):
    """Lädt false_positives_set.json.

    Returns:
        tuple[set, list]: (fp_ips, fp_networks)
    """
    global _fp_ips, _fp_networks
    _fp_ips = set()
    _fp_networks = []
    if not os.path.exists(path):
        return _fp_ips, _fp_networks
    try:
        with open(path) as f:
            data = json.load(f)
        for entry in data.get("ips", []):
            try:
                if "/" in entry:
                    _fp_networks.append(ipaddress.ip_network(entry, strict=False))
                else:
                    _fp_ips.add(entry)
            except Exception:
                pass
        print(f"false_positives_set.json: {len(_fp_ips)} IPs + {len(_fp_networks)} CIDRs geladen")
    except Exception as e:
        print(f"WARNUNG: false_positives_set.json nicht lesbar: {e}")
    return _fp_ips, _fp_networks


def is_in_fp_set(ip_str):
    """True wenn IP im False-Positive-Set steht."""
    if ip_str in _fp_ips:
        return True
    try:
        addr = ipaddress.ip_address(ip_str.split("/")[0])
        return any(addr in net for net in _fp_networks)
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# IP-Validierung
# ═══════════════════════════════════════════════════════════════

def is_valid_public_ipv4(ip):
    """True wenn gültige öffentliche IPv4-Adresse (nicht private/loopback/etc)."""
    try:
        obj = ipaddress.ip_address(ip)
        return (obj.version == 4
                and not obj.is_private and not obj.is_loopback
                and not obj.is_multicast and not obj.is_unspecified
                and not obj.is_reserved and not obj.is_link_local)
    except Exception:
        return False


_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("224.0.0.0/4"),
]


def is_valid_public_cidr(cidr):
    """True wenn gültiges öffentliches IPv4-CIDR mit Prefix >= /8.

    FIX BUG-PRIV1: Prüft zusätzlich ob der CIDR-Range mit privaten/
    reservierten Bereichen ÜBERLAPPT. Vorher wurde nur net.is_private
    geprüft (Netzadresse), aber z.B. 192.128.0.0/9 hat eine öffentliche
    Netzadresse und deckt trotzdem 192.168.0.0/16 ab.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if not (net.version == 4
                and not net.is_private and not net.is_loopback
                and not net.is_multicast and not net.is_reserved
                and not net.is_link_local and net.prefixlen >= 8):
            return False
        # Overlap-Check: breite CIDRs die private Ranges einschließen ablehnen
        for priv in _PRIVATE_RANGES:
            if net.overlaps(priv):
                return False
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# Feed-Parsing (Universal-Parser)
# ═══════════════════════════════════════════════════════════════

def parse_entries(text, use_protected_check=False):
    """Universeller Parser: plain IPv4, CIDR, ip:port, ipset, FortiGate,
    Spamhaus DROP, URLhaus, CSV erste Spalte. Privates/Loopback gefiltert.

    Args:
        text: Rohtext des Feeds.
        use_protected_check: Wenn True, wird is_protected_entry() statt
            is_valid_public_ipv4() verwendet (schließt Whitelist ein).

    Returns:
        set[str]: Gefiltertes Set von IPs und CIDRs.
    """
    ip_check = (lambda ip: not is_protected_entry(ip)) if use_protected_check else is_valid_public_ipv4
    cidr_check = (lambda c: not is_protected_entry(c)) if use_protected_check else is_valid_public_cidr

    # Defensiv: Wenn ein Feed None zurückliefert (fetch_url-Timeout,
    # Corrupt-Download, leerer JSON-Wert), soll der Parser nicht crashen.
    # Auch Bytes werden toleriert, falls ein Upstream-Fetch nicht dekodiert.
    if text is None:
        return set()
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", errors="replace")
        except Exception:
            return set()
    if not isinstance(text, str):
        return set()

    entries = set()
    for raw_line in text.splitlines():
        # Zeilen mit Null-Bytes (Binärmüll, Dateikorruption) komplett
        # verwerfen statt Null-Bytes zu strippen und die IP dann doch zu
        # akzeptieren. Legitime IP-Feeds enthalten keine Null-Bytes.
        if "\x00" in raw_line:
            continue
        line = raw_line.strip()
        if not line or line.startswith('#') or line.startswith(';') or line.startswith('//'):
            continue

        # FortiGate: "set subnet 1.2.3.4 ..."
        fg = re.match(r'set\s+subnet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if fg:
            ip = fg.group(1)
            if ip_check(ip):
                entries.add(ip)
            continue

        # ipset: "add setname 1.2.3.4" oder "add setname 1.2.3.0/24"
        ipset_m = re.match(r'add\s+\S+\s+(\S+)', line)
        if ipset_m:
            val = ipset_m.group(1).split(';')[0].strip()
            if '/' in val:
                if cidr_check(val):
                    entries.add(str(ipaddress.ip_network(val, strict=False)))
            else:
                if ip_check(val):
                    entries.add(val)
            continue

        # Inline-Kommentar abschneiden (Spamhaus DROP: "1.2.3.0/24 ; SBLxxx")
        line = re.split(r'\s*[;#]', line)[0].strip()
        if not line:
            continue

        # CSV: nur erste Spalte prüfen
        first_col = line.split(',')[0].strip()

        # CIDR?
        cidr_m = CIDR_RE.match(first_col)
        if cidr_m:
            if cidr_check(cidr_m.group(1)):
                entries.add(str(ipaddress.ip_network(cidr_m.group(1), strict=False)))
            continue

        # ip:port?
        ip_port = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+', first_col)
        if ip_port:
            ip = ip_port.group(1)
            if ip_check(ip):
                entries.add(ip)
            continue

        # Plain IP in erster Spalte?
        # (?![\d.]) statt \b: schliesst auch nachfolgenden Punkt aus,
        # damit '1.2.3.4.5' (Versions-String) nicht als '1.2.3.4' durchgeht.
        ip_m = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])', first_col)
        if ip_m:
            ip = ip_m.group(1)
            if ip_check(ip):
                entries.add(ip)
            continue

        # Fallback: alle IPs/CIDRs in der Zeile (URLhaus, JSON-Felder etc.)
        for cidr in CIDR_RE.findall(line):
            if cidr_check(cidr):
                entries.add(str(ipaddress.ip_network(cidr, strict=False)))
        for m in IPV4_RE.finditer(line):
            ip = m.group(1)
            if ip_check(ip):
                entries.add(ip)

    return entries


# ═══════════════════════════════════════════════════════════════
# Scoring-Modell
# ═══════════════════════════════════════════════════════════════

def calculate_confidence(is_hq=False, today_count=0, feed_count=0,
                         days_since_last=999, days_seen=1, days_known=0):
    """Berechnet den Confidence-Score (0-100) für eine IP.

    Dimensionen:
        [A] Quellen-Qualität (max 40)
        [B] Aktualität (max 30)
        [C] Persistenz (max 20)
        [D] Bekannt seit (max 10)

    Returns:
        int: Score 0-100
    """
    # Typ-Koerzierung VOR dem Clamp: Wenn seen_db korrupt ist (None, "5",
    # float aus fremden Tools) muss der Score-Aufruf nicht crashen, sondern
    # einen definierten Default liefern. Ohne die Koerzierung würde
    # `max(0, None)` oder `today_count >= 5` mit String-Input einen
    # TypeError werfen und den gesamten Main-Loop killen.
    def _int_or(val, default):
        try:
            return int(val) if val is not None else default
        except (TypeError, ValueError, OverflowError):
            # OverflowError: int(float('inf')) – sollte nie in JSON-seen_db
            # vorkommen (JSON erlaubt kein Infinity), aber die Funktion ist
            # dokumentiert crash-sicher. Konsistent mit den anderen Except-Typen.
            return default

    today_count     = _int_or(today_count,     0)
    feed_count      = _int_or(feed_count,      0)
    days_since_last = _int_or(days_since_last, 999)
    days_seen       = _int_or(days_seen,       1)
    days_known      = _int_or(days_known,      0)
    is_hq           = bool(is_hq)

    # Negative Inputs auf 0 klemmen – solche Werte sollten nie auftreten,
    # aber wenn die seen_db korrupt ist, sollen sie nicht versehentlich
    # hohe Scores erzeugen (negativ < alle Schwellen → triggert den
    # "<=1"-Zweig und vergibt volle 30 Punkte für Aktualität).
    today_count     = max(0, today_count)
    feed_count      = max(0, feed_count)
    days_since_last = max(0, days_since_last)
    days_seen       = max(0, days_seen)
    days_known      = max(0, days_known)

    # [A] Quellen-Qualität
    if is_hq:
        score_a = 40
    elif today_count >= 5:
        score_a = 35
    elif today_count >= 3:
        score_a = 28
    elif today_count >= 2:
        score_a = 20
    elif feed_count >= 5:
        score_a = 15
    elif feed_count >= 3:
        score_a = 10
    elif feed_count >= 2:
        score_a = 5
    else:
        score_a = 0

    # [B] Aktualität
    if days_since_last <= 1:
        score_b = 30
    elif days_since_last <= 3:
        score_b = 25
    elif days_since_last <= 7:
        score_b = 20
    elif days_since_last <= 14:
        score_b = 12
    elif days_since_last <= 30:
        score_b = 6
    else:
        score_b = 0

    # [C] Persistenz
    if days_seen >= 14:
        score_c = 20
    elif days_seen >= 7:
        score_c = 15
    elif days_seen >= 3:
        score_c = 10
    elif days_seen >= 2:
        score_c = 6
    else:
        score_c = 2

    # [D] Bekannt seit
    if days_known >= 90:
        score_d = 10
    elif days_known >= 30:
        score_d = 6
    elif days_known >= 14:
        score_d = 3
    else:
        score_d = 0

    return min(score_a + score_b + score_c + score_d, 100)


# ═══════════════════════════════════════════════════════════════
# HTTP-Fetch mit Retry
# ═══════════════════════════════════════════════════════════════

def _is_safe_public_host(hostname):
    """True wenn der Hostname ausschließlich auf öffentliche IPs auflöst.

    Schützt fetch_url gegen SSRF: kein localhost, kein RFC1918,
    kein Link-Local (inkl. 169.254.169.254 Cloud-Metadata), kein Loopback,
    keine Carrier-Grade NAT (100.64.0.0/10), keine Multicast/Reserved.
    """
    import socket
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False
        # Gürtel + Hosenträger: is_global excluded auch Carrier-Grade NAT
        # (100.64/10) und einige weitere Reserved-Ranges explizit.
        if not ip.is_global:
            return False
    return True


def fetch_url(url, timeout=30, retries=3, user_agent="NETSHIELD/3.0",
              read_limit=25 * 1024 * 1024):
    """Fetcht eine URL mit exponentiellem Backoff.

    Sicherheit:
        - Nur http/https als Schema (kein file://, ftp://, gopher://).
        - Host muss auf öffentliche IP auflösen (kein SSRF gegen
          localhost, RFC1918 oder Cloud-Metadata wie 169.254.169.254).
        - Gleicher Check wird bei Redirects erneut durchgeführt.

    Args:
        url: Ziel-URL.
        timeout: Timeout in Sekunden.
        retries: Max. Versuche.
        user_agent: User-Agent Header.
        read_limit: Max. Bytes zum Lesen.

    Returns:
        str | None: Response-Body oder None bei Fehler.
    """
    import time
    import urllib.request
    import urllib.error
    import urllib.parse

    def _validate(u):
        parsed = urllib.parse.urlparse(u)
        if parsed.scheme not in ("http", "https"):
            print(f"  FEHLER Schema nicht erlaubt: {parsed.scheme}://")
            return False
        if not parsed.hostname:
            print(f"  FEHLER kein Hostname in URL: {u}")
            return False
        if not _is_safe_public_host(parsed.hostname):
            print(f"  FEHLER Host nicht öffentlich (SSRF-Schutz): {parsed.hostname}")
            return False
        return True

    if not _validate(url):
        return None

    class _SafeRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not _validate(newurl):
                raise urllib.error.URLError(
                    f"Redirect zu unsicherem Ziel blockiert: {newurl}")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    # HTTP-Statuscodes die als transient gelten und retried werden:
    # - 429: Rate-Limit, nach Backoff oft wieder OK
    # - 500-504: Server-Fehler, oft kurzfristig
    # - 404 NUR bei raw.githubusercontent.com: dokumentierter GitHub-Bug,
    #   siehe https://github.com/orgs/community/discussions/169205 –
    #   Files existieren, werden aber sporadisch mit 404 ausgeliefert.
    TRANSIENT_CODES = {429, 500, 502, 503, 504}
    _host_is_gh_raw = urllib.parse.urlparse(url).hostname == "raw.githubusercontent.com"

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": user_agent})
            opener = urllib.request.build_opener(_SafeRedirect())
            with opener.open(req, timeout=timeout) as r:
                return r.read(read_limit).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            retryable = e.code in TRANSIENT_CODES or (e.code == 404 and _host_is_gh_raw)
            if retryable and attempt < retries:
                print(f"  HTTP {e.code} {url} – Versuch {attempt}/{retries}, Retry...")
                time.sleep(2 ** attempt)
                continue
            print(f"  FEHLER HTTP {e.code} {url}")
            return None
        except Exception as e:
            if attempt < retries:
                time.sleep(2 ** attempt)
            else:
                print(f"  FEHLER {url} (nach {retries} Versuchen): {e}")
    return None


# ═══════════════════════════════════════════════════════════════
# seen_db Hilfsfunktionen
# ═══════════════════════════════════════════════════════════════

def safe_get_date(data, key, default="2000-01-01"):
    """Sicheres Auslesen eines Datumsstrings aus einem dict.

    Behandelt None-Werte, fehlende Keys und ungültige Formate.

    Returns:
        str: Datumsstring im Format YYYY-MM-DD
    """
    val = data.get(key)
    if not val or not isinstance(val, str):
        return default
    # Validierung
    try:
        datetime.strptime(val, "%Y-%m-%d")
        return val
    except (ValueError, TypeError):
        return default


def parse_date(date_str, default_str="2000-01-01"):
    """Parst einen Datumsstring zu datetime (UTC).

    Returns:
        datetime: UTC-datetime
    """
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return datetime.strptime(default_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)


def check_local_feed_age(filepath, max_age_hours=48):
    """Prüft das Alter einer lokalen Feed-Datei anhand des Aktualisiert-Headers.

    Returns:
        float | None: Alter in Stunden oder None wenn nicht bestimmbar.
    """
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            header = f.read(4096)
        m = TIMESTAMP_RE.search(header)
        if not m:
            return None
        file_dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        age_h = (datetime.now(timezone.utc) - file_dt).total_seconds() / 3600
        if age_h > max_age_hours:
            msg = (f"{filepath} ist {age_h:.0f}h alt "
                   f"(letztes Update: {m.group(1)} UTC)")
            print(f"::warning ::{msg}")
            print(f"WARNUNG: {msg}")
        return age_h
    except Exception:
        return None


def sort_ips(ip_list):
    """Sortiert IPs/CIDRs numerisch (1.2.3.4 vor 10.0.0.1).

    Returns:
        list[str]: Sortierte Liste.
    """
    try:
        return sorted(ip_list,
                      key=lambda e: (tuple(int(x) for x in e.split('/')[0].split('.')), e))
    except Exception:
        return sorted(ip_list)


def write_ip_list(filepath, ips, header_lines=None):
    """Schreibt eine sortierte IP-Liste mit Header – atomar.

    Schreibt erst in eine temporäre Datei im selben Verzeichnis und
    benennt sie dann per os.replace() um. Damit bleibt die Zieldatei
    bei Crash/Kill/OOM garantiert in einem konsistenten Zustand:
    entweder kompletter alter Inhalt oder kompletter neuer Inhalt,
    niemals eine halb geschriebene Datei.

    Wichtig: tempfile im selben Verzeichnis, weil os.replace über
    Filesystem-Grenzen hinweg nicht atomar ist.

    Args:
        filepath: Zieldatei.
        ips: Iterable von IPs/CIDRs.
        header_lines: Liste von Kommentarzeilen (ohne #-Prefix).
    """
    import tempfile
    sorted_list = sort_ips(ips)
    target_dir = os.path.dirname(os.path.abspath(filepath)) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(filepath)}.",
        suffix=".tmp",
        dir=target_dir,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            if header_lines:
                for line in header_lines:
                    f.write(f"# {line}\n")
                f.write("\n")
            f.write("\n".join(sorted_list) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, filepath)
    except Exception:
        # Bei Fehler das tempfile wieder entfernen statt Leichen zu lassen
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return sorted_list


def write_json_atomic(filepath, data, **dump_kwargs):
    """Schreibt JSON atomar: tmp-Datei + fsync + os.replace.

    Verhindert korrupte seen_db.json bei Runner-OOM/SIGKILL/Timeout.
    Ohne diesen Fix bleibt bei Crash eine halb geschriebene Datei zurück,
    die der naechste Run als korrupt erkennt und ignoriert → Leerungsschutz
    greift → kein Update.

    Args:
        filepath: Zieldatei.
        data: JSON-serialisierbares Objekt.
        **dump_kwargs: An json.dump weitergereicht (z.B. separators, indent).
    """
    import tempfile
    target_dir = os.path.dirname(os.path.abspath(filepath)) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(filepath)}.",
        suffix=".tmp",
        dir=target_dir,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, **dump_kwargs)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, filepath)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def write_text_atomic(filepath, content):
    """Schreibt einen Text atomar (tempfile + fsync + os.replace).

    Fuer Faelle wo weder write_ip_list (erwartet Iterable von IPs + Header)
    noch write_json_atomic passt – z.B. Firewall-Blocklisten mit
    Meta-Kommentaren je Zeile, Reports usw.

    Args:
        filepath: Zieldatei.
        content: Kompletter Text-Inhalt als String.
    """
    import tempfile
    target_dir = os.path.dirname(os.path.abspath(filepath)) or "."
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(filepath)}.",
        suffix=".tmp",
        dir=target_dir,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, filepath)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
