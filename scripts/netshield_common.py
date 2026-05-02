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

# FIX BUG-PRIV2: Unifizierte Liste aller nicht-oeffentlich routbaren IPv4-Bereiche.
# Vorher existierten zwei abweichende Listen:
#   _RFC_PRIVATE_NETS (3 Eintraege, nur RFC1918)  -> genutzt von is_protected_entry
#   _PRIVATE_RANGES   (7 Eintraege, voll)          -> genutzt von is_valid_public_cidr
# Folge: is_protected_entry liess z.B. 169.0.0.0/8 durch (ueberlappt 169.254/16
# link-local), obwohl is_valid_public_cidr denselben CIDR korrekt ablehnte.
# Divergenz zwischen zwei Funktionen mit gleichem Vertrag ("Rangiere Private/
# Reserved aus"). Jetzt eine Single Source of Truth.
_RESERVED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 private
    ipaddress.ip_network("127.0.0.0/8"),      # RFC 990  loopback
    ipaddress.ip_network("169.254.0.0/16"),   # RFC 3927 link-local (inkl. 169.254.169.254 AWS IMDS)
    ipaddress.ip_network("100.64.0.0/10"),    # RFC 6598 Carrier-Grade NAT
    ipaddress.ip_network("224.0.0.0/4"),      # RFC 5771 multicast
    ipaddress.ip_network("240.0.0.0/4"),      # RFC 1112 Class E reserved (inkl. 255.255.255.255 broadcast)
    ipaddress.ip_network("0.0.0.0/8"),        # RFC 1122 "this network"
    ipaddress.ip_network("192.0.2.0/24"),     # RFC 5737 TEST-NET-1 documentation
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # RFC 5737 TEST-NET-3
    ipaddress.ip_network("198.18.0.0/15"),    # RFC 2544 benchmarking
]

# FIX ALIAS-IMMUTABLE: Backward-compat aliases als Tuple, nicht als
# Referenz auf dasselbe Listenobjekt. Vorher waren _RFC_PRIVATE_NETS,
# _PRIVATE_RANGES und _RESERVED_NETS dieselbe Liste – ein versehentlicher
# .append/.extend auf einem der Aliases (z.B. in einem Test der nicht
# resettet) haette das Source-of-Truth silent verschmutzt. Tuple wirft
# AttributeError beim Mutationsversuch und bleibt iterierbar.
_RFC_PRIVATE_NETS = tuple(_RESERVED_NETS)
_PRIVATE_RANGES = tuple(_RESERVED_NETS)


# ═══════════════════════════════════════════════════════════════
# Whitelist (Single Source of Truth: whitelist.json)
# ═══════════════════════════════════════════════════════════════

_whitelist_networks = []
# FIX BUG-RESERVED-INIT: _protected_networks bereits beim Modul-Import mit
# _RESERVED_NETS füllen, nicht erst in load_whitelist(). Sonst ist die Liste
# leer wenn is_protected_entry() vor load_whitelist() aufgerufen wird (z.B.
# in Tests die load_whitelist() nicht im setUp() haben). Dann liefert
# is_protected_entry("100.0.0.0/9") False, weil Python's is_private/is_reserved
# für teilweise-public Supernets False zurückgibt – der Reserved-Net-Overlap-
# Check fällt komplett aus.
_protected_networks = list(_RESERVED_NETS)

# FIX BUG-WL1-HARDENING: Loaded-Flag verhindert Fail-Open.
# Hintergrund: BUG-WL1 (08:37 UTC, 2026-04-26) entstand weil ein Job-Step
# is_whitelisted() aufrief OHNE vorher load_whitelist() ausgeführt zu haben.
# _whitelist_networks war leer, is_whitelisted() lieferte für jede IP False,
# und 8+ Google-/Microsoft-Service-IPs (52.123.128.14, 142.250.154.94, …)
# landeten in den ausgelieferten Blacklists. Symptom: Filterung wirkungslos,
# Diagnose erst durch workflow_health_checker im Nachhinein.
# Lösung: Statt Fail-Open (False = nicht-whitelisted = wird publiziert) jetzt
# Fail-Closed (RuntimeError, Workflow stirbt laut beim ersten Aufruf).
_whitelist_loaded = False


class WhitelistNotLoadedError(RuntimeError):
    """Wird geworfen wenn is_whitelisted() oder is_protected_entry() aufgerufen
    werden, bevor load_whitelist() lief. Verhindert das Fail-Open-Muster aus
    BUG-WL1."""
    pass


def _reset_whitelist_for_testing():
    """Setzt den Whitelist-State zurück. NUR für Tests."""
    global _whitelist_networks, _protected_networks, _whitelist_loaded
    _whitelist_networks = []
    _protected_networks = list(_RESERVED_NETS)
    _whitelist_loaded = False


def load_whitelist(path=".github/workflows/whitelist.json", min_entries=50):
    """Lädt whitelist.json und baut Netzwerk-Listen.

    Returns:
        list[ipaddress.IPv4Network]: Liste der Whitelist-Netzwerke.

    Raises:
        SystemExit: Wenn Datei nicht ladbar oder zu wenig Einträge.
    """
    global _whitelist_networks, _protected_networks, _whitelist_loaded
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        entries = raw["entries"]
        # FIX BUG-WL1-STRICT: 'entries' MUSS eine Liste sein. Vorher genuegte
        # ein String mit ausreichender Laenge dem min_entries-Check, weil
        # len("...") >= min_entries True ergab. Die nachfolgende Iteration
        # ueber Zeichen produzierte 0 valide Netzwerke und _whitelist_loaded
        # wurde trotzdem auf True gesetzt → exakt der BUG-WL1 Fail-Open-
        # Pfad, gegen den das Hardening eigentlich schuetzen sollte.
        if not isinstance(entries, list):
            msg = (f"whitelist.json: 'entries' ist {type(entries).__name__}, "
                   f"erwartet list")
            print(f"::error ::{msg}", file=sys.stderr)
            sys.exit(1)
        if len(entries) < min_entries:
            msg = f"whitelist.json hat nur {len(entries)} Einträge (<{min_entries}) – möglicherweise korrupt"
            print(f"::error ::{msg}", file=sys.stderr)
            sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        msg = f"whitelist.json nicht ladbar: {e}"
        print(f"::error ::{msg}", file=sys.stderr)
        sys.exit(1)

    # FIX BUG-WL-PARTIAL: Whitelist erst in eine lokale Variable bauen
    # und nur bei vollstaendigem Erfolg in das Modul-Global uebernehmen.
    # Vorher schrieben wir direkt in _whitelist_networks und konnten dann
    # via sys.exit(1) abbrechen – falls jemand SystemExit catcht (Tests,
    # Library-Use), bleibt _whitelist_networks halb-befuellt zurueck.
    # Trotz _whitelist_loaded=False sieht der Folge-Code (oder Tests die
    # _reset_whitelist_for_testing vergessen) eine 'Geister-Whitelist'.
    new_networks = []
    for entry in entries:
        try:
            new_networks.append(ipaddress.ip_network(entry, strict=False))
        except Exception:
            pass

    # FIX BUG-WL1-STRICT: Zweite Schwelle nach der Iteration. Eine Liste
    # mit min_entries Eintraegen die alle ungueltig sind (Schema-Drift,
    # Tippfehler, falsche Quote-Escapes) wuerde sonst silent zu einer
    # leeren Whitelist fuehren – wieder Fail-Open.
    if len(new_networks) < min_entries:
        msg = (f"whitelist.json: nur {len(new_networks)} valide Netzwerke "
               f"aus {len(entries)} Eintraegen geparst (<{min_entries}) – "
               f"Schema-Pruefung fehlgeschlagen")
        print(f"::error ::{msg}", file=sys.stderr)
        sys.exit(1)

    _whitelist_networks = new_networks

    # FIX BUG-PRIV2: Protected = Whitelist + alle reservierten IPv4-Bereiche
    # (RFC1918 + Loopback + Link-Local + CGNAT + Multicast + Reserved + Doc-Ranges).
    # Vorher wurden nur die 3 RFC1918-Ranges hinzugefuegt -> is_protected_entry
    # liess z.B. 169.0.0.0/8 durch (ueberlappt 169.254/16). Jetzt ueber die
    # unifizierte _RESERVED_NETS-Liste konsistent mit is_valid_public_cidr.
    _protected_networks = list(_whitelist_networks) + list(_RESERVED_NETS)
    # FIX BUG-WL1-HARDENING: Erst nach erfolgreichem Aufbau auf True setzen,
    # damit ein halb-fertiger State von is_whitelisted() noch als "nicht geladen"
    # erkannt wird.
    _whitelist_loaded = True

    print(f"whitelist.json geladen: {len(_whitelist_networks)} Einträge")
    return _whitelist_networks


def is_whitelisted(ip_str):
    """True wenn IP in einer der Whitelist-Ranges liegt.

    FIX BUG-WL1-HARDENING: Raised WhitelistNotLoadedError wenn vor dem ersten
    Aufruf kein load_whitelist() erfolgte. Verhindert das Fail-Open-Muster aus
    BUG-WL1, wo eine leere _whitelist_networks-Liste dazu führte, dass jede IP
    als "nicht whitelisted" galt und whitelisted Service-IPs publiziert wurden.
    """
    if not _whitelist_loaded:
        raise WhitelistNotLoadedError(
            "is_whitelisted() vor load_whitelist() aufgerufen. "
            "Jeder Workflow muss load_whitelist() früh im Init-Step aufrufen, "
            "bevor IPs gefiltert werden."
        )
    try:
        addr = ipaddress.ip_address(ip_str.split('/')[0])
        return any(addr in net for net in _whitelist_networks)
    except Exception:
        return False


def is_protected_entry(value):
    """True wenn eine IP/ein CIDR niemals in Listen landen darf.

    Prüft: Whitelist, RFC1918, Loopback, Multicast, Reserved, Link-Local,
    Unspecified, IPv6, zu große CIDRs (< /8).

    FIX BUG-WL1-HARDENING: Raised WhitelistNotLoadedError wenn die Whitelist
    nicht geladen wurde. Ohne die Whitelist würde diese Funktion zwar noch
    RFC1918/Reserved-Ranges abfangen (wegen _RESERVED_NETS-Init in Zeile 75),
    aber die explizit konfigurierten Service-IPs (Google/AWS/Cloudflare-Ranges)
    nicht – was genau der Leak-Vektor von BUG-WL1 war.
    """
    if not _whitelist_loaded:
        raise WhitelistNotLoadedError(
            "is_protected_entry() vor load_whitelist() aufgerufen. "
            "Jeder Workflow muss load_whitelist() früh im Init-Step aufrufen, "
            "bevor IPs gefiltert werden."
        )
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
    """True wenn gültige öffentliche IPv4-Adresse (nicht private/loopback/etc).

    FIX BUG-CGNAT1: Prueft zusaetzlich explizit gegen _RESERVED_NETS.
    Python's ipaddress-Modul markiert CGNAT (100.64.0.0/10, RFC 6598) nicht
    als is_private, obwohl die Adressen nie oeffentlich routbar sind. Ohne
    diesen Zusatzcheck rutschten Einzel-IPs aus dem CGNAT-Bereich durch auf
    die Blacklist und konnten legitime ISP-Kunden treffen. Dies bringt
    is_valid_public_ipv4 in Deckung mit is_valid_public_cidr, das die
    Overlap-Pruefung bereits seit FIX BUG-PRIV1 macht.
    """
    try:
        obj = ipaddress.ip_address(ip)
        if not (obj.version == 4
                and not obj.is_private and not obj.is_loopback
                and not obj.is_multicast and not obj.is_unspecified
                and not obj.is_reserved and not obj.is_link_local):
            return False
        # FIX BUG-CGNAT1: Zusaetzlicher Check gegen explizite Liste,
        # weil stdlib CGNAT/Doc-Ranges nicht immer als private markiert.
        return not any(obj in net for net in _RESERVED_NETS)
    except Exception:
        return False


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
        for priv in _RESERVED_NETS:
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

    Parameter-Defaults (FIX DOC-DEFAULTS):
        - days_seen=1 bedeutet "heute zum ersten Mal bestaetigt" → 2 Pkt
          Persistenz. NICHT null – der FIX BUG-5-Kommentar bezieht sich
          auf expliziten Aufruf mit days_seen=0 (noch nie bestaetigt).
        - days_since_last=999 → Bucket >30 Tage → 0 Pkt Aktualitaet.
        - today_count=0, feed_count=0 → 0 Pkt Quellen-Qualitaet (sofern
          is_hq=False).
        - days_known=0 → 0 Pkt Bekannt seit.
        → Minimaler Score bei komplettem Default-Aufruf: 2 (Persistenz
          fuer "aktuell gesehen"). Ruft niemand so auf.

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

    # Counts (today_count, feed_count) sind monoton nicht-negativ,
    # negativ ist hier semantisch "nichts gesehen" → 0.
    today_count = max(0, today_count)
    feed_count  = max(0, feed_count)

    # FIX BUG-NEG-AGE: Aged-Werte NICHT via max(0, x) klemmen.
    # Vorheriger Kommentar wollte verhindern, dass korrupte seen_db-
    # Eintraege "versehentlich hohe Scores" erzeugen – aber genau das
    # passierte: max(0, -1) = 0, und days_since_last <= 1 vergibt volle
    # 30 Punkte fuer Aktualitaet. Eine IP mit kaputtem Datums-Diff
    # (Clock-Drift, Future-Timestamp, Schema-Drift in seen_db) sah
    # damit aus wie "heute frisch bestaetigt" ohne jeden Quellen-Bezug.
    # Korrekt: negativ ⇒ unbekannt, auf den jeweiligen "Score-0"-Bucket
    # mappen (days_since_last=999 → 0 Pkt, days_seen/days_known=0 → 0 Pkt).
    if days_since_last < 0:
        days_since_last = 999
    if days_seen < 0:
        days_seen = 0
    if days_known < 0:
        days_known = 0

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
    elif days_seen >= 1:
        score_c = 2
    else:
        # FIX BUG-5: days_seen=0 bedeutet "noch nie stark bestätigt"
        # (Watchlist-IPs ohne HQ). Vorher gab der else-Zweig +2 Punkte
        # für genau diesen Fall → systematische Score-Inflation für
        # jede Neu-IP. Korrekt: 0 Punkte Persistenz ohne Bestätigungstag.
        score_c = 0

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
    """Prueft Hostname auf oeffentliche IPs und gibt die aufgeloesten
    IPs zurueck (fuer IP-Pinning gegen DNS-Rebinding).

    Schützt fetch_url gegen SSRF: kein localhost, kein RFC1918,
    kein Link-Local (inkl. 169.254.169.254 Cloud-Metadata), kein Loopback,
    keine Carrier-Grade NAT (100.64.0.0/10), keine Multicast/Reserved.

    FIX IPV4-ONLY: NETSHIELD verwendet projektweit ausschliesslich IPv4
    (siehe _RESERVED_NETS, parse_entries, alle Validatoren). IPv6-Records
    eines Hosts werden uebersprungen, statt durchzulassen und spaeter in
    _pinned_getaddrinfo silent gefiltert zu werden – das fuehrte bei
    Hosts mit nur AAAA zu einer leeren getaddrinfo-Antwort und einem
    schwer diagnostizierbaren gaierror beim connect().

    Returns:
        list[str] | None: Liste der aufgeloesten oeffentlichen IPv4-IPs bei
        Erfolg. None wenn die Aufloesung fehlschlaegt, eine IPv4 unsicher
        ist oder gar keine IPv4 vorliegt.
    """
    import socket
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return None
    resolved = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return None
        # IPv6-Records ueberspringen, nicht ablehnen – ein Host darf
        # zusaetzlich AAAA haben, solange mindestens ein safe-public A da ist.
        if ip.version != 4:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return None
        # Gürtel + Hosenträger: is_global excluded auch Carrier-Grade NAT
        # (100.64/10) und einige weitere Reserved-Ranges explizit.
        if not ip.is_global:
            return None
        resolved.append(addr)
    return resolved or None


# FIX DNS-REBIND: Kontext-lokaler Storage fuer gepinnte Hostnamen.
# getaddrinfo wird innerhalb von fetch_url so gepatcht, dass fuer den
# validierten Host ausschliesslich die bereits geprueften IPs genutzt
# werden. Ein Angreifer-DNS kann nicht zwischen _validate() und
# opener.open() auf 127.0.0.1 / 169.254.169.254 umschwenken.
#
# FIX DNS-PIN-THREADSAFE: _patched und _original_getaddrinfo sind module-
# global (vorher: threading.local). Der globale socket.getaddrinfo-Patch
# ist prozessweit, aber bei threading.local sah jeder Thread '_patched =
# False' und versuchte erneut zu patchen – wobei er den BEREITS gepatchten
# getaddrinfo als '_original' speicherte. Folge: bei einem nicht-gepinnten
# Host fiel _pinned_getaddrinfo zurueck auf '_original' = sich selbst →
# RecursionError. Jetzt einmal pro Prozess patchen, mit Lock geschuetzt.
# pin_map bleibt threading.local damit gleichzeitige fetch_url-Aufrufe
# aus verschiedenen Threads sich nicht die Pins gegenseitig ueberschreiben.
import threading as _threading
_pin_state = _threading.local()
_install_lock = _threading.Lock()
_original_getaddrinfo = None  # gesetzt beim ersten _install_dns_pin()
_patched = False


def _install_dns_pin():
    """Aktiviert den getaddrinfo-Monkey-Patch (einmalig pro Prozess)."""
    import socket
    global _original_getaddrinfo, _patched
    # Double-checked locking: erster Check ohne Lock fuer den Hot-Path
    if _patched:
        return
    with _install_lock:
        if _patched:
            return
        _original_getaddrinfo = socket.getaddrinfo

        def _pinned_getaddrinfo(host, port, *args, **kwargs):
            pin_map = getattr(_pin_state, "pin_map", None)
            if pin_map and host in pin_map:
                # Bekanntes Pin → nur validierte IPs zurueckgeben
                ips = pin_map[host]
                # Port-Normalisierung: getaddrinfo akzeptiert int, str, None
                try:
                    port_int = int(port) if port is not None else 0
                except (TypeError, ValueError):
                    port_int = 0
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port_int))
                    for ip in ips
                    if ":" not in ip  # nur IPv4 (IPs aus _is_safe_public_host)
                ]
            # Modul-globaler Original-Verweis – kein Self-Reference moeglich.
            return _original_getaddrinfo(host, port, *args, **kwargs)

        socket.getaddrinfo = _pinned_getaddrinfo
        _patched = True


def _pin_host(hostname, ips):
    """Fuegt ein Hostname→IP-Mapping fuer die Dauer des Fetch hinzu."""
    _install_dns_pin()
    if not hasattr(_pin_state, "pin_map"):
        _pin_state.pin_map = {}
    _pin_state.pin_map[hostname] = ips


def _unpin_host(hostname):
    """Entfernt das Mapping nach dem Fetch."""
    pin_map = getattr(_pin_state, "pin_map", None)
    if pin_map and hostname in pin_map:
        del pin_map[hostname]


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

    pinned_hosts = []  # fuer finally-Cleanup

    def _validate(u):
        """Validiert URL und pinnt den Host auf die geprueften IPs.

        FIX DNS-REBIND: Rueckgabewert sind die validierten IPs, die
        direkt ins _pin_state-Mapping eingetragen werden. Der naechste
        socket.getaddrinfo-Aufruf (durch urllib intern) bekommt dann
        ausschliesslich diese IPs zurueck – ein Angreifer-DNS kann
        nicht zwischen Check und Connect wechseln.
        """
        parsed = urllib.parse.urlparse(u)
        if parsed.scheme not in ("http", "https"):
            print(f"  FEHLER Schema nicht erlaubt: {parsed.scheme}://")
            return False
        if not parsed.hostname:
            print(f"  FEHLER kein Hostname in URL: {u}")
            return False
        safe_ips = _is_safe_public_host(parsed.hostname)
        if not safe_ips:
            print(f"  FEHLER Host nicht öffentlich (SSRF-Schutz): {parsed.hostname}")
            return False
        # FIX DNS-REBIND: IPs pinnen, aber backward-kompatibel – wenn
        # _is_safe_public_host durch einen Test auf lambda h: True
        # gepatcht ist (legacy API), wird nicht gepinnt und der Fetch
        # laeuft ohne Rebind-Schutz weiter (Test-Kontext, kein Risiko).
        if isinstance(safe_ips, list):
            _pin_host(parsed.hostname, safe_ips)
            pinned_hosts.append(parsed.hostname)
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

    try:
        for attempt in range(1, retries + 1):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": user_agent})
                opener = urllib.request.build_opener(_SafeRedirect())
                with opener.open(req, timeout=timeout) as r:
                    # FIX READ-LIMIT: +1 Byte mehr lesen um Truncation zu erkennen.
                    # Wenn genau read_limit+1 gelesen werden konnte, war die Antwort
                    # groesser als der Limit und wir haben stillschweigend getrimmt.
                    # Das wurde sonst nie sichtbar und Feeds konnten IPs verlieren.
                    data = r.read(read_limit + 1)
                    if len(data) > read_limit:
                        print(f"  WARNUNG {url}: Response > {read_limit} bytes – "
                              f"Limit erhoehen sonst gehen Daten verloren")
                        data = data[:read_limit]
                    return data.decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                retryable = e.code in TRANSIENT_CODES or (e.code == 404 and _host_is_gh_raw)
                if retryable and attempt < retries:
                    print(f"  HTTP {e.code} {url} – Versuch {attempt}/{retries}, Retry...")
                    time.sleep(2 ** attempt)
                    continue
                print(f"  FEHLER HTTP {e.code} {url}")
                return None
            except urllib.error.URLError as e:
                # URLError kommt bei DNS-Fehlern, Connection-Refused, Timeouts
                # UND bei bewusst vom _SafeRedirect ausgelösten SSRF-Blocks.
                # SSRF-Blocks und URL-Schema-Fehler sind nicht transient – sofort
                # abbrechen statt 3× zu versuchen und dabei ~6s Backoff zu warten.
                msg = str(e.reason) if hasattr(e, "reason") else str(e)
                non_transient = (
                    "Redirect zu unsicherem Ziel blockiert" in msg
                    or "unknown url type" in msg.lower()
                )
                if non_transient or attempt >= retries:
                    print(f"  FEHLER {url}"
                          + (f" (nach {retries} Versuchen)" if attempt >= retries else "")
                          + f": {e}")
                    return None
                time.sleep(2 ** attempt)
            except Exception as e:
                if attempt < retries:
                    time.sleep(2 ** attempt)
                else:
                    print(f"  FEHLER {url} (nach {retries} Versuchen): {e}")
        return None
    finally:
        # FIX DNS-REBIND: Pin-Mapping wieder entfernen damit spaetere
        # Aufrufe mit anderen URLs nicht gestale IPs bekommen.
        for h in pinned_hosts:
            _unpin_host(h)


# ═══════════════════════════════════════════════════════════════
# seen_db Hilfsfunktionen
# ═══════════════════════════════════════════════════════════════

def _fsync_dir(dir_path):
    """FIX DIR-FSYNC: os.replace ist auf POSIX erst durable, wenn das
    Parent-Directory gefsyncted wurde. Ohne das kann nach Power-Loss der
    Rename verloren gehen, selbst wenn os.replace bereits returnt hat.

    In GitHub-Actions-Runnern (VMs) ist das Risiko gering, aber wenn
    netshield_common als Library in anderen Umgebungen (Baremetal,
    Container mit tmpfs-overlay) genutzt wird, ist es notwendig.

    Auf Windows nicht unterstuetzt – os.open auf Directory schlaegt fehl.
    Failure beim fsync wird geloggt aber nicht propagiert: der eigentliche
    Write ist bereits erfolgreich und weitergeleitete Exceptions wuerden
    die Aufrufer in unklarem Zustand zuruecklassen.
    """
    try:
        dir_fd = os.open(dir_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return  # z.B. Windows, oder Directory existiert nicht
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)

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

    FIX SORT-FALLBACK: Bei einer einzelnen korrupten Entry fiel die
    gesamte Liste auf lexikalischen Sort zurueck (4.7 Mio IPs waeren
    dann "10.0.0.1" vor "2.3.4.5" → Firewall-Diffs werden riesig).
    Jetzt: korrupte Entries werden per-Element abgefangen und an's
    Ende sortiert, der Rest bleibt numerisch.

    Returns:
        list[str]: Sortierte Liste.
    """
    def _numeric_key(e):
        try:
            parts = tuple(int(x) for x in e.split('/')[0].split('.'))
            if len(parts) != 4 or any(p > 255 or p < 0 for p in parts):
                # Ungueltige Entry: sortiert nach hinten, lexikalisch untereinander
                return (1, (256, 256, 256, 256), e)
            return (0, parts, e)
        except (ValueError, AttributeError, TypeError):
            return (1, (256, 256, 256, 256), str(e))

    try:
        return sorted(ip_list, key=_numeric_key)
    except Exception:
        # Absoluter Fallback (sollte nie triggern da _numeric_key selbst safe ist)
        return sorted(ip_list, key=str)


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
        _fsync_dir(target_dir)  # FIX DIR-FSYNC
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
        _fsync_dir(target_dir)  # FIX DIR-FSYNC
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
        _fsync_dir(target_dir)  # FIX DIR-FSYNC
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
