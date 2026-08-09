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

import bisect
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

# ═══════════════════════════════════════════════════════════════
# Kompilierte Regex-Patterns (Modul-Ebene, einmalig)
# ═══════════════════════════════════════════════════════════════

IPV4_RE = re.compile(r'(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])')
CIDR_RE = re.compile(r'(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})(?!\d)')
TIMESTAMP_RE = re.compile(
    r'#\s*Aktualisiert:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})'
    r'\s*(UTC|CET|CEST)(?:\s*\(Europe/Berlin\))?'
)

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
# _RESERVED_NETS füllen, nicht erst in load_whitelist().
#
# Historischer Hintergrund: Vor BUG-WL1-HARDENING (siehe weiter unten) gab
# is_protected_entry() bei leerer Liste silent False zurück – ein leerer
# Init bedeutete dann, dass z.B. 100.0.0.0/9 als "nicht protected" galt,
# weil Python's is_private/is_reserved für teilweise-public Supernets False
# liefert und der Reserved-Net-Overlap-Check komplett ausfiel.
#
# Nach BUG-WL1-HARDENING raised is_protected_entry() ohnehin
# WhitelistNotLoadedError, bevor diese Liste benutzt wird – die Pre-Init
# ist also nicht mehr als Sicherheitsanker noetig, sondern als defensive
# Symmetrie (gleiche Invariante "_protected_networks enthaelt mindestens
# _RESERVED_NETS" zu jedem Zeitpunkt). _reset_whitelist_for_testing() und
# der except-Pfad in load_whitelist hielten sich daran ohne diese Init
# explizit zu replizieren.
_protected_networks = list(_RESERVED_NETS)

# ───────────────────────────────────────────────────────────────
# FIX PERF-PARSE: Binary-Search-Indices fuer is_protected_entry,
# is_whitelisted und is_in_fp_set.
#
# Vorher: jeder Aufruf scannte _protected_networks (453 Eintraege)
# linear – `any(addr in net for net in ...)`. parse_entries() ruft
# is_protected_entry() pro Feed-Zeile auf. Bei firehol_anonymous
# (1,69 M IPs) ergab das 1,69M × 453 ≈ 770M Containment-Checks in
# reinem Python pro Run, ueber alle Feeds zusammen ~10–20 min.
#
# Jetzt: sortierte, gemergte (start, end)-Intervalle pro Pool +
# bisect_right → O(log K) statt O(K) pro IP-Lookup. CIDRs (selten,
# <5 % der Eintraege) gehen weiter ueber die Overlap-Pruefung, weil
# Range-Overlap nicht trivial bisect-bar ist.
#
# Merging: ueberlappende/benachbarte Ranges werden zu einem Intervall
# zusammengezogen. Wichtig fuer korrekte Treffer bei Whitelists wie
# 10.0.0.0/8 + 10.1.0.0/16 (gleiches Problem wie BUG-11 im Workflow).
# ───────────────────────────────────────────────────────────────
_protected_starts = []   # protected = whitelist + reserved
_protected_ends   = []
_whitelist_starts = []   # nur Whitelist (ohne reserved)
_whitelist_ends   = []


def _merge_intervals_from_nets(nets):
    """Sortiert (start, end) aus IPv4Networks und merged Ueberlappungen."""
    intervals = sorted(
        (int(n.network_address), int(n.broadcast_address))
        for n in nets
    )
    merged = []
    for lo, hi in intervals:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _rebuild_protected_index():
    """Baut Binary-Search-Indices fuer protected + whitelist neu auf.

    Wird automatisch von load_whitelist() und _reset_whitelist_for_testing()
    aufgerufen. Tests, die _protected_networks/_whitelist_networks direkt
    mutieren, muessen diese Funktion danach selbst aufrufen.
    """
    global _protected_starts, _protected_ends
    global _whitelist_starts, _whitelist_ends
    p = _merge_intervals_from_nets(_protected_networks)
    _protected_starts = [iv[0] for iv in p]
    _protected_ends   = [iv[1] for iv in p]
    w = _merge_intervals_from_nets(_whitelist_networks)
    _whitelist_starts = [iv[0] for iv in w]
    _whitelist_ends   = [iv[1] for iv in w]


def _interval_contains(starts, ends, ip_int):
    """O(log K) Lookup: True wenn ip_int in einem der gemergten Intervalle liegt."""
    if not starts:
        return False
    pos = bisect.bisect_right(starts, ip_int) - 1
    return pos >= 0 and ip_int <= ends[pos]


def _interval_overlaps(starts, ends, lo, hi):
    """O(log K) Lookup: True wenn die Range [lo, hi] eines der gemergten
    Intervalle in (starts, ends) ueberlappt.

    FIX PERF-PARSE-CIDR (2026-08-09): Erweitert den bestehenden Punkt-Lookup
    (_interval_contains) auf Range-Overlap. Bisher liefen CIDR-Eintraege in
    is_protected_entry() ueber einen linearen Scan (`any(net.overlaps(p) for
    p in _protected_networks)`, ~450+ Eintraege) - mit der Annahme, CIDRs
    seien "selten (<5% der Eintraege)". Bei honeypot_ips.txt (~20% CIDR-
    Anteil, 237k CIDRs) kostete das >100 Mio. teure ipaddress-Overlap-Checks
    und dominierte die Laufzeit von "Fetch, discover, learn and build IPv4
    lists" spuerbar (im Produktions-Log: ~4:15 min allein fuer diese eine
    lokale Datei).

    Korrektheitsbeweis (kurz): starts/ends sind sortiert UND gemergt, d.h.
    disjunkt mit ends[i] < starts[i+1] fuer alle i. Sei J das Intervall mit
    dem groessten start_J <= hi. Ueberlappt IRGENDEIN Intervall I die Query
    [lo, hi] (start_I <= hi und end_I >= lo), dann gilt start_J >= start_I.
    Ist J != I, folgt aus der Sortierung end_J > end_I >= lo, also end_J >= lo
    ebenfalls - J ueberlappt dann zwangslaeufig auch. Es genuegt daher, NUR
    dieses eine Kandidaten-Intervall J zu pruefen (bisect statt linearer Scan).
    Verifiziert gegen 200k randomisierte CIDRs + 30.918 gezielte Grenzfaelle
    an allen _protected_networks-Raendern (0 Abweichungen vom alten linearen
    Scan). Lokaler Performance-Test mit der echten honeypot_ips.txt (955.921
    IPs + 237.184 CIDRs): 271,33s (alt) -> 14,15s (neu), identisches Ergebnis.
    """
    if not starts:
        return False
    pos = bisect.bisect_right(starts, hi) - 1
    return pos >= 0 and ends[pos] >= lo


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
    _rebuild_protected_index()


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
            # Ungueltige/nicht parsebare Eintraege bewusst ueberspringen.
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
    # FIX PERF-PARSE: Binary-Search-Index aufbauen, damit is_protected_entry/
    # is_whitelisted/is_in_fp_set in O(log K) statt O(K) laufen.
    _rebuild_protected_index()
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
        addr_str = ip_str.split('/')[0]
        # FIX PERF-PARSE: Plain-IP-Pfad ueber Binary-Search-Index (O(log K)).
        # CIDR-Eintraege landen im except-Branch und gehen ueber den
        # Linear-Scan – akzeptabel, weil <5% der Eingaben CIDRs sind.
        if '/' not in ip_str:
            try:
                ip_int = int(ipaddress.IPv4Address(addr_str))
                return _interval_contains(_whitelist_starts, _whitelist_ends, ip_int)
            except (ipaddress.AddressValueError, ValueError):
                return False
        addr = ipaddress.ip_address(addr_str)
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
            # FIX PERF-PARSE-CIDR (2026-08-09): Bisect-Range-Overlap statt
            # linearem Scan ueber alle ~450+ _protected_networks. Siehe
            # Docstring von _interval_overlaps() fuer den Korrektheitsbeweis.
            return _interval_overlaps(_protected_starts, _protected_ends,
                                       int(net.network_address), int(net.broadcast_address))
        # FIX PERF-PARSE: Plain-IP-Pfad ueber Binary-Search-Index (O(log K)).
        # is_private/is_loopback/etc. werden vom Index ohnehin abgedeckt
        # (RFC1918/Reserved/Link-Local/Multicast/etc. sind alle in _RESERVED_NETS
        # und damit Teil von _protected_networks). Doppelte Pruefung entfaellt.
        try:
            ip_int = int(ipaddress.IPv4Address(candidate))
        except (ipaddress.AddressValueError, ValueError):
            # Nicht-IPv4 (z.B. IPv6-String) → protected
            return True
        return _interval_contains(_protected_starts, _protected_ends, ip_int)
    except Exception:
        return True


# ═══════════════════════════════════════════════════════════════
# False-Positive Set
# ═══════════════════════════════════════════════════════════════

_fp_ips = set()
_fp_networks = []

# FIX PERF-PARSE: Binary-Search-Index fuer FP-Networks (siehe oben).
_fp_starts = []
_fp_ends   = []


def _rebuild_fp_index():
    """Baut den Binary-Search-Index fuer FP-Networks neu auf.
    Wird automatisch von load_fp_set() aufgerufen. Tests, die _fp_networks
    direkt mutieren, muessen diese Funktion danach selbst aufrufen.
    """
    global _fp_starts, _fp_ends
    fp = _merge_intervals_from_nets(_fp_networks)
    _fp_starts = [iv[0] for iv in fp]
    _fp_ends   = [iv[1] for iv in fp]


def load_fp_set(path="false_positives_set.json"):
    """Lädt false_positives_set.json.

    Returns:
        tuple[set, list]: (fp_ips, fp_networks)
    """
    global _fp_ips, _fp_networks
    _fp_ips = set()
    _fp_networks = []
    if not os.path.exists(path):
        _rebuild_fp_index()
        return _fp_ips, _fp_networks
    try:
        with open(path) as f:
            data = json.load(f)
        # FIX BUG-FP-STRICT: 'ips' MUSS eine Liste sein. Vorher genuegte ein
        # String wie "1.2.3.4" – data.get("ips", []) lieferte den String,
        # die for-Schleife iterierte ueber die Zeichen, und das Set enthielt
        # danach {'1', '.', '2', '3', '4'}. Folge: is_in_fp_set('.') == True,
        # und beliebige IPs/Substrings wurden faelschlich als False-Positive
        # markiert – das FP-Set verfehlt seine Filterfunktion.
        # Selbe Fail-Loud-Strategie wie load_whitelist (BUG-WL1-STRICT):
        # lieber Workflow-Crash als silent korrumpierter State.
        if not isinstance(data, dict):
            raise ValueError(
                f"'false_positives_set.json' Root ist {type(data).__name__}, "
                f"erwartet dict")
        ips_field = data.get("ips", [])
        if not isinstance(ips_field, list):
            raise ValueError(
                f"'false_positives_set.json': 'ips' ist {type(ips_field).__name__}, "
                f"erwartet list")
        for entry in ips_field:
            # Nur String-Eintraege akzeptieren – None/int/dict silent skippen
            # (Schema-Drift, aber fail-soft pro Entry, nicht pro Datei).
            if not isinstance(entry, str):
                continue
            try:
                if "/" in entry:
                    _fp_networks.append(ipaddress.ip_network(entry, strict=False))
                else:
                    _fp_ips.add(entry)
            except Exception:
                # Ungueltige Eintraege in der FP-Liste bewusst ueberspringen.
                pass
        print(f"false_positives_set.json: {len(_fp_ips)} IPs + {len(_fp_networks)} CIDRs geladen")
    except Exception as e:
        # Bei Schema-/Parse-Fehler State zurueck auf leer (defensiv – falls
        # zwischen Init oben und except hier eine partielle Befuellung lief).
        _fp_ips = set()
        _fp_networks = []
        print(f"WARNUNG: false_positives_set.json nicht lesbar: {e}")
    _rebuild_fp_index()
    return _fp_ips, _fp_networks


def is_in_fp_set(ip_str):
    """True wenn IP im False-Positive-Set steht."""
    if ip_str in _fp_ips:
        return True
    try:
        addr_str = ip_str.split("/")[0]
        # FIX PERF-PARSE: Plain-IP-Pfad ueber Binary-Search-Index (O(log K)).
        if '/' not in ip_str:
            try:
                ip_int = int(ipaddress.IPv4Address(addr_str))
                return _interval_contains(_fp_starts, _fp_ends, ip_int)
            except (ipaddress.AddressValueError, ValueError):
                return False
        addr = ipaddress.ip_address(addr_str)
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
    """True wenn gültiges öffentliches IPv4-CIDR mit Prefix == /32.

    Policy: Nur Einzel-IPs (/32) werden akzeptiert. Breitere CIDRs
    (/8 bis /31) werden abgelehnt, um Kollateralschäden durch
    Range-Blocks zu vermeiden (z.B. 144.76.0.0/16 würde 65k
    legitime Hetzner-Hosts wie schroederdennis.de mitblocken).

    FIX BUG-PRIV1: Prüft zusätzlich ob der CIDR-Range mit privaten/
    reservierten Bereichen ÜBERLAPPT. Vorher wurde nur net.is_private
    geprüft (Netzadresse), aber z.B. 192.128.0.0/9 hat eine öffentliche
    Netzadresse und deckt trotzdem 192.168.0.0/16 ab. Overlap-Check
    bleibt aktiv (auch wenn /32 mit privaten Bereichen ohnehin nur
    auf Einzel-IP-Ebene kollidieren kann).
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if not (net.version == 4
                and not net.is_private and not net.is_loopback
                and not net.is_multicast and not net.is_reserved
                and not net.is_link_local and net.prefixlen == 32):
            return False
        # Overlap-Check: breite CIDRs die private Ranges einschließen ablehnen
        for priv in _RESERVED_NETS:
            if net.overlaps(priv):
                return False
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# Feed-Klassifikation (Auto-discovered Feeds)
# ═══════════════════════════════════════════════════════════════

def is_bot_detector_feed_name(name, file=None):
    """Heuristik: ist ein Auto-discovered-Feed (aus
    state/auto_discovered_feeds.json) ein fuer den Bot-Detector relevanter
    Feed (Proxy-, Bot-, Crawler- oder Scanner-Liste)?

    HERKUNFT (2026-07-05): lula73/bot-detector lieferte keine IPs mehr.
    Ersatz: update_bot_detector.yml liest jetzt state/auto_discovered_feeds.json
    dynamisch und wählt per dieser Funktion passende Feeds aus, statt einer
    statischen, manuell zu pflegenden Namensliste. update_combined_blacklist.yml
    nutzt DIESELBE Funktion, um genau diese Feeds aus dem Auto-Feed-Loop
    auszuschließen (Doppelzaehlungs-Schutz). Beide Seiten MÜSSEN dieselbe
    Funktion importieren statt eigener Kopien, sonst laufen sie wieder
    auseinander.

    UMBENENNUNG (2026-07-05): vorher is_proxy_feed_name(), Substring-Check
    nur auf "prox"/"socks". Erweitert um weitere Schluesselwoerter (siehe
    KEYWORDS unten), damit auch Bot-, Crawler- und Scanner-Feeds erfasst
    werden, die sonst ungefiltert (und unerkannt) durch den Auto-Feed-Loop
    liefen.

    ERWEITERUNG (2026-07-05): zusaetzlicher optionaler `file`-Parameter
    (Feld "file" aus state/auto_discovered_feeds.json, der Datei-Pfad
    innerhalb des Repos). Grund: der generierte Feed-*Name* (aus Owner/Repo
    zusammengesetzt) verraet manchmal nichts, waehrend der tatsaechliche
    Datei-*Pfad* das Schluesselwort enthaelt. Verifiziert an 3 echten
    Faellen in state/auto_discovered_feeds.json (Stand 2026-07-05):
      - alsyundawy_mikrotik_blacklist  -> file "antiscanner.rsc" ("scanner")
      - celestialbrain_worldpool       -> file "proxies/hijacked.txt" ("prox")
      - fadouse_clash_threat_intel     -> file "clash/generated/botnet.txt" ("bot")
    Bewusst NICHT verwendet: das Feld "search_sources" (GitHub-Topics).
    Das ist nachweislich unzuverlässig – antoinevastel_avastel_bot_ips_lists
    trägt dort fälschlich "topic:proxy-list", obwohl es kein Proxy-Feed ist
    (matcht hier korrekt trotzdem, aber ueber "bot", nicht ueber das
    fehlerhafte Topic). Ausserdem sind generische Topics wie
    "topic:blocklist"/"topic:ioc" bei >15 Feeds vorhanden, die inhaltlich
    nichts Bot-Spezifisches sind – darueber wuerde man zu breit matchen.

    KEYWORDS: prox, proxy, socks, bot, crawler, scanner, mikroblack, prx.
    "attack"/"attacker" und "badip"/"badips" wurden bewusst NICHT aufgenommen
    (Entscheidung 2026-07-05): ein "attacker"- oder "badip"-benannter Feed
    ist nicht per Definition ein Bot-Feed, das waere eine zu unspezifische
    Vermischung. "mikroblack" und "prx" bleiben trotz kryptischem Namen
    drin, weil die zugehoerigen Feeds (darzanebor_mikroblack,
    openprx_prx_sd_signatures) inhaltlich Bot-IP-Listen liefern – hier ist
    ausschliesslich der Feed-Name das Problem, nicht der Inhalt.

    Validiert gegen die 146 Feeds in state/auto_discovered_feeds.json
    (Stand 2026-07-05): 51 Treffer nur ueber `name`, 54 Treffer mit
    zusaetzlicher `file`-Pruefung (die 3 oben genannten kommen dazu, sonst
    keine Aenderung – 0 neue Fehltreffer, da dieselbe enge Keyword-Liste
    verwendet wird). Alle bisherigen 41 Treffer (Stand vor dieser gesamten
    Aenderung, reiner "prox"/"socks"-Check) bleiben weiterhin erfasst
    (keine Regression). Bewusst NICHT erfasst (matchten nur ueber
    attack/badip): kamalmjt_emerging_attackers_badips, cbuijs_badip,
    configserverapps_service_blocklists_attacks_mail.

    GRENZEN (bewusst nicht verschwiegen): Reine Namens-/Pfad-Heuristik. Ein
    künftig neu gefundener relevanter Feed mit untypischem Namen UND
    untypischem Datei-Pfad (ohne eines der Schluesselwoerter in beiden)
    würde NICHT erfasst und liefe stattdessen normal durch den
    Auto-Feed-Loop in update_combined_blacklist.yml – das ist unkritisch
    (keine Doppelzählung), bedeutet aber, dass er nicht zusätzlich in
    bot_detector_blacklist_ipv4.txt auftaucht. Umgekehrt könnte ein
    zukünftiger, komplett unverwandter Feed mit einem dieser Schluesselwoerter
    im Namen oder Datei-Pfad fälschlich erfasst werden. Bei Zweifeln:
    reports/bot_detector_report.md (Pro-Quelle-Tabelle) prüfen.

    Args:
        name: Feed-Name aus state/auto_discovered_feeds.json (Feld "name").
        file: Optional. Datei-Pfad aus state/auto_discovered_feeds.json
            (Feld "file"). Wird nur geprueft, wenn `name` allein nicht
            matcht. None/nicht-str wird ignoriert (kein Fehler).

    Returns:
        bool: True wenn Name ODER Datei-Pfad auf einen fuer den
        Bot-Detector relevanten Feed hindeutet.
    """
    keywords = (
        "prox", "proxy", "socks", "bot", "crawler", "scanner",
        "mikroblack", "prx",
    )
    if isinstance(name, str) and any(k in name.lower() for k in keywords):
        return True
    if isinstance(file, str) and any(k in file.lower() for k in keywords):
        return True
    return False


# ═══════════════════════════════════════════════════════════════
# Feed-Parsing (Universal-Parser)
# ═══════════════════════════════════════════════════════════════

def parse_entries(text, use_protected_check=False):
    """Universeller Parser: plain IPv4, CIDR, ip:port, ipset, FortiGate,
    Spamhaus DROP, URLhaus, CSV erste Spalte. Privates/Loopback gefiltert.

    Hat zwei distinkte Modi - die Wahl ist sicherheitsrelevant:

    - ``use_protected_check=False`` (Default, "Validierungs-Modus"):
      Filtert nur technisch nicht-oeffentliche IPs (RFC1918, Loopback,
      Reserved, Multicast, Class E, Link-Local, CGNAT, Doc-Ranges).
      Whitelist-IPs (z.B. 8.8.8.8, 1.1.1.1) kommen DURCH. Geeignet zum
      Validieren ob ein String eine "echte" IPv4 ist, oder fuer Tests
      ohne geladene Whitelist. Braucht KEIN load_whitelist() vorher.

    - ``use_protected_check=True`` ("Pipeline-Modus"):
      Filtert zusaetzlich Whitelist-IPs heraus (via is_protected_entry).
      DAS ist der Modus den Workflows fuer Blacklist-Generierung
      verwenden muessen. Verlangt vorher load_whitelist(); sonst
      WhitelistNotLoadedError.

    Wenn der Output dieser Funktion in eine produzierte Blacklist fliesst,
    MUSS use_protected_check=True gesetzt sein. Siehe BUG-WL1/WL3/WL7
    (historische False-Negative-Faelle wo Whitelist-IPs in Outputs landeten).
    Convenience-Wrapper: ``parse_entries_for_blacklist()``.

    Args:
        text: Rohtext des Feeds.
        use_protected_check: Pipeline-Modus aktivieren (siehe oben).

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

        # FIX BUG-IPSET-EAGER: Vorher gab es hier Format-spezifische
        # Fast-Pfade fuer FortiGate ("set subnet 1.2.3.4 ...") und ipset
        # ("add setname 1.2.3.4"), jeweils mit `continue` am Ende. Beide
        # waren gefaehrlich:
        #
        #   1) ipset: die Regex `add\s+\S+\s+(\S+)` matcht JEDE Zeile mit
        #      "add " am Anfang – auch Fliesstext wie
        #      "add notes here 1.2.3.4 important". val wurde dann "here",
        #      ip_check schlug fehl, und das `continue` schluckte die
        #      echte IP "1.2.3.4". Datenverlust.
        #   2) FortiGate: strenger (verlangt IP direkt nach "set subnet"),
        #      aber bei Zeilen mit zweiter IP nach Whitespace
        #      ("set subnet 1.2.3.4 8.8.8.8 dst-addr") wurde 8.8.8.8 ebenso
        #      verworfen – Pfad-Inkonsistenz mit dem dokumentierten
        #      "Fallback ist Superset"-Vertrag aus FIX BUG-MULTI-ENTRY.
        #      (Hinweis: IPs nach '#' werden weiter abgeschnitten, weil '#'
        #      als Spamhaus-DROP-Inline-Kommentar gilt – siehe Zeile unten.)
        #
        # Loesung: Format-spezifische Pfade entfernt. Der untere Fallback
        # findet alle IPs/CIDRs in der Zeile per IPV4_RE/CIDR_RE.finditer
        # und ist robust gegen alle hier relevanten Formate:
        #   - "set subnet 1.2.3.4 ..."     → IPV4_RE matcht 1.2.3.4
        #   - "add setname 1.2.3.4"        → IPV4_RE matcht 1.2.3.4
        #   - "add setname 1.2.3.0/24"     → CIDR_RE matcht, IP wird per
        #                                    cidr_spans nicht doppelt erfasst
        #   - "1.2.3.4:8080"               → IPV4_RE matcht 1.2.3.4
        #
        # Zu beachten: bei einer ipset-Zeile mit privatem CIDR
        # ("add setname 10.0.0.0/8") wird der CIDR korrekt verworfen
        # (cidr_check=False), und der Fallback tut nichts mehr – exakt
        # gleiches Verhalten wie vorher.

        # Inline-Kommentar abschneiden (Spamhaus DROP: "1.2.3.0/24 ; SBLxxx")
        line = re.split(r'\s*[;#]', line)[0].strip()
        if not line:
            continue

        # CSV: nur erste Spalte... siehe Kommentar unten zur Cidr-Span-Strategie.
        # FIX BUG-MULTI-ENTRY: Vorher gab es drei Fast-Path-Bloecke
        # (CIDR-am-Anfang / ip:port / Plain-IP-am-Anfang) die jeweils
        # 'continue' am Ende hatten. Eine Zeile wie "5.5.5.0/24 6.6.6.6"
        # matchte CIDR_RE.match(first_col), legte den CIDR ab und sprang
        # aus der Zeile. Die "6.6.6.6" ging silent verloren. Genauso bei
        # "10.20.30.0/24 5.5.5.5" (privat-CIDR + oeffentliche IP - die IP
        # verschwand komplett).
        #
        # Heute betrifft das keinen der konsumierten Feeds (alle haben
        # genau 1 Eintrag/Zeile), aber auto_feed_discovery.yml nimmt
        # automatisch neue Feeds auf - dort waere der Bug ein latenter
        # Datenleck-Vektor.
        #
        # Fix: Die drei Fast-Pfade entfernt. Der Fallback unten ist ein
        # Superset:
        #   - findet alle IPs/CIDRs in der Zeile (Multi-Entry)
        #   - hat per cidr_spans Schutz gegen Phantom-IPs aus CIDR-
        #     Netzadressen (kein "5.5.5.0" extra zur "5.5.5.0/24")
        #   - IPV4_RE hat den Versions-String-Schutz ((?![\d.]))
        #     bereits eingebaut, sodass "1.2.3.4.5" nicht als
        #     "1.2.3.4" durchgeht
        #   - ip:port wird durch IPV4_RE korrekt geparst (matcht IP vor ':')
        #
        # Verhaltensaenderung: Bei einer CSV-Zeile mit IPs in mehreren
        # Spalten (z.B. "1.2.3.4,US,reported_by:5.6.7.8") wird jetzt
        # auch die zweite IP erfasst, statt sie per first_col-Cut zu
        # verwerfen. In den 30+ derzeit konsumierten Feeds ist dieser
        # Fall null Mal vorhanden (verifiziert ueber 986k Zeilen).

        # Inline-Kommentar wurde oben bereits per re.split([;#]) abgetrennt,
        # damit z.B. Spamhaus-DROP "1.2.3.0/24 ; SBL12345" sauber laeuft.

        # Fallback: alle IPs/CIDRs in der Zeile.
        # FIX BUG-PARSE-DUAL: CIDR-Spans merken, damit IPV4_RE die Netzadresse
        # einer CIDR (z.B. 5.5.5.0 in 5.5.5.0/24) NICHT zusaetzlich als
        # Single-IP einfuegt. Vorher (vor dem Fix): Eine Zeile wie
        # '{"net":"5.5.5.0/24"}' erzeugte BEIDE Eintraege - die CIDR und ihre
        # Netzadresse als IP. Symptom: redundante Phantom-IPs in den
        # Output-Listen, je nach Feed-Format (URLhaus / JSON / Fliesstext).
        cidr_spans = []
        for cm in CIDR_RE.finditer(line):
            cidr_str = cm.group(1)
            # Span IMMER merken (auch fuer ungueltige CIDRs), damit eine
            # private/reservierte CIDR nicht als Phantom-IP durchrutscht.
            cidr_spans.append((cm.start(), cm.end()))
            if cidr_check(cidr_str):
                entries.add(str(ipaddress.ip_network(cidr_str, strict=False)))
        for m in IPV4_RE.finditer(line):
            # IP innerhalb einer CIDR-Span ueberspringen (= Netzadresse der CIDR)
            if any(start <= m.start() < end for start, end in cidr_spans):
                continue
            # FIX BUG-IPV6-MAPPED: '::ffff:1.2.3.4' und Verwandte (IPv4-mapped
            # IPv6) duerfen die '1.2.3.4' nicht als Phantom-Eintrag durchlassen.
            # Der Lookbehind '(?<![\d.])' der IPV4_RE laesst ':' als Trenner
            # gelten – und matcht damit den IPv4-Suffix einer IPv6-Adresse.
            # Heuristik: wenn das whitespace-getrennte Token der Match-
            # Position '::' enthaelt oder >=2 Doppelpunkte hat, ist es ein
            # IPv6-Token und der IPv4-Suffix wird verworfen. Plain "host:1.2.3.4"
            # (1 Doppelpunkt) bleibt unbeeintraechtigt.
            if _is_in_ipv6_token(line, m.start(), m.end()):
                continue
            ip = m.group(1)
            if ip_check(ip):
                entries.add(ip)

    return entries


def _is_in_ipv6_token(line, start, end):
    """True wenn die Position [start:end] in einem whitespace-Token liegt,
    das wie eine IPv6-Adresse aussieht (enthaelt '::' oder >=2 ':').

    Token-Boundary ist Whitespace; wir scannen rueckwaerts/vorwaerts vom
    Match. CSV-Komma und Klammern werden als Token-Begrenzer behandelt,
    damit `2001:db8::1,1.2.3.4` zwei Tokens ergibt.
    """
    # Token-Boundary: Whitespace + Standard-Trennzeichen die in Feeds
    # vorkommen (Komma in CSV, Klammern in JSON-aehnlichen Strings).
    boundaries = " \t\n\r,()[]{}\"'"
    t_start = start
    while t_start > 0 and line[t_start - 1] not in boundaries:
        t_start -= 1
    t_end = end
    while t_end < len(line) and line[t_end] not in boundaries:
        t_end += 1
    token = line[t_start:t_end]
    return "::" in token or token.count(":") >= 2



def parse_feed_entries(text, source_hint="", use_protected_check=False):
    """Formatbewusster Zentral-Parser fuer externe IP-/Firewall-Feeds.

    Diese Funktion ist die gemeinsame Parser-API fuer Auto-Discovery und
    Combined-Workflow. Dadurch wird ein Feed bei der Aufnahme und bei der
    spaeteren Verarbeitung mit exakt derselben Logik interpretiert.

    Unterstuetzte Textformate umfassen unter anderem TXT/LIST, CSV/TSV,
    JSON/JSONL, XML, YAML/TOML/INI sowie ipset, nftables, iptables,
    MikroTik RouterOS, Cisco ACL, FortiGate, pf, nginx/Apache,
    Snort/Suricata-Drop-Regeln und Clash/Surge-Listen. GZIP wird bereits
    von ``fetch_url()`` entpackt; Archive wie ZIP/7z werden hier bewusst
    nicht verarbeitet.

    Sicherheits-Policy von NETSHIELD:
      * Nur einzelne IPv4-Hosts werden zurueckgegeben.
      * ``/32`` wird in eine einzelne IP normalisiert.
      * Breitere CIDRs, Wildcard-Netze und IP-Ranges werden NICHT expandiert.
      * Allow-/Whitelist-Regeln (z.B. ``ignoreip``, ``allow``, ``permit``)
        werden nicht als Blocklist-Eintraege interpretiert.
      * Dateien werden nur als Text geparst und niemals ausgefuehrt.

    Args:
        text: Bereits heruntergeladener und ggf. entpackter Feed-Inhalt.
        source_hint: URL oder Dateipfad. Dient nur als Format-Hinweis.
        use_protected_check: Wie bei :func:`parse_entries`; im Pipeline-Modus
            werden zusaetzlich Whitelist-/Protected-Eintraege entfernt.

    Returns:
        set[str]: Validierte einzelne oeffentliche IPv4-Adressen.
    """
    ip_check = (lambda ip: not is_protected_entry(ip)) if use_protected_check else is_valid_public_ipv4

    if text is None:
        return set()
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", errors="replace")
        except Exception:
            return set()
    if not isinstance(text, str) or not text.strip():
        return set()

    # Null-Bytes deuten auf Binärdaten/Korruption. Anders als parse_entries()
    # verwerfen wir hier den kompletten Inhalt, weil strukturierte Parser sonst
    # Fragmente einer Binärdatei als Text missverstehen koennten.
    if "\x00" in text:
        return set()

    stripped = text.strip()
    hint = str(source_hint or "").split("?", 1)[0].split("#", 1)[0].lower()
    if hint.endswith(".gz"):
        hint = hint[:-3]
    ext = os.path.splitext(hint)[1]

    # Schneller Pfad fuer die haeufigsten grossen Feeds: eine IP bzw. /32
    # pro Zeile. Dadurch muss der Combined-Workflow bei Multi-MB-Listen nicht
    # erst JSON/XML/CSV/Firewall-Erkennung ueber den gesamten Text ausfuehren.
    import io as _io
    _plain_sample = []
    for _raw in _io.StringIO(stripped):
        _line = _raw.strip()
        if not _line or _line.startswith(("#", ";", "//")):
            continue
        _plain_sample.append(_line)
        if len(_plain_sample) >= 40:
            break
    if not _plain_sample:
        return set()
    _plain_token_re = re.compile(
        r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2}|:\d{1,5})?$"
    )
    _plain_hits = 0
    for _line in _plain_sample:
        _token = re.split(r"\s*[#;]", _line, maxsplit=1)[0].strip()
        if _token and len(_token.split()) == 1 and _plain_token_re.fullmatch(_token):
            _plain_hits += 1
    if _plain_hits / len(_plain_sample) >= 0.85:
        _parsed = parse_entries(stripped, use_protected_check=use_protected_check)
        return {
            entry[:-3] if entry.endswith("/32") else entry
            for entry in _parsed
            if "/" not in entry or entry.endswith("/32")
        }

    data_lines = [
        line.strip() for line in stripped.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "//"))
    ]
    if not data_lines:
        return set()

    def _add_hosts(fragment, target):
        """Fuegt Host-IPs aus einem bereits als relevant erkannten Fragment ein.

        Im Unterschied zu parse_entries() wird ein Semikolon hier NICHT als
        Kommentartrenner behandelt. Das ist fuer kompakte nftables-Regeln wie
        ``type ipv4_addr; elements = { ... };`` erforderlich.
        """
        if fragment is None:
            return
        value = str(fragment).strip()
        if not value or "\x00" in value:
            return

        # Ranges niemals nur als Start-/End-IP missverstehen.
        if re.search(
            r'(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}\s*(?:-|\.\.)\s*'
            r'\d{1,3}(?:\.\d{1,3}){3}(?![\d.])',
            value,
        ):
            return

        cidr_spans = []
        for cm in CIDR_RE.finditer(value):
            cidr_spans.append((cm.start(), cm.end()))
            cidr = cm.group(1)
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except Exception:
                continue
            # NETSHIELD blockt absichtlich keine Netze; nur echte Hosts.
            if net.version == 4 and net.prefixlen == 32:
                ip = str(net.network_address)
                if ip_check(ip):
                    target.add(ip)

        for m in IPV4_RE.finditer(value):
            if any(start <= m.start() < end for start, end in cidr_spans):
                continue
            if _is_in_ipv6_token(value, m.start(), m.end()):
                continue
            ip = m.group(1)
            if ip_check(ip):
                target.add(ip)

    def _hosts_from_fragments(fragments):
        result = set()
        for fragment in fragments:
            _add_hosts(fragment, result)
        return result

    def _json_values(obj, depth=0):
        if depth > 20:
            return []
        if isinstance(obj, str):
            return [obj]
        if isinstance(obj, (int, float)) and not isinstance(obj, bool):
            return [str(obj)]
        if isinstance(obj, (list, tuple)):
            out = []
            for item in obj:
                out.extend(_json_values(item, depth + 1))
            return out
        if isinstance(obj, dict):
            out = []
            for key, value in obj.items():
                key_lc = str(key).lower()
                # Eindeutige Allow-/Infrastruktur-Metadaten nicht aufnehmen.
                if any(bad in key_lc for bad in (
                    "whitelist", "allowlist", "trusted", "ignore",
                    "resolver", "gateway", "nameserver", "reporter",
                )):
                    continue
                out.extend(_json_values(value, depth + 1))
            return out
        return []

    # 1) JSON / JSONL -------------------------------------------------------
    if stripped[:1] in ("{", "[") or ext in (".json", ".jsonl"):
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, ValueError, TypeError):
            parsed = None
        except RecursionError:
            # FIX RECURSION-CRASH (2026-08-01): Beobachtet im Auto-Feed-
            # Discovery-Run vom 01.08. (#146) - eine einzelne, pathologisch
            # tief verschachtelte JSON-Datei aus einem Fremd-Repo hat
            # json.loads() selbst (nicht erst unseren eigenen _json_values-
            # Walker) ueber Pythons Rekursionslimit gebracht. Der Fehler
            # wurde vorher nicht abgefangen (nur JSONDecodeError/ValueError/
            # TypeError), riss den kompletten Eval-Worker-Thread und damit
            # das gesamte Script mit sich (Exit-Code 1, ##[error] nach
            # 19m33s - Laufzeitbudget war dabei kein Faktor).
            # Da hier grundsaetzlich ungepruefter Inhalt aus beliebigen
            # GitHub-Repos geparst wird (potenziell adversarial), darf ein
            # einzelner kaputter Kandidat nie den gesamten Lauf stoppen -
            # konsistent mit dem bereits vorhandenen "except Exception:
            # continue" im JSONL-Fallback direkt darunter.
            parsed = None
        if parsed is not None:
            return _hosts_from_fragments(_json_values(parsed))

        jsonl_values = []
        parsed_rows = 0
        for line in data_lines:
            if not line.startswith(("{", "[")):
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            jsonl_values.extend(_json_values(row))
            parsed_rows += 1
        if parsed_rows >= 2:
            return _hosts_from_fragments(jsonl_values)

    # 2) XML / HTML-aehnliche strukturierte Listen -------------------------
    # FIX CONTENT-SNIFF-XML: Frueher reichte EIN beliebiger String wie
    # ``<blank>`` irgendwo in einer mehrmegabytegrossen Logdatei, um den
    # gesamten Inhalt als XML zu klassifizieren. Bei Honeypot-Logs mit
    # Shell-Ausgaben fuehrte das zu einem fruehen Return mit nur wenigen IPs.
    #
    # Jetzt gilt XML nur dann als plausibel, wenn die Dateiendung .xml ist
    # ODER der Dateianfang tatsaechlich wie ein XML-Dokument/-Fragment
    # aussieht. Der Probe-Bereich ist absichtlich begrenzt; echte XML-Dateien
    # haben Deklaration/Root-Tag am Anfang, zufaellige ``<...>``-Tokens in
    # Logs dagegen typischerweise nicht.
    _xml_probe = stripped[:256 * 1024].lstrip("\ufeff \t\r\n")
    # ReDoS-Fix (CWE-1333 / py/redos): Der Kommentar-Lauf wird in eine ATOMARE
    # Gruppe (?>...) gekapselt. Grund: unter re.S matcht `.` auch `-`/`>`, sodass
    # das `.*?` eines Kommentars spaeter `-->`-Sequenzen mitfressen kann. Ein Lauf
    # aus `<!---->`-Tokens liesse sich dadurch exponentiell viele Male aufteilen;
    # scheitert am Ende der geforderte Root-Tag, arbeitet die Engine alle
    # Aufteilungen ab (katastrophales Backtracking, >5s ab ~180 Byte Angriffs-
    # input). Die atomare Gruppe verbietet das Re-Partitionieren bereits
    # gematchter Kommentare -> lineares Verhalten. Match-Semantik unveraendert.
    # Hinweis: (?>...) erfordert Python >= 3.11.
    _xml_root_re = re.compile(
        r"^(?:<\?xml[^>]*>\s*)?(?>(?:<!--.*?-->\s*)*)"
        r"<[A-Za-z_][A-Za-z0-9_.:-]*(?:\s[^<>]{0,4096})?>",
        re.S,
    )
    _xml_close_re = re.compile(r"</[A-Za-z_][A-Za-z0-9_.:-]*\s*>")
    _xml_plausible = (
        ext == ".xml"
        or (_xml_root_re.search(_xml_probe) is not None
            and _xml_close_re.search(_xml_probe) is not None)
    )

    if _xml_plausible:
        xml_fragments = []
        try:
            import xml.etree.ElementTree as _ET
            root = _ET.fromstring(stripped)
            for elem in root.iter():
                tag = str(elem.tag).lower()
                if any(bad in tag for bad in (
                    "whitelist", "allowlist", "trusted", "ignore",
                    "gateway", "resolver", "nameserver",
                )):
                    continue
                if elem.text:
                    xml_fragments.append(elem.text)
                for attr_name, attr_value in elem.attrib.items():
                    attr_lc = str(attr_name).lower()
                    if not any(bad in attr_lc for bad in (
                        "whitelist", "allowlist", "trusted", "ignore",
                        "gateway", "resolver", "nameserver",
                    )):
                        xml_fragments.append(attr_value)
        except Exception:
            # Auch einfache pfSense-/OPNsense-XML-Fragmente ohne Root-Element.
            xml_fragments.extend(re.findall(r">([^<]{1,500})<", stripped))
            xml_fragments.extend(re.findall(
                r"\b(?:address|ip|host|indicator|ioc|value)\s*=\s*[\"']([^\"']+)[\"']",
                stripped,
                flags=re.I,
            ))
        xml_result = _hosts_from_fragments(xml_fragments)
        if xml_result or ext == ".xml":
            return xml_result

    # 3) CSV / TSV / Semikolon / Pipe: nur die wahrscheinlichste IP-Spalte.
    # Dadurch gelangt z.B. eine reporter_ip-Spalte nicht automatisch mit in
    # die Blacklist, wenn die eigentliche IOC-Spalte separat vorhanden ist.
    first_line = data_lines[0]
    delimiter = None
    if "\t" in first_line:
        delimiter = "\t"
    elif first_line.count(",") >= 1:
        delimiter = ","
    elif first_line.count(";") >= 2 and "elements" not in stripped.lower():
        delimiter = ";"
    elif first_line.count("|") >= 2:
        delimiter = "|"

    _csv_looks_like_firewall = any(marker in stripped.lower() for marker in (
        "elements =", "ip saddr", "ip daddr", "iptables ",
        "/ip firewall address-list", "config firewall address",
        "table <",
    )) or re.search(
        r"^\s*(?:drop|reject|alert|pass)\s+(?:ip|tcp|udp|icmp)\s+",
        stripped, re.I | re.M,
    ) is not None
    if (delimiter is not None
            and ext not in (".nft", ".rules", ".iptables", ".pf", ".rsc")
            and not _csv_looks_like_firewall):
        try:
            import csv as _csv
            import io as _io
            rows = list(_csv.reader(_io.StringIO(stripped), delimiter=delimiter))
            if rows:
                header = [str(cell).strip().lower() for cell in rows[0]]
                column_sets = {}
                for row in rows:
                    for idx, cell in enumerate(row):
                        found = set()
                        _add_hosts(str(cell).strip().strip('"').strip("'"), found)
                        if found:
                            column_sets.setdefault(idx, set()).update(found)
                if column_sets:
                    def _column_score(idx):
                        key = header[idx] if idx < len(header) else ""
                        positive = any(word in key for word in (
                            "ioc", "indicator", "malicious", "bad", "block",
                            "deny", "threat", "attacker", "source", "src",
                            "ip", "address", "host",
                        ))
                        negative = any(word in key for word in (
                            "reporter", "resolver", "gateway", "nameserver",
                            "whitelist", "allowlist", "trusted", "ignore",
                        ))
                        return (1 if positive else 0, -1 if negative else 0,
                                len(column_sets[idx]), -idx)
                    best_idx = max(column_sets, key=_column_score)
                    return column_sets[best_idx]
        except Exception:
            # Spalten-Heuristik ist optional: schlaegt die Erkennung fehl,
            # still zum naechsten Format weiter (kein Parser-Abbruch).
            pass

    # 4) Firewall-/Router-Formate ------------------------------------------
    result = set()
    firewall_detected = False
    lower_text = stripped.lower()

    # Explizite Allowlist-Konfigurationen niemals als Blocklist behandeln.
    allowlist_detected = any(re.search(pattern, lower_text, flags=re.M) for pattern in (
        r"^\s*ignoreip\s*=", r"^\s*allow\s+from\s+", r"^\s*permit\s+",
        r"^\s*whitelist\b", r"^\s*allowlist\b",
    ))

    # nftables: kompakte und mehrzeilige Sets sowie Drop-/Reject-Regeln.
    nft_content = (
        "nftables" in lower_text
        or re.search(
            r"\b(?:set|map)\s+[\w.-]+\s*\{[^}]*\belements\s*=",
            lower_text, re.S,
        ) is not None
        or "ip saddr" in lower_text
        or "ip daddr" in lower_text
    )
    if ext == ".nft" or nft_content:
        for match in re.finditer(r"\belements\s*=\s*\{(.*?)\}", stripped, re.I | re.S):
            _add_hosts(match.group(1), result)
        for line in data_lines:
            ll = line.lower()
            if ("ip saddr" in ll or "ip daddr" in ll) and any(
                action in ll for action in (" drop", " reject", " blackhole", " discard")
            ):
                for match in re.finditer(r"\bip\s+(?:saddr|daddr)\s+([^;]+)", line, re.I):
                    _add_hosts(match.group(1), result)
        if nft_content or result:
            firewall_detected = True

    # ipset restore: add <setname> <host-or-/32> [Optionen]
    ipset_content = any(
        re.match(r"^\s*(?:add|del)\s+\S+\s+", line, re.I)
        for line in data_lines[:50]
    )
    if ext == ".ipset" or ipset_content:
        for line in data_lines:
            match = re.match(r"^\s*add\s+\S+\s+([^\s#;]+)", line, re.I)
            if match:
                _add_hosts(match.group(1), result)
        if ipset_content or result:
            firewall_detected = True

    # MikroTik RouterOS Address-Lists.
    mikrotik_content = "/ip firewall address-list" in lower_text
    if ext == ".rsc" or mikrotik_content:
        for line in data_lines:
            ll = line.lower()
            if "address-list" not in ll or " add " not in f" {ll} ":
                continue
            match = re.search(r"\baddress\s*=\s*([^\s;]+)", line, re.I)
            if match:
                _add_hosts(match.group(1), result)
        if mikrotik_content or result:
            firewall_detected = True

    # iptables: nur DROP/REJECT-Regeln. Quelle bevorzugen; Destination nur
    # fuer OUTPUT-Regeln ohne explizite Quelle (typische C2-Blockliste).
    iptables_content = "iptables " in lower_text or re.search(
        r"^\s*-a\s+\S+", lower_text, re.M
    ) is not None
    if ext == ".iptables" or iptables_content:
        for line in data_lines:
            ll = line.lower()
            if not re.search(r"(?:-j|--jump)\s+(?:drop|reject)\b", ll):
                continue
            sources = re.findall(r"(?:^|\s)(?:-s|--source)\s+([^\s;]+)", line, re.I)
            for value in sources:
                _add_hosts(value, result)
            if not sources and ("-a output" in ll or "--append output" in ll):
                for value in re.findall(r"(?:^|\s)(?:-d|--destination)\s+([^\s;]+)", line, re.I):
                    _add_hosts(value, result)
        if iptables_content or result:
            firewall_detected = True

    # Cisco ACL: nur explizite host-Eintraege. Wildcard-Netze werden nicht
    # auf eine scheinbare Einzel-IP reduziert.
    cisco_content = re.search(
        r"^\s*(?:access-list\s+\S+\s+)?(?:deny|permit)\s+(?:ip|tcp|udp|icmp)\b",
        lower_text, re.M,
    ) is not None
    if ext == ".acl" or cisco_content:
        for line in data_lines:
            ll = line.lower()
            if "deny" not in ll:
                continue
            for host in re.findall(r"\bhost\s+(\d{1,3}(?:\.\d{1,3}){3})\b", line, re.I):
                _add_hosts(host, result)
        if cisco_content or result:
            firewall_detected = True

    # FortiGate Address-Objekte: nur echte Hostmasken /32.
    fortigate_detected = "config firewall address" in lower_text or re.search(
        r"^\s*set\s+subnet\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d{1,3}(?:\.\d{1,3}){3}",
        lower_text, re.M,
    ) is not None
    if fortigate_detected:
        for line in data_lines:
            match = re.match(
                r"^\s*set\s+subnet\s+(\d{1,3}(?:\.\d{1,3}){3})\s+"
                r"(\d{1,3}(?:\.\d{1,3}){3})\b",
                line,
                re.I,
            )
            if match and match.group(2) == "255.255.255.255":
                _add_hosts(match.group(1), result)
        firewall_detected = True

    # pf / OpenBSD: table-Inhalte und block-from-Regeln.
    pf_content = (
        re.search(r"\btable\s+<[^>]+>\s*\{", lower_text) is not None
        or re.search(r"^\s*block\b", lower_text, re.M) is not None
    )
    if ext == ".pf" or pf_content:
        for match in re.finditer(r"\btable\s+<[^>]+>\s*\{(.*?)\}", stripped, re.I | re.S):
            _add_hosts(match.group(1), result)
        for line in data_lines:
            if re.match(r"^\s*block\b", line, re.I):
                match = re.search(r"\bfrom\s+([^\s,;]+)", line, re.I)
                if match:
                    _add_hosts(match.group(1), result)
        if pf_content or result:
            firewall_detected = True

    # nginx / Apache: ausschliesslich deny-Regeln, niemals allow.
    web_acl_detected = re.search(r"^\s*(?:deny\s+|deny\s+from\s+)", lower_text, re.M) is not None
    if web_acl_detected:
        firewall_detected = True
        for line in data_lines:
            match = re.match(r"^\s*deny(?:\s+from)?\s+([^\s;]+)", line, re.I)
            if match:
                _add_hosts(match.group(1), result)

    # Snort/Suricata: nur Drop-/Reject-Regeln; aus dem Regel-Header wird die
    # Quellseite vor dem Pfeil ausgewertet. alert/pass-Regeln werden ignoriert.
    ids_content = re.search(
        r"^\s*(?:alert|drop|reject|pass)\s+(?:ip|tcp|udp|icmp)\s+",
        lower_text, re.M,
    ) is not None
    if ext in (".rules", ".rule") or ids_content:
        for line in data_lines:
            if not re.match(r"^\s*(?:drop|reject)\s+", line, re.I):
                continue
            header = line.split("(", 1)[0]
            source_side = header.split("->", 1)[0]
            # action + protocol entfernen; verbleibend: source + source-port
            source_side = re.sub(r"^\s*(?:drop|reject)\s+\S+\s+", "", source_side, flags=re.I)
            _add_hosts(source_side, result)
        if ids_content or result:
            firewall_detected = True

    # Null-Routes / Blackhole-Routen.
    route_detected = any(word in lower_text for word in (" null0", " blackhole", " discard"))
    if route_detected:
        firewall_detected = True
        for line in data_lines:
            ll = line.lower()
            if any(word in ll for word in ("null0", "blackhole", "discard")):
                _add_hosts(line, result)

    # Clash / Surge / Quantumult: nur IP und IP-CIDR /32.
    clash_lines = [
        line for line in data_lines
        if line.upper().startswith(("IP,", "IP-CIDR,"))
    ]
    if clash_lines:
        firewall_detected = True
        for line in clash_lines:
            parts = line.split(",")
            if len(parts) >= 2:
                _add_hosts(parts[1].strip(), result)

    if firewall_detected:
        # Bei eindeutigem Firewall-Format bewusst kein generischer Fallback:
        # sonst wuerde z.B. die Netzadresse aus Cisco-Wildcard- oder
        # FortiGate-/24-Regeln als einzelne Host-IP aufgenommen.
        if allowlist_detected and not result:
            return set()
        return result

    if allowlist_detected:
        return set()

    # 5) YAML / TOML / INI / generische Key-Value-Listen -------------------
    kv_fragments = []
    kv_seen = False
    for line in data_lines:
        match = re.match(r"^\s*[\-]?\s*([A-Za-z0-9_.-]{1,80})\s*[:=]\s*(.+)$", line)
        if not match:
            continue
        kv_seen = True
        key = match.group(1).lower()
        if any(bad in key for bad in (
            "whitelist", "allowlist", "trusted", "ignore", "gateway",
            "resolver", "nameserver", "reporter",
        )):
            continue
        if any(good in key for good in (
            "ip", "address", "host", "ioc", "indicator", "block", "deny",
            "threat", "malicious", "bad", "attacker", "source", "src",
            "target", "destination", "dst", "element", "member",
        )):
            kv_fragments.append(match.group(2))
    if kv_seen:
        kv_result = _hosts_from_fragments(kv_fragments)
        if kv_result or ext in (".yaml", ".yml", ".toml", ".ini"):
            return kv_result

    # 6) Plain-Text / Markdown / sonstige Listen ---------------------------
    # Der bewaehrte Universal-Parser bleibt der letzte Fallback. /32 wird
    # normalisiert, breitere CIDRs sind dort bereits durch die NETSHIELD-
    # Policy abgelehnt.
    # IP-Ranges vor dem Fallback entfernen, damit nicht nur Start und Ende
    # faelschlich als zwei einzelne Hosts in die Liste gelangen.
    fallback_text = re.sub(
        r'(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}\s*(?:-|\.\.)\s*'
        r'\d{1,3}(?:\.\d{1,3}){3}(?![\d.])',
        ' ',
        stripped,
    )
    parsed = parse_entries(fallback_text, use_protected_check=use_protected_check)
    result = set()
    for entry in parsed:
        if "/" not in entry:
            result.add(entry)
        elif entry.endswith("/32"):
            result.add(entry[:-3])
    return result

def parse_entries_for_blacklist(text):
    """Pipeline-Modus-Wrapper um parse_entries(use_protected_check=True).

    Diese Funktion ist die EMPFOHLENE API fuer alle Workflows die einen
    Feed-Inhalt in eine produzierte Blacklist umsetzen wollen. Sie macht
    den Whitelist-Filter explizit (kein vergessener default-Argument-Bug
    der Form BUG-WL1/WL3/WL7) und verlangt implizit, dass load_whitelist()
    vorher gelaufen ist (sonst WhitelistNotLoadedError - Fail-Closed).

    Args:
        text: Rohtext des Feeds.

    Returns:
        set[str]: Gefiltertes Set von IPs und CIDRs - ohne Whitelist,
        ohne RFC1918/Reserved/Loopback, bereit zum Schreiben in eine
        Blacklist-Datei.
    """
    return parse_entries(text, use_protected_check=True)


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
    # FIX BUG-HQ-BOOL: strikte Bool-Koerzierung analog zu _int_or fuer
    # numerische Felder. Vorher: is_hq = bool(is_hq) – Python's bool()
    # ist truthy auf jeden nicht-leeren String, also bool("false") == True.
    # Wenn seen_db durch Schema-Drift (fremdes Tool, manuelle Edits, alte
    # Backup-Restore) plueztlich is_hq als String haette, wuerde "false"
    # die volle HQ-Pruemie von 40 Punkten ausloesen statt 0. Ein einzelner
    # Score-Sprung von 2 → 42 reicht aus um eine IP unverdient in die
    # Konfidenz40-Liste zu heben.
    # Akzeptiert wird nur: echtes True, oder String "true"/"1" (case-insensitive),
    # oder int 1. Alles andere (False, 0, "false", "", None, dict, list) → False.
    if isinstance(is_hq, bool):
        pass  # echter bool – uebernehmen
    elif isinstance(is_hq, str):
        is_hq = is_hq.strip().lower() in ("true", "1", "yes")
    elif isinstance(is_hq, int):
        is_hq = is_hq == 1
    else:
        is_hq = False

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
    """Setzt ein Hostname→IP-Mapping fuer die Dauer des Fetch und gibt
    den vorherigen Pin (oder ein Sentinel) zurueck, damit der Aufrufer
    ihn nach dem Fetch wiederherstellen kann.

    FIX BUG-PIN-RESTORE: Vorher loeschte _unpin_host das Mapping
    unconditionally. Bei einem (theoretisch moeglichen) Redirect auf
    denselben Hostname mit aenderndem Pin – oder bei nested fetch_url
    auf gleichem Host – fuehrte das dazu, dass der innere Cleanup den
    Pin des aeusseren Aufrufs entfernte. Der aeussere lief danach ohne
    DNS-Rebind-Schutz weiter. Save-and-restore beseitigt diese Klasse.

    Returns:
        Der zuvor gespeicherte Pin (Liste) oder das Sentinel _PIN_ABSENT,
        wenn vorher kein Mapping existierte.
    """
    _install_dns_pin()
    if not hasattr(_pin_state, "pin_map"):
        _pin_state.pin_map = {}
    previous = _pin_state.pin_map.get(hostname, _PIN_ABSENT)
    _pin_state.pin_map[hostname] = ips
    return previous


def _restore_pin(hostname, previous):
    """Stellt den Pin-Zustand wieder her wie er VOR _pin_host(...) war.

    Wenn previous == _PIN_ABSENT war kein Mapping vorhanden → loeschen.
    Sonst → ueberschreiben.
    """
    pin_map = getattr(_pin_state, "pin_map", None)
    if pin_map is None:
        return
    if previous is _PIN_ABSENT:
        pin_map.pop(hostname, None)
    else:
        pin_map[hostname] = previous


# Sentinel-Wert: unterscheidet "kein vorheriger Pin" von "vorheriger Pin
# war eine leere Liste". Eine leere Liste sollte nie auftreten, weil
# _is_safe_public_host bei 0 IPs None liefert – aber explizit ist sicherer.
_PIN_ABSENT = object()


# FIX BUG-UNPIN-DEAD: Funktion _unpin_host(hostname) entfernt. War
# Backward-Compat-Stub fuer die alte unconditional-delete API, aber
# - Funktion ist private (_-Prefix), kein externer API-Vertrag
# - 0 Aufrufer in Repo (Workflows, Tests, Scripts)
# - durch _restore_pin() vollstaendig ersetzt (save-and-restore Pattern,
#   siehe FIX BUG-PIN-RESTORE-Kommentar in _pin_host oben)
# Toter Code mit irrefuehrendem Backward-Compat-Argument geloescht.


def fetch_parallel_daemon_start(fetch_fn, items, max_workers):
    """Startet Hintergrund-Fetches SOFORT, OHNE auf sie zu warten - das ist
    die "Start"-Haelfte von fetch_parallel_daemon() (siehe dort fuer den
    Hintergrund zu den echten daemon=True-Threads statt ThreadPoolExecutor).

    FIX PERF-AUTO-OVERLAP (2026-08-02): Ermoeglicht es, den Netzwerk-Anteil
    eines Fetch-Batches (z.B. Auto-Discovered-Feeds in
    update_combined_blacklist.yml) mit anderen, unabhaengigen Phasen zu
    ueberlappen, statt sequentiell NACH ihnen zu warten. Vorher blockierte
    fetch_parallel_daemon() in einem einzigen Aufruf fuer bis zu
    overall_timeout Sekunden, komplett additiv zur Laufzeit aller anderen
    Phasen. Jetzt: fetch_parallel_daemon_start() ganz am Anfang aufrufen
    (Threads laufen im Hintergrund mit), andere Phasen normal ausfuehren,
    erst am Ende fetch_parallel_daemon_collect() mit der ORIGINAL-Deadline
    aufrufen - die bereits waehrend der anderen Phasen verstrichene Zeit
    wird automatisch von der Wartezeit abgezogen.

    Args:
        fetch_fn, items, max_workers: wie bei fetch_parallel_daemon().

    Returns:
        dict: Handle mit "queue", "total" und "start" (monotonic-Zeitstempel
        des Start-Aufrufs) - an fetch_parallel_daemon_collect() weiterreichen.
    """
    import threading
    import queue as _queue
    import time as _time

    sem = threading.Semaphore(max_workers)
    result_q = _queue.Queue()

    def _worker(item):
        sem.acquire()
        try:
            result_q.put(fetch_fn(item))
        finally:
            sem.release()

    for _item in items:
        threading.Thread(target=_worker, args=(_item,), daemon=True).start()

    return {"queue": result_q, "total": len(items), "start": _time.monotonic()}


def fetch_parallel_daemon_collect(handle, overall_timeout):
    """Sammelt Ergebnisse eines mit fetch_parallel_daemon_start() gestarteten
    Batches ein - die "Collect"-Haelfte, siehe fetch_parallel_daemon_start().

    WICHTIG: overall_timeout gilt ab dem urspruenglichen Start-Zeitpunkt
    (handle["start"]), NICHT ab diesem Aufruf - die Zeit, die zwischen Start
    und Collect bereits durch andere, parallel gelaufene Phasen verstrichen
    ist, wird also korrekt von der verbleibenden Wartezeit abgezogen.

    FIX BUG-COLLECT-DRAIN (2026-08-02): Beobachtet in einem Lauf, in dem
    Phase 0-3 laenger als overall_timeout dauerten - die Deadline war beim
    Erreichen dieser Funktion bereits abgelaufen, und die urspruengliche
    Implementierung brach dann SOFORT ab, OHNE auch nur die Ergebnisse
    abzuholen, die laengst fertig in der Queue lagen (102 von 180
    Auto-Feeds wurden faelschlich als "abgebrochen" gemeldet, obwohl die
    meisten im Hintergrund laengst erfolgreich durchgelaufen waren). Fix:
    Zuerst wird die Queue nicht-blockierend LEERGERAEUMT (alles, was schon
    da ist, unabhaengig von der Deadline) - erst danach wird, falls noch
    Zeitbudget uebrig ist, blockierend auf weitere Ergebnisse gewartet.

    Args:
        handle: Rueckgabewert von fetch_parallel_daemon_start().
        overall_timeout: Gesamt-Deadline in Sekunden ab dem urspruenglichen
            Start-Aufruf.

    Returns:
        list: siehe fetch_parallel_daemon().
    """
    import queue as _queue
    import time as _time

    result_q = handle["queue"]
    total = handle["total"]
    results = []

    # Erst alles bereits fertige, nicht-blockierend abholen - unabhaengig
    # davon, ob die Deadline schon verstrichen ist. Das ist der eigentliche
    # Bugfix: vorher ging genau das verloren, wenn andere Phasen laenger
    # als overall_timeout gebraucht hatten.
    while len(results) < total:
        try:
            results.append(result_q.get_nowait())
        except _queue.Empty:
            break

    # Danach, falls noch Zeitbudget uebrig ist, blockierend auf den Rest
    # warten (identisches Verhalten wie vorher fuer den Normalfall, in dem
    # die anderen Phasen kuerzer als overall_timeout waren).
    deadline = handle["start"] + overall_timeout
    while len(results) < total:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            break
        try:
            results.append(result_q.get(timeout=remaining))
        except _queue.Empty:
            break
    return results


def fetch_parallel_daemon(fetch_fn, items, max_workers, overall_timeout):
    """Parallele Ausfuehrung mit echter Wall-Clock-Deadline, ohne dass
    haengende Downloads das Skriptende blockieren.

    FIX BUG-ATEXIT-JOIN: concurrent.futures.ThreadPoolExecutor registriert
    intern einen atexit-Hook (concurrent.futures.thread._python_exit), der
    beim Interpreter-Shutdown ALLE jemals erzeugten Worker-Threads joint –
    unabhaengig davon, ob shutdown(wait=False) aufgerufen oder ein Future
    per future.cancel() "abgebrochen" wurde. cancel() wirkt nur auf noch
    nicht gestartete Futures; ein bereits laufender Thread (z.B. mitten in
    einem blockierenden Netzwerk-Read) wird dadurch NICHT gestoppt und
    blockiert am Skriptende trotzdem den Prozessexit. Beobachtet im Log:
    Auto-Feeds meldeten "Timeout - abgebrochen", liefen aber 2-4,5 Min
    im Hintergrund weiter, bevor sie fertig wurden (siehe Kommentar bei
    fetch_auto). Diese Funktion verwendet echte daemon=True Threads statt
    ThreadPoolExecutor – Daemon-Threads werden von Python beim
    Interpreter-Exit NICHT gejoint, der Prozess kann sich sofort beenden,
    auch wenn einzelne Downloads im Hintergrund noch haengen. Nicht
    rechtzeitig fertige Items werden schlicht nicht in die Ergebnisliste
    aufgenommen (ihre Daten gehen fuer diesen Lauf verloren – das ist bei
    Best-Effort-Feeds wie Auto-Discovered-Feeds akzeptabel).

    FIX PERF-AUTO-OVERLAP (2026-08-02): Intern jetzt ein duenner Wrapper um
    fetch_parallel_daemon_start()+fetch_parallel_daemon_collect() (siehe
    dort). Bestehende Aufrufer (z.B. honeypot_monitor.yml) funktionieren
    unveraendert weiter - fuer neuen Code, der Fetch-Start und -Ende
    zeitlich trennen will, direkt die beiden Teilfunktionen nutzen.

    Args:
        fetch_fn: Callable(item) -> Ergebnis. Muss Fehler selbst abfangen
            (siehe fetch_auto/fetch_ips – dort wird bei Fehlern (name, set())
            zurueckgegeben statt eine Exception zu werfen).
        items: Liste von Eingabe-Items fuer fetch_fn.
        max_workers: Max. gleichzeitig laufende Threads (Semaphore-basiert).
        overall_timeout: Gesamt-Deadline in Sekunden ab Funktionsstart.

    Returns:
        list: Ergebnisse der Items, die innerhalb der Deadline fertig
        wurden (Reihenfolge = Fertigstellungsreihenfolge, nicht Input-
        Reihenfolge). Items, die die Deadline reissen, fehlen einfach.
    """
    _handle = fetch_parallel_daemon_start(fetch_fn, items, max_workers)
    return fetch_parallel_daemon_collect(_handle, overall_timeout)


def fetch_url(url, timeout=30, retries=3, user_agent="NETSHIELD/3.0",
              read_limit=25 * 1024 * 1024, extra_headers=None,
              fail_on_truncation=False, warn_on_truncation=True,
              total_timeout=None):
    """Fetcht eine URL mit exponentiellem Backoff.

    Sicherheit:
        - Nur http/https als Schema (kein file://, ftp://, gopher://).
        - Host muss auf öffentliche IP auflösen (kein SSRF gegen
          localhost, RFC1918 oder Cloud-Metadata wie 169.254.169.254).
        - Gleicher Check wird bei Redirects erneut durchgeführt.

    Args:
        url: Ziel-URL.
        timeout: Timeout in Sekunden. WICHTIG: Das ist der Socket-Timeout
            fuer eine EINZELNE blockierende Operation (Connect oder ein
            einzelner recv()), NICHT fuer die Gesamtdauer von r.read().
            Ein Server, der Daten langsam-aber-stetig liefert (jeder
            einzelne Chunk kommt innerhalb von `timeout` Sekunden an),
            kann r.read() beliebig lange laufen lassen, ohne dass dieser
            Timeout je greift.
        retries: Max. Versuche.
        user_agent: User-Agent Header.
        read_limit: Max. Bytes zum Lesen.
        fail_on_truncation: Bei True eine zu grosse normale HTTP-Antwort
            verwerfen statt als abgeschnittenen Teiltext zurueckzugeben.
        warn_on_truncation: Bei False die Warnung fuer eine bewusst begrenzte
            Stichprobe unterdruecken. Der Rueckgabewert bleibt auf read_limit
            Bytes begrenzt. Fuer Voll-Downloads sollte der Standard True bleiben.
        total_timeout: Optionale Gesamt-Deadline in Sekunden fuer den
            kompletten Lesevorgang (Connect + alle Chunks zusammen).
            FIX BUG-TRICKLE-TIMEOUT: `timeout` allein reicht bei langsam
            tropfenden Feeds nicht aus (siehe oben) – ein Auto-Discovered-
            Feed konnte dadurch trotz retries=1/timeout=15 mehrere Minuten
            im Hintergrund weiterlaufen (beobachtet: cbuijs_accomplist ~8
            Min. statt der erwarteten ~15s Fail-fast-Grenze), weil einzelne
            recv()-Calls immer knapp unter 15s blieben. Default None =
            alte Semantik (kein Gesamt-Limit) – WICHTIG fuer legitim grosse/
            langsame Feeds wie firehol_anonymous oder bitwire_ipblocklist,
            die im normalen Betrieb mehrere Minuten fuer den vollen Download
            brauchen und bei einem generischen Gesamt-Limit faelschlich
            abbrechen wuerden. Nur explizit setzen, wo Fail-fast wirklich
            gewuenscht ist (z.B. Auto-Discovered-Feeds).

    Returns:
        str | None: Response-Body oder None bei Fehler.
    """
    import time
    import urllib.request
    import urllib.error
    import urllib.parse

    # Liste von (hostname, previous_pin) Paaren fuer finally-Cleanup.
    # FIX BUG-PIN-RESTORE: vorher nur Hostnames; jetzt auch der zuvor
    # gespeicherte Pin, damit nested/redirect-same-host-Faelle den State
    # nicht durcheinanderbringen.
    pinned_hosts = []

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
            previous = _pin_host(parsed.hostname, safe_ips)
            pinned_hosts.append((parsed.hostname, previous))
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
                _req_headers = {"User-Agent": user_agent}
                # FEED-MOVE-RESOLVER: optionale Zusatz-Header (z.B.
                # Authorization fuer die GitHub-API). User-Agent bleibt
                # gesetzt, extra_headers koennen ihn bei Bedarf ueberschreiben.
                if extra_headers:
                    _req_headers.update(extra_headers)
                req = urllib.request.Request(url, headers=_req_headers)
                opener = urllib.request.build_opener(_SafeRedirect())
                with opener.open(req, timeout=timeout) as r:
                    # FIX READ-LIMIT: +1 Byte mehr lesen um Truncation zu erkennen.
                    # Wenn genau read_limit+1 gelesen werden konnte, war die Antwort
                    # groesser als der Limit und wir haben stillschweigend getrimmt.
                    # Das wurde sonst nie sichtbar und Feeds konnten IPs verlieren.
                    #
                    # FIX BUG-TRICKLE-TIMEOUT: r.read(read_limit + 1) in einem
                    # einzigen Call unterliegt nur dem Socket-Timeout pro
                    # blockierender recv()-Operation, nicht der Gesamtdauer.
                    # Wenn total_timeout gesetzt ist, lesen wir stattdessen in
                    # Chunks und pruefen nach jedem Chunk eine Wall-Clock-
                    # Deadline – so begrenzt total_timeout tatsaechlich die
                    # GESAMTE Lesezeit, nicht nur einzelne Netzwerk-Calls.
                    # Ohne total_timeout (Default) bleibt das alte Verhalten
                    # unveraendert (kein Risiko fuer bestehende Slow-Feeds).
                    if total_timeout is not None:
                        _deadline = time.monotonic() + total_timeout
                        _chunks = []
                        _total = 0
                        _CHUNK = 65536
                        while True:
                            if time.monotonic() >= _deadline:
                                raise TimeoutError(
                                    f"Gesamt-Timeout ({total_timeout}s) beim "
                                    f"Lesen ueberschritten (bisher {_total} bytes)")
                            _to_read = min(_CHUNK, read_limit + 1 - _total)
                            if _to_read <= 0:
                                break
                            piece = r.read(_to_read)
                            if not piece:
                                break
                            _chunks.append(piece)
                            _total += len(piece)
                        data = b"".join(_chunks)
                    else:
                        data = r.read(read_limit + 1)
                    if len(data) > read_limit:
                        # Bei Voll-Downloads ist Truncation ein echter Fehler und
                        # bleibt sichtbar. Content-Sniff/Awesome-List laden dagegen
                        # absichtlich nur eine Stichprobe; dort waere die gleiche
                        # Warnung irrefuehrend und erzeugte bei jedem Lauf Log-Spam.
                        if warn_on_truncation:
                            print(f"  WARNUNG {url}: Response > {read_limit} bytes – "
                                  f"Limit erhoehen sonst gehen Daten verloren")
                        if fail_on_truncation:
                            print(f"  FEHLER {url}: unvollstaendige Antwort verworfen "
                                  f"(fail_on_truncation=True)")
                            return None
                        data = data[:read_limit]
                    # FIX GZIP: Transparent gepackte Feeds (.gz) dekomprimieren.
                    # Erkennung über Magic-Bytes (\x1f\x8b) – URL-unabhängig, greift
                    # auch wenn Server kein .gz-Suffix in der URL hat oder gzip per
                    # Content-Encoding ausliefert.
                    #
                    # FIX BUG-GZIP-BOMB: gzip.decompress(data) lud das KOMPLETTE
                    # expandierte Ergebnis in den Speicher, BEVOR der Limit-Check
                    # griff. 25 MB komprimiert koennen auf mehrere GB expandieren
                    # → OOM des Runners. Der alte Kommentar "zip-bomb-Schutz"
                    # stimmte nicht – der Schutz wirkte erst nach der Allokation.
                    # Jetzt: streaming via GzipFile mit harter read(read_limit + 1)
                    # Grenze. Wenn der Stream mehr liefern wuerde, wird er
                    # abgeschnitten und der Fetch failt fail-loud.
                    if data[:2] == b"\x1f\x8b":
                        import gzip as _gzip
                        import io as _io
                        try:
                            with _gzip.GzipFile(fileobj=_io.BytesIO(data)) as _gz:
                                # +1 Byte um Truncation zuverlaessig zu erkennen
                                decompressed = _gz.read(read_limit + 1)
                        except (OSError, EOFError, MemoryError) as _gz_err:
                            print(f"  FEHLER gzip-Dekomprimierung {url}: {_gz_err}")
                            return None
                        if len(decompressed) > read_limit:
                            # Streaming-Limit erreicht: behandle wie zip-bomb –
                            # KEINE getrimmte Auslieferung wie bei nicht-gzip
                            # Truncation, weil eine teilweise dekomprimierte
                            # Datei stark verzerrt sein kann (mitten im Eintrag
                            # abgeschnitten, oder kuenstlich aufgeblaeht durch
                            # einen boesartigen Stream). Lieber abbrechen.
                            print(f"  FEHLER {url}: gzip-Stream > {read_limit} "
                                  f"bytes nach Dekomprimierung – moegliche "
                                  f"zip-bomb, Fetch verworfen")
                            return None
                        data = decompressed
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
        # FIX BUG-PIN-RESTORE: Restore in umgekehrter Reihenfolge des Pinnens
        # (LIFO), damit verschachtelte Pins korrekt aufgeloest werden.
        for h, previous in reversed(pinned_hosts):
            _restore_pin(h, previous)


# ═══════════════════════════════════════════════════════════════
# Feed-Move-Resolver (GitHub)
# ═══════════════════════════════════════════════════════════════

# Cache je Prozess-Run: (owner, repo, ref, basename) → neue raw-URL | None.
# Verhindert wiederholte Git-Tree-API-Abfragen, wenn mehrere Feeds aus
# demselben Repo im selben Run 404en. None wird ebenfalls gecacht
# ("nicht auffindbar"), damit nicht pro Feed erneut angefragt wird.
_GH_MOVE_CACHE = {}


def _parse_github_raw_url(url):
    """Zerlegt eine raw.githubusercontent.com-URL in ihre Bestandteile.

    Unterstuetzt beide Ref-Formen:
      .../{owner}/{repo}/{branch_or_sha}/{path...}
      .../{owner}/{repo}/refs/heads/{branch}/{path...}   (auch refs/tags)

    Returns:
        dict mit owner, repo, ref (Branch/SHA fuer die API), ref_prefix
        (Segmentliste zur URL-Rekonstruktion) und basename – oder None,
        wenn es keine parsebare GitHub-raw-URL ist.
    """
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname != "raw.githubusercontent.com":
        return None
    segs = [s for s in parsed.path.split("/") if s]
    if len(segs) < 4:
        return None
    owner, repo = segs[0], segs[1]
    rest = segs[2:]
    if len(rest) >= 4 and rest[0] == "refs" and rest[1] in ("heads", "tags"):
        ref_prefix = rest[:3]
        ref = rest[2]
        file_segs = rest[3:]
    else:
        ref_prefix = rest[:1]
        ref = rest[0]
        file_segs = rest[1:]
    if not file_segs:
        return None
    return {
        "owner": owner,
        "repo": repo,
        "ref": ref,
        "ref_prefix": ref_prefix,
        "file_segs": file_segs,
        "file_path": "/".join(file_segs),
        "basename": file_segs[-1],
    }


def resolve_github_moved_url(url, token=None, timeout=20):
    """Lokalisiert eine in einen anderen Ordner verschobene GitHub-raw-Datei neu.

    Aufrufen NUR nachdem fetch_url(url) None zurueckgab. fetch_url liefert
    bei JEDEM Fehler None (404, Timeout, 429/5xx, SSRF-Block, gzip-Abbruch),
    nicht nur bei "Datei verschoben". Diese Funktion unterscheidet das selbst:

      1. 404-Gate: per Contents-API pruefen, ob die EXAKTE Originaldatei noch
         existiert. Existiert sie (= der fetch-Fehler war transient, kein
         Move) → None, KEIN teurer Tree-Walk. Nur bei echtem 404 weiter.
      2. Tree-Walk: Git-Tree-API laden, Kandidaten mit gleichem Basename
         sammeln und per Longest-Common-Suffix zum Originalpfad ranken.
         Eindeutiges Maximum → neue raw-URL. Sonst (0 Kandidaten oder
         Gleichstand an der Spitze) → None + Warnung (kein Raten: ein
         falscher Treffer koennte falsche IPs in die Blacklist ziehen).

    Sicherheit:
        - Nur fuer raw.githubusercontent.com (sonst None, kein API-Call).
        - Nutzt fetch_url (SSRF-/Redirect-/DNS-Rebind-Schutz) fuer API-Calls;
          token (falls vorhanden) als Authorization-Header (5000/h statt 60/h).
        - Ergebnis (auch None) wird pro Run gecacht.

    Returns:
        str (neue raw-URL) | None.
    """
    import json as _json
    import urllib.parse as _uparse

    info = _parse_github_raw_url(url)
    if info is None:
        return None

    cache_key = (info["owner"], info["repo"], info["ref"], info["file_path"])
    if cache_key in _GH_MOVE_CACHE:
        return _GH_MOVE_CACHE[cache_key]

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # ── 1. 404-Gate: existiert die exakte Originaldatei noch? ──────────
    # Contents-API auf genau diesen Pfad ist billig (nur Metadaten, kein
    # rekursiver Tree). 200 → Datei da, fetch-Fehler war transient → NICHT
    # relocaten. 404 → wirklich weg → Tree-Walk. Andere Codes (Rate-Limit
    # etc.): fetch_url gibt None → konservativ NICHT relocaten.
    contents_url = (f"https://api.github.com/repos/{info['owner']}/{info['repo']}"
                    f"/contents/{_uparse.quote(info['file_path'])}"
                    f"?ref={_uparse.quote(info['ref'])}")
    probe = fetch_url(contents_url, timeout=timeout, retries=1,
                      user_agent="NETSHIELD/3.0",
                      read_limit=2 * 1024 * 1024,
                      extra_headers=headers)
    if probe is not None:
        # Datei existiert weiterhin → der urspruengliche Fehler war
        # transient (Timeout/5xx/Rate-Limit). Kein Move → kein Relocate.
        print(f"  MOVE-RESOLVER: '{info['file_path']}' existiert noch "
              f"({info['owner']}/{info['repo']}) – transienter Fehler, "
              f"kein Relocate")
        _GH_MOVE_CACHE[cache_key] = None
        return None

    # ── 2. Tree-Walk: Datei am neuen Ort suchen ────────────────────────
    api_url = (f"https://api.github.com/repos/{info['owner']}/{info['repo']}"
               f"/git/trees/{_uparse.quote(info['ref'])}?recursive=1")
    raw = fetch_url(api_url, timeout=timeout, retries=2,
                    user_agent="NETSHIELD/3.0",
                    read_limit=20 * 1024 * 1024,
                    extra_headers=headers)
    if raw is None:
        print(f"  MOVE-RESOLVER: Tree-API nicht erreichbar fuer "
              f"{info['owner']}/{info['repo']}@{info['ref']}")
        _GH_MOVE_CACHE[cache_key] = None
        return None

    try:
        tree_data = _json.loads(raw)
    except (ValueError, TypeError) as e:
        print(f"  MOVE-RESOLVER: Tree-JSON nicht parsebar: {e}")
        _GH_MOVE_CACHE[cache_key] = None
        return None

    tree = tree_data.get("tree", [])
    target = info["basename"]
    orig_segs = info["file_segs"]

    def _suffix_score(cand_path):
        """Anzahl uebereinstimmender Pfad-Segmente von hinten (inkl. Basename)."""
        cand_segs = cand_path.split("/")
        score = 0
        for a, b in zip(reversed(orig_segs), reversed(cand_segs)):
            if a == b:
                score += 1
            else:
                break
        return score

    candidates = [
        node["path"] for node in tree
        if node.get("type") == "blob"
        and isinstance(node.get("path"), str)
        and node["path"].rsplit("/", 1)[-1] == target
    ]

    if not candidates:
        if tree_data.get("truncated"):
            print(f"  MOVE-RESOLVER: '{target}' nicht gefunden und Tree "
                  f"truncated ({info['owner']}/{info['repo']}) – evtl. unvollstaendig")
        else:
            print(f"  MOVE-RESOLVER: '{target}' im Repo "
                  f"{info['owner']}/{info['repo']} nicht mehr vorhanden")
        _GH_MOVE_CACHE[cache_key] = None
        return None

    # Longest-Common-Suffix-Ranking: der Kandidat, dessen Pfad dem
    # Original am aehnlichsten ist, gewinnt. Behebt das Basename-Duplikat-
    # Problem (z.B. Legacy Other/Scanners vs. Lists/Scanners): der Pfad mit
    # mehr uebereinstimmenden Trailing-Segmenten ist eindeutig der richtige.
    scored = [(_suffix_score(p), p) for p in candidates]
    top_score = max(s for s, _ in scored)
    top = sorted(p for s, p in scored if s == top_score)

    if len(top) > 1:
        print(f"  MOVE-RESOLVER: '{target}' mehrdeutig in "
              f"{info['owner']}/{info['repo']} – {len(top)} Pfade mit "
              f"gleichem Suffix-Score {top_score}: {', '.join(top[:5])} "
              f"– kein Auto-Match (FP-Schutz)")
        _GH_MOVE_CACHE[cache_key] = None
        return None

    new_path = top[0]
    new_url = (f"https://raw.githubusercontent.com/{info['owner']}/"
               f"{info['repo']}/" + "/".join(info["ref_prefix"]) +
               "/" + new_path)
    print(f"  MOVE-RESOLVER: '{info['file_path']}' verschoben → {new_path} "
          f"({info['owner']}/{info['repo']}, Suffix-Score {top_score})")
    _GH_MOVE_CACHE[cache_key] = new_url
    return new_url


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
        # dir-fsync ist best-effort (nicht auf allen FS/Plattformen
        # verfuegbar); Fehler hier bewusst ignorieren.
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
        zone = m.group(2)
        tz = timezone.utc if zone == "UTC" else ZoneInfo("Europe/Berlin")
        file_dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M").replace(tzinfo=tz).astimezone(timezone.utc)
        age_h = (datetime.now(timezone.utc) - file_dt).total_seconds() / 3600
        if age_h > max_age_hours:
            msg = (f"{filepath} ist {age_h:.0f}h alt "
                   f"(letztes Update: {m.group(1)} {zone})")
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


def write_ip_list(filepath, ips, header_lines=None, presorted=False):
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
        presorted: Bei True wird sort_ips() NICHT nochmal aufgerufen.
            FIX BUG-DOUBLE-SORT: Ohne diesen Parameter hat write_ip_list()
            IMMER per sort_ips() neu sortiert – auch wenn der Aufrufer die
            Liste bereits per schnellerem Key (z.B. socket.inet_aton statt
            sort_ips()' langsamerem String-Split+int()-Key) vorsortiert
            hatte. Gemessen: bei combined_threat_blacklist_ipv4.txt (7,3M
            IPs) + 2 Parts + active_blacklist kostete dieser unnoetige
            Re-Sort zusammen ca. 95s pro Lauf, komplett verschwendet, weil
            das Ergebnis identisch zur bereits sortierten Eingabe war.
            presorted=True setzen NUR wenn die Liste garantiert schon
            numerisch sortiert ist (z.B. via _ip_sort_key) – bei
            unsortierter Eingabe mit presorted=True wird KEINE Sortierung
            mehr durchgefuehrt und die Ausgabedatei waere fehlerhaft
            sortiert. Default bleibt False (altes, sicheres Verhalten).

    Returns:
        list[str]: Die geschriebene, sortierte Liste.
    """
    import tempfile
    sorted_list = list(ips) if presorted else sort_ips(ips)
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
            # Best-effort-Cleanup: schlaegt das Entfernen des tempfiles
            # fehl, wird das bewusst ignoriert. Der Originalfehler wird
            # unten via raise weitergereicht.
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
    # FIX SUBDIR-MKDIR: analog write_text_atomic – Unterordner-Ziele anlegen.
    os.makedirs(target_dir, exist_ok=True)
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
            # Best-effort-Cleanup: schlaegt das Entfernen des tempfiles
            # fehl, wird das bewusst ignoriert. Der Originalfehler wird
            # unten via raise weitergereicht.
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
    # FIX SUBDIR-MKDIR: Zielverzeichnis bei Bedarf anlegen, damit Schreibziele
    # in Unterordnern (z.B. reports/, logs/, geo_enriched/) nicht an
    # mkstemp(dir=...) scheitern. Fuer target_dir="." ein No-op.
    os.makedirs(target_dir, exist_ok=True)
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
            # Best-effort-Cleanup: schlaegt das Entfernen des tempfiles
            # fehl, wird das bewusst ignoriert. Der Originalfehler wird
            # unten via raise weitergereicht.
            pass
        raise

def concatenate_files_atomic(filepath, source_paths, chunk_size=1024 * 1024):
    """Fuegt vorhandene Dateien speicherschonend und atomar zusammen.

    Die Quelldateien werden in der angegebenen Reihenfolge blockweise in
    eine temporaere Datei im Zielverzeichnis kopiert. Erst nachdem alle
    Bytes geschrieben und per fsync() dauerhaft gesichert wurden, ersetzt
    os.replace() die Zieldatei atomar. Damit kann auch eine grosse Combined-
    Liste aus ihren kanonischen Parts rekonstruiert werden, ohne den gesamten
    Inhalt gleichzeitig in den Arbeitsspeicher zu laden.

    Die Funktion fuehrt eine bytegenaue Verkettung aus und fuegt selbst keine
    zusaetzlichen Zeilenumbrueche ein. Die Part-Dateien muessen daher – wie
    von write_ip_list() garantiert – mit einem Zeilenumbruch enden.

    Args:
        filepath: Zieldatei.
        source_paths: Iterable der Quelldateien in gewuenschter Reihenfolge.
        chunk_size: Groesse der Kopierbloecke in Bytes (Standard: 1 MiB).

    Returns:
        int: Anzahl der geschriebenen Bytes.
    """
    import tempfile

    if not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("chunk_size muss eine positive Ganzzahl sein")

    sources = [os.fspath(path) for path in source_paths]
    if not sources:
        raise ValueError("source_paths darf nicht leer sein")

    target_path = os.fspath(filepath)
    target_abs = os.path.abspath(target_path)
    for source in sources:
        if os.path.abspath(source) == target_abs:
            raise ValueError("Zieldatei darf nicht zugleich Quelldatei sein")

    target_dir = os.path.dirname(target_abs) or "."
    os.makedirs(target_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(target_path)}.",
        suffix=".tmp",
        dir=target_dir,
    )

    bytes_written = 0
    try:
        with os.fdopen(fd, "wb") as out_file:
            for source in sources:
                with open(source, "rb") as in_file:
                    while True:
                        chunk = in_file.read(chunk_size)
                        if not chunk:
                            break
                        out_file.write(chunk)
                        bytes_written += len(chunk)
            out_file.flush()
            os.fsync(out_file.fileno())
        os.replace(tmp_path, target_path)
        _fsync_dir(target_dir)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            # Best-effort-Cleanup: schlaegt das Entfernen des tempfiles
            # fehl, wird das bewusst ignoriert. Der Originalfehler wird
            # unten via raise weitergereicht.
            pass
        raise

    return bytes_written

# ═══════════════════════════════════════════════════════════════
# Auto-Discovered Feeds: Schema- und URL-Validierung
# ═══════════════════════════════════════════════════════════════

def validate_auto_feeds(auto_data):
    """Filtert auto_discovered_feeds.json-Eintraege auf safe Schema + URL.

    Hintergrund (FIX BUG-AUTOFEEDS-VALIDATE): Vorher las
    update_combined_blacklist die Datei direkt mit
    ``auto_data.get("feeds", [])`` ohne Schema-/URL-Pruefung. Risiko:
    Ein Angreifer mit Repo-Schreibrechten konnte malicious URLs in
    den Feed-Loop einschmuggeln, ohne den Code-Review-Pfad ueber
    SOURCES zu durchlaufen. fetch_url's SSRF-Schutz blockt zwar
    localhost/RFC1918, aber externe Angreifer-URLs mit boeswilligen
    IP-Listen waeren durch.

    Akzeptiert:
        - dict-Root mit "feeds"-Liste
        - pro Eintrag: dict mit string-keys "name" und "url"
        - URL muss http:// oder https:// sein

    Args:
        auto_data: Geparstes JSON aus auto_discovered_feeds.json.

    Returns:
        tuple[list[dict], int]: (akzeptierte_feeds, anzahl_verworfen).
            Jeder akzeptierte Feed ist {"name":..., "url":..., "file":...}.
            "file" (Datei-Pfad im Repo, fuer is_bot_detector_feed_name()
            gedacht) wird durchgereicht wenn vorhanden und str, sonst "".
            Kein Sicherheitsmerkmal – nur Metadaten fuer die Namens-/Pfad-
            Heuristik, wird nirgends gefetcht oder ausgefuehrt.

    Raises:
        ValueError: Wenn Root nicht dict oder feeds nicht list ist
                    (= grundsaetzlich kaputtes Schema, kein partieller
                    Restore moeglich).
    """
    if not isinstance(auto_data, dict):
        raise ValueError(
            f"auto_discovered_feeds Root ist {type(auto_data).__name__}, "
            f"erwartet dict")
    raw_feeds = auto_data.get("feeds", [])
    if not isinstance(raw_feeds, list):
        raise ValueError(
            f"auto_discovered_feeds 'feeds' ist {type(raw_feeds).__name__}, "
            f"erwartet list")
    accepted = []
    rejected = 0
    for feed in raw_feeds:
        if not isinstance(feed, dict):
            rejected += 1
            continue
        name = feed.get("name")
        url = feed.get("url")
        if not isinstance(name, str) or not isinstance(url, str):
            rejected += 1
            continue
        if not (url.startswith("https://") or url.startswith("http://")):
            rejected += 1
            continue
        # FIX BUG-AUTOFEEDS-CTRL: Control-Zeichen in URLs explizit ablehnen.
        # \n, \r, \t und andere C0-Controls (ord < 0x20) sowie DEL (0x7F)
        # haben in einer http(s)-URL nichts verloren. urllib faengt das
        # heute mit "InvalidURL: nonnumeric port" ab, aber:
        #   - die Diagnose passiert erst beim Fetch (spaeter, schwerer zu
        #     finden), nicht beim Schema-Check
        #   - kommt mal ein anderer Fetcher (requests, httpx) zum Einsatz,
        #     der CRLF nicht out-of-the-box rejected, ist der Schutz weg
        # Explizit hier ablehnen = Defense-in-Depth konsistent zu den
        # anderen Schema-Checks oben.
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in url):
            rejected += 1
            continue
        _file = feed.get("file")
        if not isinstance(_file, str):
            _file = ""
        accepted.append({"name": name, "url": url, "file": _file})
    return accepted, rejected