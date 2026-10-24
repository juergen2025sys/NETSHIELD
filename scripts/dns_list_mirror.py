#!/usr/bin/env python3
"""
NETSHIELD DNS-Listen-Spiegel
============================
Erzeugt Domain-Listen fuer die OPNsense-Unbound-DNSBL unter dns/, fuer
Quellen, die OPNsense nicht direkt laden kann:

  - dns/antimalware_domains.txt
        DandelionSprout Anti-Malware List. Die Original-URL enthaelt "%20";
        OPNsense liest die Listen-URLs mit ConfigParser ein, an dem "%"
        stuerzt der komplette Blocklisten-Aufbau ohne Log-Eintrag ab
        (verifiziert 2026-10-24: seit 09:00 kein einziger DNSBL-Lauf mehr,
        bis die URL entfernt wurde). Der Spiegel liefert dieselbe Liste
        unter einer URL ohne Sonderzeichen.

  - dns/threatfox_domains.txt
        ThreatFox-IOCs vom Typ "domain" aus dem authentifizierten
        full.csv.zip-Export (gleicher Endpoint und Secret wie
        honeypot_monitor.yml). Die oeffentlichen ThreatFox-Hostfiles/
        -Exporte liefern seit 2026 nur noch HTTP 410.
        Bewusst NUR ioc_type=domain, keine Hosts aus ioc_type=url: deren
        Hosts sind oft geteilte Plattformen (github.com, Discord-CDN,
        Google Drive ...), die man per DNS nicht sperren darf.

Format: eine Domain pro Zeile, ohne Wildcard. OPNsense sperrt diese
Eintraege exakt (keine Subdomains), was das Fehlalarm-Risiko klein haelt.

Leerungsschutz: Liefert eine Quelle weniger als MIN_ENTRIES, bleibt die
bestehende Datei unveraendert (kein Ueberschreiben mit Muell/Leer).

Ausfuehren:
    python3 -u scripts/dns_list_mirror.py
"""
from __future__ import annotations

import csv
import io
import ipaddress
import os
import re
import sys
import time
import urllib.error
import zipfile
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netshield_common import fetch_url, safe_urlopen, write_text_atomic  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(REPO_ROOT, "dns")

USER_AGENT = "NETSHIELD-DNS-Mirror/1.0"

DANDELION_URL = ("https://raw.githubusercontent.com/DandelionSprout/adfilt/master/"
                 "Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt")

# Untere Normalwerte (Stand 2026-10-24): DandelionSprout ~11k Eintraege.
# ThreatFox-Domains schwanken staerker, 500 faengt nur echte Leer-/Muell-
# Antworten ab.
MIN_ENTRIES = {
    "antimalware": 1000,
    "threatfox": 500,
}

# ThreatFox: nur IOCs ab dieser Confidence (0-100) uebernehmen.
THREATFOX_MIN_CONFIDENCE = 50
THREATFOX_READ_LIMIT = 150 * 1024 * 1024  # wie honeypot_monitor.yml

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$"
)

# Hosts-Datei-Ziele, die vor dem eigentlichen Domainnamen stehen.
HOSTS_SINK_TOKENS = {"0.0.0.0", "127.0.0.1", "::", "::1", "0", "255.255.255.255"}

# Grosse Plattformen, deren Hauptdomain nie gesperrt werden darf. Weil
# OPNsense die Eintraege exakt (ohne Subdomains) sperrt, reicht es, genau
# diese Namen und ihre www-Variante herauszufiltern. Angreifer-Subdomains
# wie "evil.blogspot.com" bleiben bewusst sperrbar.
PROTECTED_DOMAINS = frozenset({
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
    "office.com", "office365.com", "outlook.com", "azure.com",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com",
    "cloudflare.com", "github.com", "githubusercontent.com",
    "mozilla.org", "firefox.com", "spotify.com", "discord.com",
    "discordapp.com", "steampowered.com", "steamcommunity.com",
    "facebook.com", "instagram.com", "whatsapp.com", "opnsense.org",
    "quad9.net", "dropbox.com", "drive.google.com", "docs.google.com",
})

LOCAL_NAMES = {"localhost", "localhost.localdomain", "local", "broadcasthost"}


def normalize_domain(token: str) -> str | None:
    """Bringt einen Listeneintrag auf eine reine, kleingeschriebene Domain.

    Liefert None fuer IPs, lokale Namen und alles, was keine gueltige
    Domain ist.
    """
    if not token:
        return None
    value = token.strip().strip('"').lower()
    # Adblock-/Wildcard-Schreibweisen ("||foo.com^", "*.foo.com") tolerieren
    if value.startswith("||"):
        value = value[2:]
    value = value.split("^", 1)[0]
    if value.startswith("*."):
        value = value[2:]
    value = value.rstrip(".")
    if not value or value in LOCAL_NAMES or len(value) > 253:
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    if not DOMAIN_RE.match(value):
        return None
    return value


def is_protected(domain: str) -> bool:
    return domain in PROTECTED_DOMAINS or (
        domain.startswith("www.") and domain[4:] in PROTECTED_DOMAINS)


def parse_hosts_text(text: str) -> set[str]:
    """Liest Hosts-Dateien und reine Domainlisten (eine Domain pro Zeile)."""
    domains: set[str] = set()
    for raw in text.splitlines():
        line = raw.lstrip("﻿").split("#", 1)[0].strip()
        if not line or line.startswith("!"):
            continue
        tokens = [t for t in line.split() if t not in HOSTS_SINK_TOKENS]
        # Hosts-Zeilen koennen mehrere Namen je IP enthalten
        for token in tokens:
            domain = normalize_domain(token)
            if domain and not is_protected(domain):
                domains.add(domain)
    return domains


def parse_threatfox_csv(text: str, min_confidence: int = THREATFOX_MIN_CONFIDENCE) -> set[str]:
    """Extrahiert ioc_type=domain aus dem ThreatFox-CSV-Export.

    Header-basiertes Spalten-Mapping wie in honeypot_monitor.yml, weil
    sich das Schema zwischen Exportarten unterscheiden kann.
    """
    lines = text.splitlines()
    col_index: dict[str, int] = {}
    for line in lines:
        stripped = line.lstrip("#").strip()
        if stripped.startswith('"first_seen_utc"'):
            header = next(csv.reader([stripped], skipinitialspace=True))
            col_index = {name.strip(): i for i, name in enumerate(header)}
            break
    if "ioc_value" not in col_index or "ioc_type" not in col_index:
        raise ValueError("ThreatFox-CSV: Spalten ioc_value/ioc_type nicht gefunden")

    idx_value = col_index["ioc_value"]
    idx_type = col_index["ioc_type"]
    idx_conf = col_index.get("confidence_level")
    needed = max(i for i in (idx_value, idx_type, idx_conf) if i is not None)

    domains: set[str] = set()
    data_lines = [ln for ln in lines if ln.startswith('"')]
    for row in csv.reader(data_lines, skipinitialspace=True):
        if len(row) <= needed:
            continue
        if row[idx_type].strip() != "domain":
            continue
        if idx_conf is not None:
            try:
                if int(row[idx_conf].strip()) < min_confidence:
                    continue
            except ValueError:
                pass
        domain = normalize_domain(row[idx_value])
        if domain and not is_protected(domain):
            domains.add(domain)
    return domains


def fetch_threatfox_csv(keys: list[str], retries: int = 3, timeout: int = 60) -> str | None:
    """Laedt full.csv.zip mit Key-Failover und liefert den CSV-Text.

    Binaerer Download ueber safe_urlopen, weil fetch_url() immer als Text
    dekodiert und das ZIP damit korrumpieren wuerde.
    """
    for key_idx, key in enumerate(keys, start=1):
        url = f"https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip"
        for attempt in range(1, retries + 1):
            try:
                with safe_urlopen(url, headers={"User-Agent": USER_AGENT}, timeout=timeout) as resp:
                    data = resp.read(THREATFOX_READ_LIMIT + 1)
                if len(data) > THREATFOX_READ_LIMIT:
                    print(f"  FEHLER threatfox: Antwort > {THREATFOX_READ_LIMIT} bytes")
                    return None
                archive = zipfile.ZipFile(io.BytesIO(data))
                csv_names = [n for n in archive.namelist() if n.lower().endswith(".csv")]
                if not csv_names:
                    print(f"  FEHLER threatfox: keine .csv im ZIP ({archive.namelist()})")
                    return None
                with archive.open(csv_names[0]) as handle:
                    return handle.read().decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as err:
                if err.code in (401, 403):
                    print(f"  HTTP {err.code} threatfox (Key #{key_idx}) - naechster Key")
                    break
                print(f"  HTTP {err.code} threatfox (Key #{key_idx}, Versuch {attempt}/{retries})")
            except zipfile.BadZipFile:
                print(f"  FEHLER threatfox: kein gueltiges ZIP (Key #{key_idx}) - Key pruefen")
                break
            except Exception as err:  # Netzwerkfehler, Timeouts
                print(f"  FEHLER threatfox (Key #{key_idx}, Versuch {attempt}/{retries}): {err}")
            if attempt < retries:
                time.sleep(2 ** attempt)
    return None


def write_domain_list(name: str, filename: str, title: str, source: str,
                      domains: set[str], now_str: str) -> bool:
    """Schreibt die Liste atomar - oder behaelt die alte bei zu wenig Eintraegen."""
    path = os.path.join(OUT_DIR, filename)
    minimum = MIN_ENTRIES[name]
    if len(domains) < minimum:
        print(f"::warning ::{filename}: nur {len(domains)} Domains (< {minimum}) - "
              f"bestehende Datei bleibt unveraendert")
        return False
    os.makedirs(OUT_DIR, exist_ok=True)
    header = [
        f"# Title: {title}",
        f"# Quelle: {source}",
        f"# Aktualisiert: {now_str}",
        f"# Eintraege: {len(domains)}",
        "# Erzeugt von NETSHIELD (scripts/dns_list_mirror.py) fuer OPNsense Unbound DNSBL",
        "",
    ]
    write_text_atomic(path, "\n".join(header + sorted(domains)) + "\n")
    print(f"  {filename}: {len(domains)} Domains geschrieben")
    return True


def main() -> int:
    now = datetime.now(timezone.utc)
    now_str = now.astimezone(ZoneInfo("Europe/Berlin")).strftime("%Y-%m-%d %H:%M %Z")
    results: dict[str, bool] = {}

    print("DandelionSprout Anti-Malware List ...")
    text = fetch_url(DANDELION_URL, timeout=60, retries=3, user_agent=USER_AGENT)
    if text is None:
        print("::warning ::DandelionSprout nicht erreichbar - bestehende Datei bleibt")
        results["antimalware"] = False
    else:
        results["antimalware"] = write_domain_list(
            "antimalware", "antimalware_domains.txt",
            "DandelionSprout Anti-Malware List (Spiegel ohne %20 in der URL)",
            DANDELION_URL, parse_hosts_text(text), now_str)

    print("ThreatFox Domain-IOCs ...")
    keys = [k for k in (os.environ.get("THREATFOX_AUTH_KEY", "").strip(),
                        os.environ.get("THREATFOX_AUTH_KEY_2", "").strip()) if k]
    if not keys:
        print("::warning ::THREATFOX_AUTH_KEY nicht gesetzt - ThreatFox uebersprungen")
        results["threatfox"] = False
    else:
        csv_text = fetch_threatfox_csv(keys)
        if csv_text is None:
            print("::warning ::ThreatFox-Export nicht ladbar - bestehende Datei bleibt")
            results["threatfox"] = False
        else:
            try:
                tf_domains = parse_threatfox_csv(csv_text)
            except ValueError as err:
                print(f"::warning ::{err} - bestehende Datei bleibt")
                results["threatfox"] = False
            else:
                results["threatfox"] = write_domain_list(
                    "threatfox", "threatfox_domains.txt",
                    f"ThreatFox Domain-IOCs (abuse.ch, Confidence >= {THREATFOX_MIN_CONFIDENCE})",
                    "https://threatfox.abuse.ch (authentifizierter full.csv.zip-Export)",
                    tf_domains, now_str)

    ok = [name for name, done in results.items() if done]
    print(f"\nFERTIG: {len(ok)}/{len(results)} Listen aktualisiert ({', '.join(ok) or '-'})")
    # Nur scheitern, wenn GAR NICHTS aktualisiert werden konnte
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
