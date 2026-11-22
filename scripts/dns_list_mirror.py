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
        ThreatFox-IOCs vom Typ "domain" aus taeglichem authentifiziertem
        full.csv.zip-Export und zweistuendlicher Recent-API (gleicher Endpoint und Secret wie
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
import http.client
import json
import ipaddress
import os
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netshield_common import fetch_url, safe_urlopen, write_text_atomic  # noqa: E402
def threatfox_keys(environ=None):
    """Read all numbered API keys (THREATFOX_AUTH_KEY, _2, _3 ...) from the environment.

    Die Workflows reichen die Schluessel einzeln als Umgebungsvariablen weiter
    (kein toJSON(secrets) mehr - CodeQL "Excessive Secrets Exposure").
    THREATFOX_SECRETS_JSON wird nur noch aus Kompatibilitaetsgruenden gelesen.
    """
    import json

    env = os.environ if environ is None else environ
    pattern = re.compile(r"THREATFOX_AUTH_KEY(?:_([0-9]+))?\Z")
    candidates = {}
    raw = env.get("THREATFOX_SECRETS_JSON", "")
    if raw:
        try:
            values = json.loads(raw)
        except (ValueError, TypeError):
            raise ValueError("THREATFOX_SECRETS_JSON ist kein gueltiges JSON") from None
        if not isinstance(values, dict):
            raise ValueError("THREATFOX_SECRETS_JSON muss ein JSON-Objekt sein")
        candidates.update(values)
    candidates.update({k: v for k, v in env.items() if pattern.fullmatch(k)})
    numbered = []
    for name, value in candidates.items():
        match = pattern.fullmatch(name)
        if match and isinstance(value, str) and value.strip():
            numbered.append((int(match.group(1)) if match.group(1) else 1, name, value.strip()))
    numbered.sort(key=lambda item: (item[0], item[1]))
    return list(dict.fromkeys(value for _, _, value in numbered))


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
    "threatfox_ips": 200,
}

# ThreatFox: nur IOCs ab dieser Confidence (0-100) uebernehmen.
THREATFOX_MIN_CONFIDENCE = 50
THREATFOX_READ_LIMIT = 150 * 1024 * 1024  # wie honeypot_monitor.yml
# 2026-11-15 (Nutzerentscheidung): ThreatFox-Export hoechstens alle 2 Stunden
# laden. Grund: Bei stuendlichem Cron plus Combined- und Report-Trigger waren
# alle Schluessel im Rate-Limit (HTTP 429). Gemessen wird am Zeitstempel in
# dns/threatfox_last_fetch.txt, der bei JEDEM erfolgreichen Abruf geschrieben
# wird (die Listen selbst werden nur bei Inhaltsaenderung neu geschrieben).
THREATFOX_MIN_AGE_HOURS = 1.75   # 1 h 45 min: Laeufe kurz vor 2 h (z. B. 1 h 58 min) sollen trotzdem laden
THREATFOX_STAMP_FILE = "threatfox_last_fetch.txt"
THREATFOX_FULL_STAMP_FILE = "threatfox_last_full_fetch.txt"
THREATFOX_FULL_ATTEMPT_FILE = "threatfox_last_full_attempt.txt"

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
        # Keine IP-Adresse - weiter mit der Domain-Pruefung
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
                # Leere oder nicht numerische Confidence: IOC trotzdem uebernehmen
                pass
        domain = normalize_domain(row[idx_value])
        if domain and not is_protected(domain):
            domains.add(domain)
    return domains


def parse_threatfox_ips(text: str, min_confidence: int = THREATFOX_MIN_CONFIDENCE) -> set[str]:
    """Extrahiert die IPv4-Adressen aus ThreatFox-IOCs vom Typ ip:port (C2-Server).

    Wird nicht fuer DNS benutzt, sondern von scripts/asn_drop_build.py, um
    Netzbetreiber mit auffaellig vielen C2-Servern zu finden (2026-11-15).
    ThreatFox-Daten stehen unter CC0.
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
    idx_value, idx_type = col_index["ioc_value"], col_index["ioc_type"]
    idx_conf = col_index.get("confidence_level")
    needed = max(i for i in (idx_value, idx_type, idx_conf) if i is not None)
    ips: set[str] = set()
    for row in csv.reader([ln for ln in lines if ln.startswith('"')], skipinitialspace=True):
        if len(row) <= needed or row[idx_type].strip() != "ip:port":
            continue
        if idx_conf is not None:
            try:
                if int(row[idx_conf].strip()) < min_confidence:
                    continue
            except ValueError:
                # Leere oder nicht numerische Confidence: IOC trotzdem uebernehmen
                pass
        value = row[idx_value].strip().strip('"').rsplit(":", 1)[0]
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            continue
        if addr.version == 4 and addr.is_global:
            ips.add(str(addr))
    return ips


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
                if err.code == 429:
                    # Rate-Limit: weitere Versuche mit demselben Key verschaerfen es nur
                    print(f"  HTTP 429 threatfox (Key #{key_idx}) - Rate-Limit, naechster Key")
                    break
                print(f"  HTTP {err.code} threatfox (Key #{key_idx}, Versuch {attempt}/{retries})")
            except zipfile.BadZipFile:
                print(f"  FEHLER threatfox: kein gueltiges ZIP (Key #{key_idx}) - Key pruefen")
                break
            except Exception as err:  # Netzwerkfehler, Timeouts
                print(f"  FEHLER threatfox (Key #{key_idx}, Versuch {attempt}/{retries}): {type(err).__name__}")
            if attempt < retries:
                time.sleep(2 ** attempt)
    return None


def write_domain_list(name: str, filename: str, title: str, source: str,
                      domains: set[str], now_str: str, refresh_timestamp: bool = False) -> bool:
    """Schreibt die Liste atomar - oder behaelt die alte bei zu wenig Eintraegen."""
    path = os.path.join(OUT_DIR, filename)
    minimum = MIN_ENTRIES[name]
    if len(domains) < minimum:
        print(f"::warning ::{filename}: nur {len(domains)} Domains (< {minimum}) - "
              f"bestehende Datei bleibt unveraendert")
        return False
    # Nur schreiben, wenn sich der Inhalt geaendert hat. Sonst wuerde allein
    # die "Aktualisiert"-Zeile bei jedem (stuendlichen) Lauf einen Commit
    # erzeugen und die Git-Historie unnoetig aufblaehen.
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            existing = {ln.strip() for ln in handle if ln.strip() and not ln.startswith("#")}
        added = len(domains - existing)
        removed = len(existing - domains)
        print(f"  {filename}: Vergleich zur bisherigen Liste: +{added} neu, -{removed} entfernt")
        if existing == domains and not refresh_timestamp:
            print(f"  {filename}: unveraendert ({len(domains)} Domains) - kein Schreiben")
            return True
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
    print(f"  {filename}: {len(domains)} Domains geschrieben (Abrufzeit, nicht Quell-Datenstand)")
    return True



def stamp_time(filename: str) -> datetime | None:
    try:
        with open(os.path.join(OUT_DIR, filename), encoding="utf-8") as handle:
            value = datetime.fromisoformat(handle.read().strip())
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    except (OSError, ValueError):
        return None


def save_stamp(filename: str, now: datetime) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    write_text_atomic(os.path.join(OUT_DIR, filename), now.isoformat(timespec="seconds") + "\n")


def threatfox_last_fetch_age(now: datetime) -> float | None:
    stamp = stamp_time(THREATFOX_STAMP_FILE)
    return (now - stamp).total_seconds() / 3600 if stamp else None


def read_existing(filename: str) -> set[str] | None:
    path = os.path.join(OUT_DIR, filename)
    try:
        with open(path, encoding="utf-8") as handle:
            return {line.strip() for line in handle if line.strip() and not line.startswith("#")}
    except OSError:
        return None


def fetch_threatfox_recent(key: str, timeout: int = 60) -> tuple[set[str], set[str]] | None:
    """Official ThreatFox get_iocs API, 2 days by first_seen; never replace full baseline."""
    request = urllib.request.Request(
        "https://threatfox-api.abuse.ch/api/v1/",
        data=json.dumps({"query": "get_iocs", "days": 2}).encode("utf-8"),
        headers={"Auth-Key": key, "Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    # Nur vollstaendige Antworten verarbeiten. Bei einem abgebrochenen
    # Transfer niemals Teil-JSON in die Blocklisten uebernehmen.
    raw = None
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(20 * 1024 * 1024 + 1)
            break
        except (http.client.IncompleteRead, http.client.RemoteDisconnected,
                ConnectionResetError, TimeoutError, urllib.error.URLError,
                OSError) as err:
            print(f"::warning ::ThreatFox Recent Transfer unterbrochen "
                  f"({type(err).__name__}, Versuch {attempt}/3)")
            if attempt == 3:
                return None
            time.sleep(min(2 ** attempt, 8))
    try:
        if raw is None or len(raw) > 20 * 1024 * 1024:
            raise ValueError("Recent-Antwort fehlt oder ist zu gross")
        payload = json.loads(raw)
        if payload.get("query_status") not in ("ok", "no_result"):
            raise ValueError(f"Recent-API: {payload.get('query_status')}")
        rows = payload.get("data") or []
        if not isinstance(rows, list):
            raise ValueError("Recent-API: data ist keine Liste")
        domains, ips = set(), set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                if int(row.get("confidence_level") or 0) < THREATFOX_MIN_CONFIDENCE:
                    continue
            except (ValueError, TypeError):
                continue
            value = str(row.get("ioc") or "").strip()
            if row.get("ioc_type") == "domain":
                domain = normalize_domain(value)
                if domain and not is_protected(domain):
                    domains.add(domain)
            elif row.get("ioc_type") == "ip:port":
                try:
                    addr = ipaddress.ip_address(value.rsplit(":", 1)[0])
                    if addr.version == 4 and addr.is_global:
                        ips.add(str(addr))
                except ValueError:
                    continue
        return domains, ips
    except urllib.error.HTTPError as err:
        print(f"::warning ::ThreatFox Recent HTTP {err.code} - bestehende Listen bleiben erhalten")
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError, http.client.HTTPException) as err:
        print(f"::warning ::ThreatFox Recent fehlgeschlagen: {type(err).__name__}")
    return None


def update_threatfox(keys: list[str], now: datetime, now_str: str) -> bool:
    if not keys:
        print("::warning ::Keine THREATFOX_AUTH_KEY-Variable gesetzt")
        return False
    domain_file, ip_file = "threatfox_domains.txt", "threatfox_c2_ips.txt"
    titles = (
        f"ThreatFox Domain-IOCs (Confidence >= {THREATFOX_MIN_CONFIDENCE})",
        f"ThreatFox C2-IPs (Confidence >= {THREATFOX_MIN_CONFIDENCE}) - ASN-Auswertung",
    )
    source = "https://threatfox.abuse.ch (Full-Export + Recent-API)"
    last_full = stamp_time(THREATFOX_FULL_STAMP_FILE)
    last_attempt = stamp_time(THREATFOX_FULL_ATTEMPT_FILE)
    # At most one large full-export attempt per UTC calendar day, even after 429.
    # On a new deployment, existing files remain intact if the full export fails.
    full_due = (last_full is None or last_full.date() < now.date()) and (last_attempt is None or last_attempt.date() < now.date())
    if full_due:
        save_stamp(THREATFOX_FULL_ATTEMPT_FILE, now)
        # One key per day, avoiding 30 downloads against a shared export quota.
        key = keys[now.date().toordinal() % len(keys)]
        print("  taeglicher Full-Export: genau ein Download-Versuch")
        csv_text = fetch_threatfox_csv([key], retries=1)
        if csv_text is not None:
            try:
                domains = parse_threatfox_csv(csv_text)
                ips = parse_threatfox_ips(csv_text)
            except ValueError as err:
                print(f"::warning ::Full-Export ungueltig: {err}")
            else:
                good_domains = write_domain_list("threatfox", domain_file, titles[0], source, domains, now_str)
                good_ips = write_domain_list("threatfox_ips", ip_file, titles[1], source, ips, now_str)
                if good_domains and good_ips:
                    save_stamp(THREATFOX_FULL_STAMP_FILE, now)
                    save_stamp(THREATFOX_STAMP_FILE, now)
                    print("  Full-Export erfolgreich, veraltete IOCs bereinigt")
                    return True
        print("::warning ::Full-Export fehlgeschlagen; keine Loeschung, Recent-Fallback wird versucht")
    age = threatfox_last_fetch_age(now)
    if age is not None and 0 <= age < THREATFOX_MIN_AGE_HOURS:
        print(f"  letzter erfolgreicher Abruf vor {age:.2f} h - kein weiterer Abruf")
        return True
    existing_domains = read_existing(domain_file)
    existing_ips = read_existing(ip_file)
    if existing_domains is None or existing_ips is None:
        print("::warning ::Recent-API kann ohne beide bestehenden Basislisten keinen Full-Export ersetzen")
        return False
    # Rotate one key per two-hour slot, without retry storms on HTTP 429.
    slot = int(now.timestamp() // 7200)
    print("  Recent-API: neue IOCs der letzten 48 Stunden")
    recent = fetch_threatfox_recent(keys[slot % len(keys)])
    if recent is None:
        return False
    domains, ips = recent
    good_domains = write_domain_list("threatfox", domain_file, titles[0], source, existing_domains | domains, now_str)
    good_ips = write_domain_list("threatfox_ips", ip_file, titles[1], source, existing_ips | ips, now_str)
    if good_domains and good_ips:
        save_stamp(THREATFOX_STAMP_FILE, now)
        print(f"  Recent erfolgreich: +{len(domains - existing_domains)} Domains, +{len(ips - existing_ips)} C2-IPs")
        return True
    return False


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

    print("ThreatFox Domain-IOCs und C2-IPs ...")
    results["threatfox"] = update_threatfox(threatfox_keys(), now, now_str)

    ok = [name for name, done in results.items() if done]
    print(f"\nFERTIG: {len(ok)}/{len(results)} Listen aktualisiert ({', '.join(ok) or '-'})")
    # Nur scheitern, wenn GAR NICHTS aktualisiert werden konnte
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
