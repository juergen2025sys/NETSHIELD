#!/usr/bin/env python3
"""
OTX AlienVault Yield Test
=========================
Einmaliger Test-Lauf: Misst, wie viele IPv4-Adressen die OTX API
tatsaechlich liefert UND wie viele davon NACH Dedup gegen die
bestehende combined_threat_blacklist wirklich NEU sind.

Liefert die harte Zahl, die fuer die Entscheidung
"OTX-Workflow integrieren ja/nein" gebraucht wird.

Verwendung:
    export OTX_API_KEY="dein_otx_key_hier"
    python3 scripts/otx_test_yield.py

Optional:
    export OTX_DAYS_BACK=30          # Default: 30 Tage zurueck
    export OTX_MAX_PULSES=500        # Default: 500 (Sicherheits-Limit)
    export OTX_MAX_API_REQUESTS=100  # Default: 100 (verhindert Rate-Limit)

Exit-Codes:
    0 = Test erfolgreich abgeschlossen (egal ob viele/wenige IPs)
    1 = Konfigurationsfehler (kein API-Key)
    2 = API-Fehler (Auth, Rate-Limit, Netzwerk)
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone, timedelta

# NETSHIELD common helpers
sys.path.insert(0, "scripts")
from netshield_common import (
    load_whitelist, load_fp_set, is_in_fp_set,
    is_valid_public_ipv4, is_whitelisted,
    IPV4_RE,
)


# ═══════════════════════════════════════════════════════════════
# Konfiguration
# ═══════════════════════════════════════════════════════════════

API_KEY = os.environ.get("OTX_API_KEY", "").strip()
DAYS_BACK = int(os.environ.get("OTX_DAYS_BACK", "30"))
MAX_PULSES = int(os.environ.get("OTX_MAX_PULSES", "500"))
MAX_API_REQUESTS = int(os.environ.get("OTX_MAX_API_REQUESTS", "100"))

BASE_URL = "https://otx.alienvault.com"
USER_AGENT = "NETSHIELD-OTX-Test/1.0"

COMBINED_BLACKLIST = "combined_threat_blacklist_ipv4.txt"
ACTIVE_BLACKLIST = "active_blacklist_ipv4.txt"


# ═══════════════════════════════════════════════════════════════
# OTX API Client (ohne externe Dependencies)
# ═══════════════════════════════════════════════════════════════

class OTXClient:
    """Minimaler OTX API Client. Nutzt nur stdlib."""

    def __init__(self, api_key, max_requests=100):
        self.api_key = api_key
        self.max_requests = max_requests
        self.request_count = 0

    def _get(self, path, params=None):
        """GET-Request mit API-Key Header. Throttled (max_requests Limit)."""
        if self.request_count >= self.max_requests:
            raise RuntimeError(
                f"API-Request-Limit erreicht ({self.max_requests}). "
                f"Erhoehe OTX_MAX_API_REQUESTS falls noetig."
            )

        url = f"{BASE_URL}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        req = urllib.request.Request(url, headers={
            "X-OTX-API-KEY": self.api_key,
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        })

        self.request_count += 1
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 401 or e.code == 403:
                raise RuntimeError(
                    f"OTX API Auth-Fehler ({e.code}). "
                    f"Pruefe OTX_API_KEY (https://otx.alienvault.com/api)."
                )
            if e.code == 429:
                raise RuntimeError("OTX API Rate-Limit (429). Spaeter erneut versuchen.")
            raise RuntimeError(f"OTX API HTTP {e.code}: {e.reason}")

    def get_subscribed_pulses(self, modified_since=None, max_pulses=500):
        """
        Holt alle Pulses, die der API-Key abonniert hat.
        Iteriert ueber alle Seiten bis max_pulses oder Ende.

        Returns:
            list[dict]: Pulse-Objekte mit eingebetteten 'indicators'.
        """
        pulses = []
        page = 1
        params = {"limit": 50, "page": page}
        if modified_since:
            params["modified_since"] = modified_since.strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )

        while len(pulses) < max_pulses:
            params["page"] = page
            data = self._get("/api/v1/pulses/subscribed", params)
            results = data.get("results", [])
            if not results:
                break
            pulses.extend(results)
            print(
                f"  Seite {page}: {len(results)} Pulses geholt "
                f"(Total: {len(pulses)}/{data.get('count', '?')})",
                flush=True,
            )
            if not data.get("next"):
                break
            page += 1
            time.sleep(0.5)  # rate-limit safety

        return pulses[:max_pulses]


# ═══════════════════════════════════════════════════════════════
# Hauptlogik
# ═══════════════════════════════════════════════════════════════

def load_existing_blacklist():
    """Laedt bestehende blacklist als Set fuer schnellen Dedup-Check."""
    existing = set()
    for path in (COMBINED_BLACKLIST, ACTIVE_BLACKLIST):
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Erste Spalte (kann CIDR oder IP sein)
                token = line.split()[0] if line.split() else ""
                m = IPV4_RE.search(token)
                if m:
                    existing.add(m.group(1))
        print(f"  {path}: {len(existing):,} IPs (kumuliert) geladen", flush=True)
    return existing


def extract_ipv4_from_pulses(pulses):
    """
    Extrahiert IPv4-Indikatoren aus Pulse-Liste.

    Returns:
        dict: {ip: [(pulse_name, pulse_id, created_date), ...]}
    """
    ip_to_pulses = {}
    pulses_with_ipv4 = 0

    for pulse in pulses:
        pulse_name = pulse.get("name", "<unbenannt>")
        pulse_id = pulse.get("id", "")
        pulse_created = pulse.get("created", "")[:10]
        indicators = pulse.get("indicators", [])

        had_ipv4 = False
        for ind in indicators:
            ind_type = ind.get("type", "")
            if ind_type != "IPv4":
                continue
            ip = ind.get("indicator", "").strip()
            if not ip:
                continue
            had_ipv4 = True
            ip_to_pulses.setdefault(ip, []).append(
                (pulse_name, pulse_id, pulse_created)
            )
        if had_ipv4:
            pulses_with_ipv4 += 1

    return ip_to_pulses, pulses_with_ipv4


def main():
    if not API_KEY:
        print("FEHLER: OTX_API_KEY nicht gesetzt.", file=sys.stderr)
        print("", file=sys.stderr)
        print("Setup:", file=sys.stderr)
        print("  1. https://otx.alienvault.com  -> kostenlosen Account erstellen", file=sys.stderr)
        print("  2. Mindestens 1 Pulse abonnieren (z.B. AlienVault Labs)", file=sys.stderr)
        print("  3. API-Key holen: https://otx.alienvault.com/api", file=sys.stderr)
        print("  4. export OTX_API_KEY='dein_key'", file=sys.stderr)
        sys.exit(1)

    print("=" * 70)
    print("OTX AlienVault Yield Test")
    print("=" * 70)
    print(f"Zeitraum:           letzte {DAYS_BACK} Tage")
    print(f"Max. Pulses:        {MAX_PULSES}")
    print(f"Max. API-Requests:  {MAX_API_REQUESTS}")
    print(f"Gestartet:          {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 70)
    print()

    # 1) NETSHIELD Validierung initialisieren
    print("[1/5] Lade NETSHIELD Whitelist + False-Positive-Set...")
    load_whitelist()
    load_fp_set()
    print()

    # 2) Bestehende Blacklist als Dedup-Basis laden
    print("[2/5] Lade bestehende Blacklist als Dedup-Basis...")
    existing_ips = load_existing_blacklist()
    print(f"  Total bekannte IPs: {len(existing_ips):,}")
    print()

    # 3) OTX API: subscribed Pulses holen
    print("[3/5] Hole abonnierte Pulses von OTX...")
    client = OTXClient(API_KEY, max_requests=MAX_API_REQUESTS)
    modified_since = datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)

    try:
        pulses = client.get_subscribed_pulses(
            modified_since=modified_since,
            max_pulses=MAX_PULSES,
        )
    except RuntimeError as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"  -> {len(pulses)} Pulses geladen ({client.request_count} API-Requests)")
    print()

    # 4) IPv4 extrahieren
    print("[4/5] Extrahiere IPv4-Indikatoren...")
    ip_to_pulses, pulses_with_ipv4 = extract_ipv4_from_pulses(pulses)
    raw_ip_count = len(ip_to_pulses)
    print(f"  Pulses mit IPv4-Indikatoren: {pulses_with_ipv4} / {len(pulses)}")
    print(f"  Unique IPv4 (raw):           {raw_ip_count:,}")
    print()

    # 5) Validierung + Dedup
    print("[5/5] Validiere + dedupliziere...")
    valid_ips = []
    skipped_invalid = 0
    skipped_whitelist = 0
    skipped_fp = 0

    for ip in ip_to_pulses:
        if not is_valid_public_ipv4(ip):
            skipped_invalid += 1
            continue
        if is_whitelisted(ip):
            skipped_whitelist += 1
            continue
        if is_in_fp_set(ip):
            skipped_fp += 1
            continue
        valid_ips.append(ip)

    new_ips = [ip for ip in valid_ips if ip not in existing_ips]
    overlap_ips = [ip for ip in valid_ips if ip in existing_ips]

    print(f"  Ungueltig/privat:    -{skipped_invalid:,}")
    print(f"  In Whitelist:        -{skipped_whitelist:,}")
    print(f"  In FP-Set:           -{skipped_fp:,}")
    print(f"  Gueltig (public):    {len(valid_ips):,}")
    print(f"  Bereits in Blacklist: {len(overlap_ips):,}  ({100*len(overlap_ips)/max(1,len(valid_ips)):.1f}% Overlap)")
    print(f"  WIRKLICH NEU:        {len(new_ips):,}")
    print()

    # ═══════════════════════════════════════════════════════════════
    # ENTSCHEIDUNGS-EMPFEHLUNG
    # ═══════════════════════════════════════════════════════════════
    print("=" * 70)
    print("ERGEBNIS")
    print("=" * 70)
    print(f"  Pulses gescannt:        {len(pulses):,}")
    print(f"  Raw IPv4 aus OTX:       {raw_ip_count:,}")
    print(f"  Nach Validierung:       {len(valid_ips):,}")
    print(f"  Wirklich NEUE IPs:      {len(new_ips):,}")
    print(f"  API-Requests genutzt:   {client.request_count}")
    print()

    new_count = len(new_ips)
    if new_count >= 5000:
        verdict = "SEHR GUT - OTX-Integration empfohlen"
        rationale = (
            f"  {new_count:,} neue IPs liegen oberhalb der HoneyDB-Liefermenge\n"
            f"  (~12k) und rechtfertigen einen eigenen Workflow."
        )
    elif new_count >= 2000:
        verdict = "OK - Integration sinnvoll, aber Erwartungen kalibrieren"
        rationale = (
            f"  {new_count:,} neue IPs sind solide, aber kleiner als HoneyDB.\n"
            f"  Lohnt sich wenn Pulse-Kontext (Tags/Adversary) auch genutzt wird."
        )
    elif new_count >= 500:
        verdict = "GRENZWERTIG - Aufwand-Nutzen ueberdenken"
        rationale = (
            f"  {new_count:,} neue IPs rechtfertigen kaum einen eigenen Workflow.\n"
            f"  Erwaege stattdessen: spezifische OTX-Pulse-IDs als Feed in\n"
            f"  auto_discovered_feeds.json einzutragen."
        )
    else:
        verdict = "NICHT EMPFOHLEN - Aufwand zu hoch fuer Mehrwert"
        rationale = (
            f"  Nur {new_count:,} wirklich neue IPs nach Dedup. NETSHIELDs\n"
            f"  bestehende Quellen (URLhaus, ThreatFox, Feodo, MISP) decken\n"
            f"  bereits den Grossteil der OTX-Daten ab."
        )

    print(f"  EMPFEHLUNG: {verdict}")
    print()
    print(rationale)
    print()

    # Sample der neuen IPs (Debugging)
    if new_ips:
        print("  Sample (erste 10 neue IPs + Pulse-Kontext):")
        for ip in sorted(new_ips)[:10]:
            pulse_info = ip_to_pulses[ip][0]
            print(f"    {ip:<16} <- {pulse_info[0][:50]} ({pulse_info[2]})")
        print()

    # Optional: Ergebnis als JSON fuer weitere Analyse
    report_path = "otx_yield_test_report.json"
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config": {
            "days_back": DAYS_BACK,
            "max_pulses": MAX_PULSES,
            "max_api_requests": MAX_API_REQUESTS,
        },
        "results": {
            "pulses_scanned": len(pulses),
            "pulses_with_ipv4": pulses_with_ipv4,
            "raw_ipv4_count": raw_ip_count,
            "valid_after_filter": len(valid_ips),
            "skipped_invalid": skipped_invalid,
            "skipped_whitelist": skipped_whitelist,
            "skipped_fp": skipped_fp,
            "overlap_with_existing": len(overlap_ips),
            "new_ips": len(new_ips),
            "api_requests_used": client.request_count,
        },
        "verdict": verdict,
        "sample_new_ips": sorted(new_ips)[:50],
    }
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"  Vollstaendiger Bericht: {report_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
