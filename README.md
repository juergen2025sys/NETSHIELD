
<div align="center">

# 🛡️ NETSHIELD

**Automatisiertes IP-Threat-Intelligence-System mit dynamischer Blacklist-Verwaltung.**

[![Update Combined](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_combined_blacklist.yml/badge.svg)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_combined_blacklist.yml)
[![Feed Health](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/feed_health_monitor.yml/badge.svg)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/feed_health_monitor.yml)
[![Confidence Blacklist](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_confidence_blacklist.yml/badge.svg)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_confidence_blacklist.yml)
[![False Positive Checker](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/false_positive_checker.yml/badge.svg)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/false_positive_checker.yml)

</div>

---

<!-- STATS_TABLE_START -->
**Key Statistics**

| IP-Quellen | Aktive IP-Drohungen (Confidence ≥65) | CVE/Exploit IPs | Honeypot IPs |
|:---|:---|:---|:---|
| 103 (dynamisch) | **2,385,651** | **216,760** | **10,094** |
<!-- STATS_TABLE_END -->

<!-- META_TABLE_START -->
**Aktualisierungs-Status**

| Letztes Update | Update-Intervall | IP-Retention | Aktive Workflows | Geografische Abdeckung |
|:---|:---|:---|:---|:---|
| 2026-04-05 21:54 UTC | 8× täglich | 180 Tage | 16 | 250+ Länder |
<!-- META_TABLE_END -->

NETSHIELD aggregiert, bewertet und bereinigt täglich IP-Bedrohungsdaten aus 98 öffentlichen Feeds. Das System unterscheidet aktive Bedrohungen von veralteten statischen Listen und liefert daraus qualitativ hochwertige Blocklisten für OPNsense, pfSense und iptables.

---

## ⚡ Quick Start — OPNsense Alias

**Firewall → Aliases → URL Table (Type: URL Table (IPs)):**

1. Neuen URL Alias erstellen
2. Listen-URL einfügen
3. Intervall auf `Täglich` setzen
4. Regeln anwenden

```
# Empfohlen – aktive Bedrohungen (Score ≥65, letzte 30 Tage)
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/active_blacklist_ipv4.txt

# Größere Abdeckung (Score ≥40)
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/blacklist_confidence40_ipv4.txt

# Nur Monitoring (Score 25–39)
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/watchlist_confidence25to39_ipv4.txt
```

**iptables:**

```bash
ipset create netshield hash:ip
curl -s https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/active_blacklist_ipv4.txt \
  | grep -v '^#' | xargs -I{} ipset add netshield {}
iptables -I INPUT -m set --match-set netshield src -j DROP
```

---

## Blocklisten

| Datei | Zweck | Einträge | Empfohlen für |
|---|---|---:|---|
| [`active_blacklist_ipv4.txt`](active_blacklist_ipv4.txt) | Aktive Bedrohungen · letzte 30 Tage · Score ≥ 65 | **2,385,651**                             | OPNsense / pfSense / Firewall |
| [`blacklist_confidence40_ipv4.txt`](blacklist_confidence40_ipv4.txt) | Mittleres bis hohes Vertrauen · Score ≥ 40 | **2,925,065**                             | Erweiterte Filterregeln |
| [`combined_threat_blacklist_ipv4.txt`](combined_threat_blacklist_ipv4.txt) | Alle IPs · 180-Tage-Fenster | **4,142,618**                             | Audit / SIEM |
| [`watchlist_confidence25to39_ipv4.txt`](watchlist_confidence25to39_ipv4.txt) | Watchlist · Score 25–39 | **322,574**                             | Monitoring |
| [`cve_exploit_ips.txt`](cve_exploit_ips.txt) | CVE-Exploits & aktive C2-Server | **216,760**                             | IDS / IPS |
| [`honeypot_ips.txt`](honeypot_ips.txt) | Honeypot-bestätigte Angreifer | **10,094**                             | Ergänzung |
| [`bot_detector_blacklist_ipv4.txt`](bot_detector_blacklist_ipv4.txt) | Bot- & Scanner-IPs | **17,950**                             | Web-Schutz |
| [`asn_blocklist_firewall.txt`](asn_blocklist_firewall.txt) | Hochrisiko-ASNs · Score ≥ 50 | **19**                             | ASN-Blocking |

### Geo-Listen

```
countries/              →  IPv4-Ranges pro Land, nach Kontinent sortiert
continents/             →  Zusammengefasste Ranges pro Kontinent
all_countries_ipv4.txt  →  Alle Länder in einer Datei
```

---

## Wie funktioniert die Bewertung

Jede IP bekommt einen **Confidence-Score (0–100)** aus vier Dimensionen:

```
Score = Quellen-Qualität (40) + Aktualität (30) + Persistenz (20) + Bekannt seit (10)
```

| Dimension | Max | Logik |
|---|:---:|---|
| Quellen-Qualität | 40 | HQ-Feed = 40 Pkt · mehrere Nicht-HQ-Feeds = 20–35 Pkt |
| Aktualität | 30 | Heute bestätigt = 30 · vor 7 Tagen = 20 · vor 30 Tagen = 6 |
| Persistenz | 20 | 14+ Tage aktiv bestätigt = 20 Pkt |
| Bekannt seit | 10 | Je länger im System, desto stabiler |

Nur **HQ-Feeds** (Feodo, AbuseIPDB, Spamhaus, Talos u. a.) bestimmen die Lebenszeit einer IP. Statische Mega-Listen erhöhen den Score, können eine IP aber nicht am Leben halten. Nach **180 Tagen** ohne HQ-Bestätigung wird eine IP automatisch entfernt.

| Score | Liste | Verwendung |
|:---:|---|---|
| ≥ 65 | `active_blacklist` | Firewall · direktes Blocking |
| ≥ 40 | `confidence40` | Erweiterte Regeln |
| 25–39 | `watchlist` | Nur Monitoring |
| < 25 | `combined` | Audit / SIEM |

---

## Architektur

```
98 öffentliche Feeds
        │
        ▼
┌─────────────────────────────────┐
│   Update Combined Blacklist     │  ← Haupt-Engine · 8× täglich
│   seen_db · Score-Berechnung    │
│   IP-Lebenszeit 180 Tage        │
└──────────┬──────────────────────┘
           │
     ┌─────┼─────────────┐
     ▼     ▼             ▼
 active  combined   confidence40
 ≥65     180T       ≥40 / watchlist
  │         │             │
  ▼         ▼             ▼
OPNsense  Audit/SIEM   Analyse
```

---

## Workflows

| Workflow | Zeitplan | Aufgabe |
|---|---|---|
| Update Combined Blacklist | 8× täglich (alle 3h) | Feeds laden, seen_db aktualisieren, Blacklists schreiben |
| Confidence Blacklist | 8× täglich (+15 min) | confidence40 + watchlist aus seen_db berechnen |
| False Positive Checker | 3× täglich | Whitelist-CIDRs prüfen, FPs entfernen |
| Honeypot Monitor | täglich 23:00 | Honeypot-Feeds → honeypot_ips.txt |
| HoneyDB Monitor | täglich 22:15 | HoneyDB API → honeydb_ips.txt |
| Bot-Detector Blacklist | täglich 22:45 | bot_detector_blacklist_ipv4.txt |
| CVE-to-IP Mapper | täglich 04:00 | C2/Exploit-IPs → cve_exploit_ips.txt |
| Update All Countries IPv4 | Mo + Mi 01:30 | Länder/Kontinente synchronisieren |
| Auto Feed Discovery | So 04:30 | GitHub nach neuen Feeds durchsuchen |
| Geo-Tagger | So 07:45 | Blacklist-IPs geo-anreichern |
| ASN Reputation Scorer | täglich 02:00 | ASN-Scoring → asn_reputation_db.json |
| Score Decay Monitor | So 07:00 | Alterungs-Report (read-only) |
| Feed Health Monitor | täglich 01:00 | Feed-URLs auf Erreichbarkeit prüfen |
| Workflow Health Checker | täglich 01:15 | Workflows auf Fehler analysieren |
| NETSHIELD Report Generator | alle 30 Minuten | NETSHIELD_REPORT.md + README aktualisieren |
| Community IP Report | bei Issue-Erstellung | Community-gemeldete IPs verarbeiten |

---

## Community Reports

Verdächtige IPs können über das **Issue-System** gemeldet werden:

1. Issue mit Label `community-report` erstellen
2. System validiert die IP automatisch (nur öffentliche IPv4)
3. IP landet als Watchlist-Eintrag in der seen_db
4. Bei **3 unabhängigen Meldungen** → Promotion zur aktiven Blacklist
5. Issue wird automatisch geschlossen

> Limit: 5 Reports pro User pro Tag.

---

## Reports & Monitoring

| Datei | Inhalt |
|---|---|
| [`NETSHIELD_REPORT.md`](NETSHIELD_REPORT.md) | Gesamtübersicht + Feed Health (alle 30 min) |
| [`feed_health_report.md`](feed_health_report.md) | Status aller Feed-URLs |
| [`workflow_health_report.md`](workflow_health_report.md) | Workflow-Analyse |
| [`geo_tagger_report.md`](geo_tagger_report.md) | Geo-Verteilung der Blacklist-IPs |
| [`asn_reputation_report.md`](asn_reputation_report.md) | ASN-Scoring-Report |
| [`score_decay_report.md`](score_decay_report.md) | Alterungs-Analyse der seen_db |
| [`auto_feed_discovery_report.md`](auto_feed_discovery_report.md) | Neu entdeckte Feeds |

---

## Dateistruktur

```
NETSHIELD/
├── .github/workflows/                   # 16 GitHub Actions Workflows
├── continents/                          # IPv4-Ranges pro Kontinent
├── countries/                           # IPv4-Ranges pro Land
│   ├── africa/ · asia/ · europe/
│   ├── north_america/ · oceania/ · south_america/
├── active_blacklist_ipv4.txt            # → Firewall
├── combined_threat_blacklist_ipv4.txt   # → Audit / SIEM
├── blacklist_confidence40_ipv4.txt      # → Confidence ≥ 40
├── watchlist_confidence25to39_ipv4.txt  # → Monitoring
├── cve_exploit_ips.txt
├── honeypot_ips.txt · honeydb_ips.txt
├── bot_detector_blacklist_ipv4.txt
├── asn_blocklist_firewall.txt
├── asn_reputation_db.json
├── blacklist_geo_enriched.json
├── seen_db_meta.json
├── NETSHIELD_REPORT.md
└── README.md
```

---

<div align="center">

*Automatisch aktualisiert · [NETSHIELD_REPORT.md](NETSHIELD_REPORT.md)*

</div>
