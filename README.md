


<div align="center">

# 🛡️ NETSHIELD

**Automatisiertes IP-Threat-Intelligence-System mit dynamischer Blacklist-Verwaltung.**

<br>

![Status](https://img.shields.io/badge/status-active-success?style=flat-square)
![Update](https://img.shields.io/badge/update-8%C3%97%20daily-blue?style=flat-square)
![Retention](https://img.shields.io/badge/retention-180%20days-orange?style=flat-square)
![Sources](https://img.shields.io/badge/sources-124-purple?style=flat-square)
![Coverage](https://img.shields.io/badge/coverage-250%2B%20countries-teal?style=flat-square)

<br>

[![Update Combined](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_combined_blacklist.yml/badge.svg)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_combined_blacklist.yml)
[![Feed Health](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/feed_health_monitor.yml/badge.svg)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/feed_health_monitor.yml)
[![Confidence Blacklist](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_confidence_blacklist.yml/badge.svg)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_confidence_blacklist.yml)
[![False Positive Checker](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/false_positive_checker.yml/badge.svg)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/false_positive_checker.yml)

<br>

[**⚡ Quick Start**](#-quick-start--opnsense-alias) · [**📊 Blocklisten**](#-blocklisten) · [**🎯 Scoring**](#-wie-funktioniert-die-bewertung) · [**🏗️ Architektur**](#%EF%B8%8F-architektur) · [**⚙️ Workflows**](#%EF%B8%8F-workflows) · [**📡 Feeds**](#-feed-quellen)

</div>

---

## 📊 Key Statistics

<!-- STATS_TABLE_START -->
<table>
<tr>
<td align="center" valign="top" width="25%">
<h3>124</h3>
<sub>IP-Quellen<br>(dynamisch)</sub>
</td>
<td align="center" valign="top" width="25%">
<h3>2,370,383</h3>
<sub>Aktive IP-Drohungen<br>(Confidence ≥65)</sub>
</td>
<td align="center" valign="top" width="25%">
<h3>53,904</h3>
<sub>CVE/Exploit IPs<br>&nbsp;</sub>
</td>
<td align="center" valign="top" width="25%">
<h3>171,555</h3>
<sub>Honeypot IPs<br>&nbsp;</sub>
</td>
</tr>
</table>
<!-- STATS_TABLE_END -->

<!-- META_TABLE_START -->
<table>
<tr>
<td><strong>🕒 Letztes Update</strong></td>
<td>2026-04-25 19:25 UTC</td>
<td><strong>🔄 Intervall</strong></td>
<td>8× täglich</td>
</tr>
<tr>
<td><strong>📅 IP-Retention</strong></td>
<td>180 Tage</td>
<td><strong>⚙️ Aktive Workflows</strong></td>
<td>19</td>
</tr>
<tr>
<td><strong>🌍 Abdeckung</strong></td>
<td colspan="3">250+ Länder</td>
</tr>
</table>
<!-- META_TABLE_END -->

> NETSHIELD aggregiert, bewertet und bereinigt täglich IP-Bedrohungsdaten aus über 120 Quellen: 98 öffentliche Remote-Feeds, 5 lokale Sub-Workflow-Feeds (CVE, Honeypot, HoneyDB, Bot-Detector, AbuseIPDB API) und ~18 automatisch entdeckte GitHub-Feeds. Das System unterscheidet aktive Bedrohungen von veralteten statischen Listen und liefert daraus qualitativ hochwertige Blocklisten für OPNsense, pfSense und iptables.

---

## ⚡ Quick Start — OPNsense Alias

**Firewall → Aliases → URL Table (Type: URL Table (IPs)):**

1. Neuen URL Alias erstellen
2. Listen-URL einfügen
3. Intervall auf `Täglich` setzen
4. Regeln anwenden

```bash
# ✅ Empfohlen – aktive Bedrohungen (Score ≥65, letzte 30 Tage)
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/active_blacklist_ipv4.txt

# 🔍 Größere Abdeckung (Score ≥40)
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/blacklist_confidence40_ipv4.txt

# 👁️ Nur Monitoring (Score 25–39)
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/watchlist_confidence25to39_ipv4.txt
```

<details>
<summary><strong>🐧 iptables / ipset</strong></summary>

```bash
ipset create netshield hash:ip
curl -s https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/active_blacklist_ipv4.txt \
  | grep -v '^#' | xargs -I{} ipset add netshield {}
iptables -I INPUT -m set --match-set netshield src -j DROP
```

</details>

---

## 📋 Blocklisten

| Datei | Zweck | Einträge | Empfohlen für |
|---|---|---:|---|
| 🛡️ [`active_blacklist_ipv4.txt`](active_blacklist_ipv4.txt) | Aktive Bedrohungen · letzte 30 Tage · Score ≥ 65 | **2,370,383**                                                                                        | OPNsense / pfSense / Firewall |
| 🔶 [`blacklist_confidence40_ipv4.txt`](blacklist_confidence40_ipv4.txt) | Mittleres bis hohes Vertrauen · Score ≥ 40 | **3,611,957**                                                                                        | Erweiterte Filterregeln |
| 📦 [`combined_threat_blacklist_ipv4.txt`](combined_threat_blacklist_ipv4.txt) | Alle IPs · 180-Tage-Fenster | **4,611,343**                                                                                        | Audit / SIEM |
| 👁️ [`watchlist_confidence25to39_ipv4.txt`](watchlist_confidence25to39_ipv4.txt) | Watchlist · Score 25–39 | **190,204**                                                                                        | Monitoring |
| 💣 [`cve_exploit_ips.txt`](cve_exploit_ips.txt) | CVE-Exploits & aktive C2-Server | **53,904**                                                                                        | IDS / IPS |
| 🍯 [`honeypot_ips.txt`](honeypot_ips.txt) | Honeypot-bestätigte Angreifer | **171,555**                                                                                        | Ergänzung |
| 🍯 [`honeydb_ips.txt`](honeydb_ips.txt) | HoneyDB Community Honeypot (API) | **38,970**                                                                                        | Ergänzung |
| 🤖 [`bot_detector_blacklist_ipv4.txt`](bot_detector_blacklist_ipv4.txt) | Bot- & Scanner-IPs | **17,948**                                                                                        | Web-Schutz |
| 🔗 [`abuseipdb_api_blacklist.txt`](abuseipdb_api_blacklist.txt) | AbuseIPDB Top-IPs (API, Score ≥50) | **9,983**                                                                                        | Ergänzung |
| 🌐 [`asn_blocklist_firewall.txt`](asn_blocklist_firewall.txt) | Hochrisiko-ASNs · Score ≥ 50 | **19**                                                                                        | ASN-Blocking |

> [!NOTE]
> **`combined_threat_blacklist_ipv4.txt`:** Wenn die Datei über 90 MB wächst, werden zusätzlich Parts `combined_threat_blacklist_ipv4_part1.txt`, `_part2.txt` (etc.) mit je ca. 40 MB erzeugt. Die Hauptdatei bleibt bestehen, solange sie unter 100 MB ist (GitHub-Limit). Firewall-Konsumenten, die am GitHub-Limit angestoßen werden, sollten stattdessen die Parts als separate URLs importieren.

<details>
<summary><strong>🌍 Geo-Listen</strong></summary>

```
countries/              →  IPv4-Ranges pro Land, nach Kontinent sortiert
continents/             →  Zusammengefasste Ranges pro Kontinent
all_countries_ipv4.txt  →  Alle Länder in einer Datei
```

</details>

---

## 🎯 Wie funktioniert die Bewertung

Jede IP bekommt einen **Confidence-Score (0–100)** aus vier Dimensionen:

```
Score = Quellen-Qualität (40) + Aktualität (30) + Persistenz (20) + Bekannt seit (10)
```

| Dimension | **Gewicht** | Logik |
|---|:---:|---|
| 🏅 Quellen-Qualität | `40` | HQ-Feed = 40 · 5+ Feeds heute = 35 · 3+ heute = 28 · 2+ heute = 20 · 5+ gesamt = 15 · 3+ gesamt = 10 · 2+ gesamt = 5 |
| ⏱️ Aktualität | `30` | Heute = 30 · ≤ 3 Tage = 25 · ≤ 7 Tage = 20 · ≤ 14 Tage = 12 · ≤ 30 Tage = 6 |
| 🔁 Persistenz | `20` | 14+ Tage = 20 · 7 Tage = 15 · 3 Tage = 10 · 2 Tage = 6 · 1 Tag = 2 |
| 📆 Bekannt seit | `10` | 90+ Tage = 10 · 30+ Tage = 6 · 14+ Tage = 3 |

> [!IMPORTANT]
> Nur **HQ-Feeds** (Feodo, AbuseIPDB, Spamhaus, DataPlane, FireHOL u. a.) bestimmen die Lebenszeit einer IP. Statische Mega-Listen erhöhen den Score, können eine IP aber nicht am Leben halten. Nach **180 Tagen** ohne HQ-Bestätigung wird eine IP automatisch entfernt. Watchlist-IPs ohne HQ-Bestätigung laufen bereits nach **30 Tagen** ab.

### Score-Schwellen

| Score | Liste | Verwendung |
|:---:|---|---|
| 🔴 **≥ 65** | `active_blacklist` | Firewall · direktes Blocking |
| 🟠 **≥ 40** | `confidence40` | Erweiterte Regeln |
| 🟡 **25–39** | `watchlist` | Nur Monitoring |
| ⚪ **< 25** | `combined` | Audit / SIEM |

---

## 🏗️ Architektur

```
121 Quellen (98 Remote + 5 Lokal + ~18 Auto-Discovered)
        │
        ▼
┌─────────────────────────────────────────────┐
│         Update Combined Blacklist           │  ← Haupt-Engine · 8× täglich
│                                             │
│  ┌─────────────┐  ┌──────────────────────┐  │
│  │  seen_db    │  │ False-Positive-Set   │  │
│  │  (Cache)    │  │ (Whitelist-Filter)   │  │
│  └──────┬──────┘  └──────────────────────┘  │
│         │                                   │
│   Score-Berechnung · HQ/Non-HQ Trennung     │
│   IP-Lebenszeit: 180T (HQ) / 30T (Watchlist)│
└──────────┬──────────────────────────────────┘
           │
     ┌─────┼─────────────────┐
     ▼     ▼                 ▼
  active  combined      confidence40
  ≥65     180T          ≥40 / watchlist
    │       │                │
    ▼       ▼                ▼
 OPNsense  Audit/SIEM    Analyse

Sub-Workflows (vor Combined):
  CVE Mapper ──────┐
  Honeypot Monitor ├──→ Lokale .txt-Dateien ──→ Combined liest ein
  HoneyDB Monitor  │
  Bot-Detector ────┘

Enrichment (nach Combined):
  Geo-Tagger ──────→ blacklist_geo_enriched.json
  ASN Scorer ──────→ asn_reputation_db.json
  Score Decay ─────→ Alterungs-Report (read-only)
```

---

## ⚙️ Workflows

<details open>
<summary><strong>🔧 Kern-Pipeline</strong></summary>

| Workflow | Zeitplan | Aufgabe |
|---|---|---|
| **Update Combined Blacklist** | 8× täglich (alle 3h) | Feeds laden, seen_db aktualisieren, combined + active Blacklists schreiben |
| **Confidence Blacklist** | 8× täglich (+45 min) | confidence40 + watchlist aus seen_db berechnen |
| **False Positive Checker** | 3× täglich | Whitelist-CIDRs prüfen → false_positives_set.json |
| **NETSHIELD Report Generator** | alle 30 Minuten | NETSHIELD_REPORT.md + README-Statistiken aktualisieren |

</details>

<details>
<summary><strong>📡 Datenquellen (Sub-Workflows)</strong></summary>

| Workflow | Zeitplan | Aufgabe |
|---|---|---|
| **CVE-to-IP Mapper** | täglich 04:00 | C2/Exploit-IPs → cve_exploit_ips.txt |
| **Honeypot Monitor** | täglich 23:00 | Honeypot-Feeds → honeypot_ips.txt |
| **HoneyDB Monitor** | täglich 22:15 | HoneyDB API → honeydb_ips.txt |
| **Bot-Detector Blacklist** | täglich 22:45 | Bot-IPs → bot_detector_blacklist_ipv4.txt |
| **Auto Feed Discovery** | wöchentlich So 04:30 | GitHub nach neuen Feeds durchsuchen |

</details>

<details>
<summary><strong>🔍 Enrichment & Monitoring</strong></summary>

| Workflow | Zeitplan | Aufgabe |
|---|---|---|
| **Geo-Tagger** | wöchentlich So 07:45 | Blacklist-IPs geo-anreichern via ScaniteX |
| **ASN Reputation Scorer** | täglich 02:00 | ASN-Scoring → asn_reputation_db.json |
| **Score Decay Monitor** | wöchentlich So 07:00 | Alterungs-Report (read-only) |
| **Feed Health Monitor** | täglich 01:00 | Feed-URLs auf Erreichbarkeit prüfen |
| **Workflow Health Checker** | 4× täglich | Python-Code + Production Health Checks (seen_db, Output-Sanity, Drift, Feed-Ausfälle) |
| **Update All Countries IPv4** | Mo + Mi 01:30 | Länder/Kontinente IPv4-Ranges synchronisieren |

</details>

<details>
<summary><strong>🤝 Community</strong></summary>

| Workflow | Trigger | Aufgabe |
|---|---|---|
| **Community IP Report** | Issue mit Label `community-report` | Community-gemeldete IPs validieren und eintragen |

</details>

---

## 🕐 Datenfluss & Timing

```
22:15  HoneyDB Monitor  ──────────────────┐
22:45  Bot-Detector Blacklist ────────────┤
23:00  Honeypot Monitor ──────────────────┤
00:00  Update Combined Blacklist ─────────┼──→ seen_db Cache
00:45  Confidence Blacklist ──────────────┘    (8× täglich wiederholt)
01:00  Feed Health Monitor
01:15  Workflow Health Checker ←──────────── (4× täglich: 01:15, 07:15, 13:15, 19:15)
01:30  Update All Countries (Mo+Mi)
02:00  ASN Reputation Scorer
04:00  CVE-to-IP Mapper
04:30  Auto Feed Discovery (So)
05:00  False Positive Checker
07:00  Score Decay Monitor (So)
07:45  Geo-Tagger (So)
```

---

## 🤝 Community Reports

Verdächtige IPs können über das **Issue-System** gemeldet werden:

1. Issue mit Label `community-report` erstellen
2. System validiert die IP automatisch (nur öffentliche IPv4)
3. IP landet als Watchlist-Eintrag in der seen_db
4. Bei **3 unabhängigen Meldungen** → Promotion zur aktiven Blacklist
5. Issue wird automatisch geschlossen

> [!TIP]
> Limit: 5 Reports pro User pro Tag.

---

## 📈 Reports & Monitoring

| Datei | Inhalt |
|---|---|
| 📊 [`NETSHIELD_REPORT.md`](NETSHIELD_REPORT.md) | Gesamtübersicht + Feed Health (alle 30 min) |
| 💚 [`feed_health_report.md`](feed_health_report.md) | Status aller Feed-URLs |
| ⚙️ [`workflow_health_report.md`](workflow_health_report.md) | Workflow-Analyse (Python-Syntax, Cron-Timing, Guards) |
| 🔀 [`combined_threat_blacklist_report.md`](combined_threat_blacklist_report.md) | Feed-Statistik pro Lauf |
| 🌍 [`geo_tagger_report.md`](geo_tagger_report.md) | Geo-Verteilung der Blacklist-IPs |
| 🏢 [`asn_reputation_report.md`](asn_reputation_report.md) | ASN-Scoring mit Abuse-Dichte |
| 📉 [`score_decay_report.md`](score_decay_report.md) | Alterungs-Analyse der seen_db |
| 🔎 [`auto_feed_discovery_report.md`](auto_feed_discovery_report.md) | Neu entdeckte Feeds + Bewertung |

---

## 📡 Feed-Quellen

NETSHIELD bezieht Daten aus folgenden Kategorien:

| Kategorie | Beispiele | HQ |
|---|---|:---:|
| Abuse-Tracker | Feodo, ThreatFox, URLhaus (abuse.ch) | ✅ |
| Blocklist-Aggregatoren | FireHOL Level 1–4, blocklist.de, DShield | ✅ |
| Honeypot-Netzwerke | DataPlane, Turris Sentinel, HoneyDB (API) | ✅ |
| Reputation-Feeds | AbuseIPDB (API + Mirrors), ipsum, CINSscore | ✅ |
| C2/Botnet-Tracker | C2-Tracker, MISP C2 Intel Feeds | ✅ |
| Threat Intelligence | Spamhaus DROP, Emerging Threats, Threatview | ✅ |
| Community-Feeds | GitHub-Repos (auto-discovered), Bot-Detector | ❌ |
| Brute-Force-Listen | CrowdSec, danger.rulez.sk, blocklist.de/ssh | ✅ |

> [!IMPORTANT]
> **HQ-Feeds** (49 von 98 Remote-Quellen) bestimmen die Lebenszeit einer IP. Non-HQ-Feeds erhöhen den Confidence-Score, können IPs aber nicht am Leben halten.

---

## 📁 Dateistruktur

<details>
<summary><strong>Repository-Layout anzeigen</strong></summary>

```
NETSHIELD/
├── .github/workflows/                   # 16 GitHub Actions Workflows
├── continents/                          # IPv4-Ranges pro Kontinent
├── countries/                           # IPv4-Ranges pro Land
│   ├── africa/ · asia/ · europe/
│   ├── north_america/ · oceania/ · south_america/
│
├── active_blacklist_ipv4.txt            # → Firewall (Score ≥65, 30 Tage)
├── blacklist_confidence40_ipv4.txt      # → Erweiterte Regeln (Score ≥40)
├── combined_threat_blacklist_ipv4.txt   # → Audit / SIEM (180 Tage)
├── watchlist_confidence25to39_ipv4.txt  # → Monitoring (Score 25–39)
│
├── cve_exploit_ips.txt                  # CVE/C2-IPs (täglich)
├── honeypot_ips.txt                     # Honeypot-Feeds (täglich)
├── honeydb_ips.txt                      # HoneyDB API (täglich)
├── bot_detector_blacklist_ipv4.txt      # Bot-Detector (täglich)
├── abuseipdb_api_blacklist.txt          # AbuseIPDB API (Round-Robin)
├── asn_blocklist_firewall.txt           # ASN-Blocking (Score ≥50)
│
├── asn_reputation_db.json               # ASN-Scoring-Daten
├── blacklist_geo_enriched.json          # Geo-Anreicherung
├── auto_discovered_feeds.json           # Auto-entdeckte Feeds
├── false_positives_set.json             # FP-Whitelist
├── feed_health_status.json              # Feed-Status
├── seen_db_meta.json                    # seen_db Metadaten (DB im Cache)
│
├── NETSHIELD_REPORT.md                  # Haupt-Dashboard
└── README.md
```

</details>

---

## 🔒 Schutzmechanismen

| Mechanismus | Beschreibung |
|---|---|
| 🛑 **Leerungsschutz** | Jeder Workflow prüft MIN_ENTRIES vor dem Schreiben — bei zu wenigen Ergebnissen bleibt die alte Datei erhalten |
| ⚪ **False-Positive-Filter** | Umfangreiche Whitelist (CDN, DNS, Mail, Cloud-Provider) verhindert Blocking legitimer Infrastruktur |
| 🏅 **HQ/Non-HQ-Trennung** | Nur verifizierte HQ-Feeds verlängern die Lebenszeit einer IP — statische Listen können IPs nicht am Leben halten |
| 🔁 **Push-Retry** | 5 Versuche mit git rebase bei gleichzeitigen Commits |
| 🔐 **Concurrency-Lock** | Jeder Workflow läuft max. 1× gleichzeitig |
| 📦 **Cache-Isolation** | Verschiedene Workflows nutzen eigene Cache-Prefixe (v2, fp, afd, community) |

---

<div align="center">

<sub>*Automatisch aktualisiert · [NETSHIELD_REPORT.md](NETSHIELD_REPORT.md)*</sub>

<sub>[⬆ Nach oben](#-netshield)</sub>

</div>
