
<div align="center">

<br/>

```
███╗   ██╗███████╗████████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
██╔██╗ ██║█████╗     ██║   ███████╗███████║██║█████╗  ██║     ██║  ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
██║ ╚████║███████╗   ██║   ███████║██║  ██║██║███████╗███████╗██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
```

**Automatisiertes IP-Threat-Intelligence-System mit dynamischer Blacklist-Verwaltung**

<br/>

[![Update Combined](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_combined_blacklist.yml/badge.svg?style=flat-square)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_combined_blacklist.yml)&nbsp;
[![Feed Health](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/feed_health_monitor.yml/badge.svg?style=flat-square)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/feed_health_monitor.yml)&nbsp;
[![Confidence Blacklist](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_confidence_blacklist.yml/badge.svg?style=flat-square)](https://github.com/juergen2025sys/NETSHIELD/actions/workflows/update_confidence_blacklist.yml)

<br/>

---

### 📊 Live-Statistiken

<br/>

| 🗂️ Gesamt (Combined) | 🔴 Aktiv (Score ≥65) | 🟡 Confidence ≥40 | 🔵 Watchlist | 📡 Feed-Quellen |
|:--------------------:|:--------------------:|:-----------------:|:------------:|:---------------:|
| **4.112.169** | **2.381.047** | **2.900.870** | **322.287** | **98** |

<br/>

> 🔄 Daten werden **8× täglich** automatisch aktualisiert — zuletzt durch den NETSHIELD Report Generator.

---

</div>

## ⚡ Schnellstart

Füge eine der folgenden URLs direkt als **URL-Alias in OPNsense / pfSense** ein:

### 🔴 Empfohlen — Aktive Bedrohungen (Score ≥65, letzte 30 Tage)
```
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/active_blacklist_ipv4.txt
```
> Präzise, aktuell, für Produktiv-Firewalls geeignet. Kein Rauschen.

### 🟡 Erweitert — Mittleres/Hohes Vertrauen (Score ≥40)
```
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/blacklist_confidence40_ipv4.txt
```
> Größere Abdeckung, ideal für zusätzliche Filterregeln oder IDS-Systeme.

### 🟠 Watchlist — Beobachtung (Score 25–39)
```
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/watchlist_confidence25to39_ipv4.txt
```
> Für Monitoring und SIEM-Korrelation. Nicht für direktes Blocking empfohlen.

---

## 🧠 Wie funktioniert NETSHIELD?

NETSHIELD aggregiert **98 öffentliche Threat-Intelligence-Feeds**, bewertet jede IP nach einem mehrdimensionalen Scoring-Modell und erzeugt daraus qualitativ hochwertige, automatisch berechnete Blocklisten.

### Das Kernprinzip

```
Nur HQ-Feeds bestimmen die Lebenszeit einer IP.
Statische Mega-Listen erhöhen den Score — aber sie können eine IP nicht am Leben halten.
Das System bereinigt automatisch, was die Feeds selbst nicht können.
```

IPs ohne HQ-Bestätigung altern nach **180 Tagen** automatisch aus. Werden sie erneut von einem HQ-Feed gemeldet, kehren sie sofort zurück.

---

## 📐 Architektur

```
┌─────────────────────────┐         ┌────────────────────────────┐
│        HQ-Feeds         │         │       Non-HQ-Feeds         │
│  Feodo · Talos · Abuse  │         │  romainmarcoux · ipsum     │
│  Spamhaus · FireHOL     │         │  littlejake · blocklist.de │
│  DShield · URLhaus …    │         │  + weitere statische Listen│
└────────────┬────────────┘         └────────────┬───────────────┘
             │ setzt last_seen                    │ erhöht feed_count
             └──────────────┬────────────────────┘
                            ▼
              ┌─────────────────────────┐
              │  Update Combined (8×/d) │
              │  seen_db · 180d Lifetime│
              └──────┬──────────┬───────┘
                     │          │
          ┌──────────┘          └────────────┐
          ▼                                  ▼
┌─────────────────┐              ┌───────────────────────┐
│ active_blacklist│              │  combined_blacklist    │
│ Score ≥65, 30d  │              │  Alle IPs · 180 Tage  │
│ → OPNsense/FW   │              │  → Audit / SIEM       │
└─────────────────┘              └───────────────────────┘
          ▼
┌─────────────────┐
│  confidence40   │
│  Score ≥40      │
│  → Analyse / IDS│
└─────────────────┘
```

---

## 📊 Confidence-Score

Jede IP erhält einen **Score von 0–100** aus vier Dimensionen:

```
Score = A (Quellen-Qualität) + B (Aktualität) + C (Persistenz) + D (Bekannt seit)
```

| Dimension | Max | Beschreibung |
|:---|:---:|:---|
| **A — Quellen-Qualität** | 40 | HQ-Feed = 40 Pkt · mehrere Feeds = 20–35 Pkt |
| **B — Aktualität** | 30 | HQ-Bestätigung heute = 30 · vor 7 Tagen = 20 · vor 30 Tagen = 6 |
| **C — Persistenz** | 20 | Bestätigt über 14+ Tage = 20 Pkt |
| **D — Bekannt seit** | 10 | Länger im System = stabilerer Score |

### Score-Schwellwerte & Verwendung

| Score | Liste | Einsatz |
|:---:|:---|:---|
| **≥ 65** | `active_blacklist` | 🔴 OPNsense · pfSense · iptables |
| **≥ 40** | `blacklist_confidence40` | 🟡 Erweiterte Filter · IDS/IPS |
| **25–39** | `watchlist` | 🟠 Monitoring · SIEM |
| **< 25** | `combined` (nur) | ⚪ Audit · Analyse |

---

## 📦 Alle Blocklisten

| Datei | Beschreibung | Einträge | Update | Einsatz |
|:---|:---|---:|:---:|:---|
| [`active_blacklist_ipv4.txt`](active_blacklist_ipv4.txt) | Aktive Bedrohungen · Score ≥65 · 30 Tage | **2.381.047** | 8×/Tag | 🔴 Firewall |
| [`combined_threat_blacklist_ipv4.txt`](combined_threat_blacklist_ipv4.txt) | Alle IPs · 180 Tage Retention | **4.112.169** | 8×/Tag | ⚪ Audit / SIEM |
| [`blacklist_confidence40_ipv4.txt`](blacklist_confidence40_ipv4.txt) | Score ≥40 · mittleres/hohes Vertrauen | **2.900.870** | 8×/Tag | 🟡 Filter |
| [`watchlist_confidence25to39_ipv4.txt`](watchlist_confidence25to39_ipv4.txt) | Score 25–39 · Beobachtungsliste | **322.287** | 8×/Tag | 🟠 Monitoring |
| [`cve_exploit_ips.txt`](cve_exploit_ips.txt) | CVE-Exploit & C2-Server | **217.542** | tägl. 04:00 | 🔴 IDS/IPS |
| [`honeypot_ips.txt`](honeypot_ips.txt) | Honeypot-bestätigte IPs | **10.111** | tägl. 23:00 | ➕ Ergänzung |
| [`honeydb_ips.txt`](honeydb_ips.txt) | HoneyDB Community Honeypot (API) | **9.404** | tägl. 22:15 | ➕ Ergänzung |
| [`bot_detector_blacklist_ipv4.txt`](bot_detector_blacklist_ipv4.txt) | Bot-Detector-Blacklist | **17.950** | tägl. 22:45 | 🌐 Web-Schutz |
| [`asn_blocklist_firewall.txt`](asn_blocklist_firewall.txt) | Hochrisiko-ASNs · Score ≥50 | **19** | tägl. 02:00 | 🔵 ASN-Blocking |

### 🌍 Geo-Listen

| Verzeichnis / Datei | Beschreibung |
|:---|:---|
| [`continents/`](continents/) | IPv4-Ranges pro Kontinent (africa, asia, europe, north_america, oceania, south_america) |
| [`countries/`](countries/) | IPv4-Ranges pro Land, nach Kontinent organisiert |
| [`all_countries_ipv4.txt`](all_countries_ipv4.txt) | Alle Länder zusammengeführt |

---

## ⚙️ Workflows & Automatisierung

| Workflow | Zeitplan | Aufgabe |
|:---|:---:|:---|
| **Update Combined Blacklist** | 8×/Tag (alle 3h) | Haupt-Engine: Feeds laden, seen_db aktualisieren, Stufe 1+2 schreiben |
| **Confidence Blacklist** | 8×/Tag (+15 min) | confidence40 + watchlist aus seen_db berechnen |
| **False Positive Checker** | 3×/Tag | Whitelist-CIDRs prüfen, FPs aus combined entfernen |
| **Honeypot Monitor** | tägl. 23:00 | Honeypot-Feeds → honeypot_ips.txt |
| **HoneyDB Monitor** | tägl. 22:15 | HoneyDB API → honeydb_ips.txt |
| **Bot-Detector Blacklist** | tägl. 22:45 | bot_detector_blacklist_ipv4.txt aktualisieren |
| **CVE-to-IP Mapper** | tägl. 04:00 | C2/Exploit-IPs → cve_exploit_ips.txt |
| **Update All Countries IPv4** | Mo + Mi 01:30 | Länder/Kontinente/all_countries synchronisieren |
| **Auto Feed Discovery** | So 04:30 | GitHub nach neuen IP-Feeds durchsuchen + bewerten |
| **Geo-Tagger** | So 07:45 | Blacklist-IPs mit Geo-Daten anreichern |
| **ASN Reputation Scorer** | tägl. 02:00 | ASN-Reputationsscoring → asn_reputation_db.json |
| **Score Decay Monitor** | So 07:00 | Alterungs-Report (read-only) |
| **Feed Health Monitor** | tägl. 01:00 | Feed-URLs auf Erreichbarkeit prüfen |
| **Workflow Health Checker** | tägl. 01:15 | YAML-Workflows auf Fehler analysieren |
| **NETSHIELD Report Generator** | alle 30 Min | NETSHIELD_REPORT.md + README-Zahlen aktualisieren |
| **Community IP Report** | bei Issue-Erstellung | Community-IPs validieren und in seen_db eintragen |

---

## 🤝 Community-Reports

Verdächtige IPs können über das **[Issue-System](../../issues)** gemeldet werden:

```
1. Issue erstellen  →  Label "community-report" verwenden
2. NETSHIELD validiert die IP (nur öffentliche IPv4, keine DNS-Whitelist)
3. IP wird mit hq=False in seen_db eingetragen (→ Watchlist)
4. Issue wird automatisch mit Feedback geschlossen
5. Bei 3+ unabhängigen Meldungen: Promotion zur active_blacklist
```

> ⚠️ **Limit:** 5 Reports pro User pro Tag.

---

## 📁 Dateistruktur

```
NETSHIELD/
├── .github/
│   └── workflows/                      ← 16 GitHub Actions Workflows
├── continents/                         ← IPv4-Ranges pro Kontinent
├── countries/                          ← IPv4-Ranges pro Land
│   ├── africa/
│   ├── asia/
│   ├── europe/
│   ├── north_america/
│   ├── oceania/
│   └── south_america/
│
├── active_blacklist_ipv4.txt           ← 🔴 OPNsense / Firewall
├── combined_threat_blacklist_ipv4.txt  ← ⚪ Audit / SIEM
├── blacklist_confidence40_ipv4.txt     ← 🟡 Confidence ≥40
├── watchlist_confidence25to39_ipv4.txt ← 🟠 Monitoring
├── cve_exploit_ips.txt
├── honeypot_ips.txt
├── honeydb_ips.txt
├── bot_detector_blacklist_ipv4.txt
├── all_countries_ipv4.txt
├── asn_blocklist_firewall.txt
│
├── asn_reputation_db.json
├── blacklist_geo_enriched.json
├── auto_discovered_feeds.json
├── seen_db_meta.json
│
├── NETSHIELD_REPORT.md                 ← Automatisch generiert (alle 30 min)
├── feed_health_report.md
├── workflow_health_report.md
├── geo_tagger_report.md
├── asn_reputation_report.md
├── score_decay_report.md
├── auto_feed_discovery_report.md
└── README.md
```

---

## 📋 Reports & Monitoring

| Datei | Beschreibung | Update |
|:---|:---|:---:|
| [`NETSHIELD_REPORT.md`](NETSHIELD_REPORT.md) | Übersicht aller Listen + Feed-Health | alle 30 min |
| [`feed_health_report.md`](feed_health_report.md) | Status aller 98 Feed-URLs | tägl. |
| [`workflow_health_report.md`](workflow_health_report.md) | Workflow-Analyse (Fehler/Warnungen) | tägl. |
| [`geo_tagger_report.md`](geo_tagger_report.md) | Geo-Verteilung der Blacklist-IPs | wöchentl. |
| [`asn_reputation_report.md`](asn_reputation_report.md) | ASN-Scoring-Report | tägl. |
| [`score_decay_report.md`](score_decay_report.md) | Alterungs-Analyse der seen_db | wöchentl. |
| [`auto_feed_discovery_report.md`](auto_feed_discovery_report.md) | Neu entdeckte Feeds | wöchentl. |

---

### HQ-Feed-Quellen (Auswahl)

`Feodo C2` · `AbuseIPDB` · `Spamhaus DROP/EDROP` · `Emerging Threats` · `FireHOL L1/L2/L3` · `blocklist.de` · `CINS Score` · `C2-Tracker` · `ThreatFox IOC` · `URLhaus` · `Binary Defense` · `Turris Greylist` · `GreenSnow` · `ThreatView High Confidence` · `DShield` · u.v.m.

---

<div align="center">

<br/>

*Automatisch aktualisiert durch NETSHIELD · [NETSHIELD_REPORT.md](NETSHIELD_REPORT.md)*

![](https://img.shields.io/badge/IPs%20gesamt-4.112.169-red?style=flat-square)
![](https://img.shields.io/badge/Feeds-98%20Quellen-blue?style=flat-square)
![](https://img.shields.io/badge/Update-8×%20täglich-green?style=flat-square)
![](https://img.shields.io/badge/Retention-180%20Tage-orange?style=flat-square)

</div>
