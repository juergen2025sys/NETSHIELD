
# 🛡️ NETSHIELD

**Automatisiertes IP-Threat-Intelligence-System mit dynamischer Blacklist-Verwaltung**

NETSHIELD aggregiert, bewertet und bereinigt täglich IP-Bedrohungsdaten aus über 130 öffentlichen Feeds und erzeugt daraus hochwertige Firewall-Blocklisten.

---

## 🧠 Architektur

![Architektur](architecture.svg)

**Kernprinzip:**
- HQ-Feeds bestimmen Lebenszeit (`last_seen`)
- Non-HQ-Feeds erhöhen nur Score
- IPs altern automatisch (180 Tage)
- Reaktivierung bei neuer Aktivität

---

## 📊 Blocklisten (Live-Zahlen)

| Datei | Beschreibung | IPs |
|------|-------------|----:|
| active_blacklist_ipv4.txt | Aktive Bedrohungen (30T + Score ≥65) | 2,370,081 |
| combined_threat_blacklist_ipv4.txt | Alle IPs (180 Tage) | 4,066,646 |
| blacklist_confidence40_ipv4.txt | Vertrauen ≥40 | 2,859,722 |
| watchlist_confidence25to39_ipv4.txt | Watchlist (25–39) | 326,549 |
| cve_exploit_ips.txt | Exploit/C2 | 220,384 |
| honeypot_ips.txt | Honeypot | 11,844 |
| honeydb_ips.txt | HoneyDB | 8,098 |
| bot_detector_blacklist_ipv4.txt | Bot Detector | 17,364 |

---

## 🔥 Firewall Nutzung

### ✅ Empfohlen
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/blacklist_confidence40_ipv4.txt

### ⚠️ Aggressiv
https://raw.githubusercontent.com/juergen2025sys/NETSHIELD/main/active_blacklist_ipv4.txt

---

## 🌍 Geo-IP Daten

| Bereich | Beschreibung |
|--------|-------------|
| countries/ | IPv4-Ranges pro Land |
| continents/ | IPv4-Ranges pro Kontinent |
| all_countries_ipv4.txt | Alle Länder kombiniert |

---

## 🌍 Geo-Statistiken (Top Länder)

| Land | IPs |
|-----|----:|
| China | 1,120,000 |
| Russland | 820,000 |
| USA | 610,000 |
| Brasilien | 210,000 |
| Indien | 190,000 |
| Vietnam | 150,000 |
| Iran | 140,000 |
| Südkorea | 120,000 |
| Deutschland | 90,000 |
| Frankreich | 70,000 |

---

## 🌐 Kontinent-Verteilung

| Kontinent | Anteil |
|----------|-------:|
| Asien | 56% |
| Europa | 22% |
| Nordamerika | 12% |
| Südamerika | 5% |
| Afrika | 4% |
| Ozeanien | 1% |

---

## ⚙️ Scoring

Score = Quellen + Aktualität + Persistenz + Historie

- ≥65 → active
- ≥40 → confidence40
- 25–39 → watchlist
- <25 → combined

---

## 🔄 Workflows

- Combined (Core Engine)
- Confidence
- Honeypot / HoneyDB
- Feed Health
- Workflow Health
- Score Decay
- Geo Tagger
- ASN Scorer

---

## 🛡️ Besonderheiten

- Selbstreinigendes System
- Cache-basierte Intelligenz (seen_db)
- False-Positive Schutz
- Multi-Feed Korrelation

---

## 📈 Reports

- NETSHIELD_REPORT.md
- feed_health_report.md
- workflow_health_report.md
- score_decay_report.md

---

## 🛡️ Fazit

Kein statischer Blocklist-Dump, sondern ein dynamisches Threat-Intelligence-System.

---

*Automatisch generiert durch NETSHIELD*
