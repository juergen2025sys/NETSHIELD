# Duplicate Cleaner – Report
**Aktualisiert:** 2026-03-17 06:37 UTC

---
## Dateigrößen

| Datei | IPs |
|---|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | 3,935,441 |
| ✅ `tor_exit_nodes.txt` | 7,841 |
| ✅ `cve_exploit_ips.txt` | 229,981 |
| ✅ `honeypot_ips.txt` | 13,846 |
| ✅ `honeydb_ips.txt` | 12,579 |
| ✅ `vpn_proxy_ranges.txt` | 62,466 |
| ✅ `bot_detector_blacklist_ipv4.txt` | 17,954 |

---
## Überschneidungen mit combined_threat_blacklist

> LOCAL_FEEDS (tor/cve/honeypot/honeydb/botdet) werden nicht bereinigt –

> combined liest sie direkt ein. Nur `vpn_proxy_ranges.txt` wird bereinigt.

| Sub-Liste | Gemeinsame IPs | Anteil | Aktion |
|---|---|---|---|
| `tor_exit_nodes.txt` | 7,840 | 100.0% | ⏭️ übersprungen (LOCAL_FEED) |
| `cve_exploit_ips.txt` | 229,890 | 100.0% | ⏭️ übersprungen (LOCAL_FEED) |
| `honeypot_ips.txt` | 13,797 | 99.6% | ⏭️ übersprungen (LOCAL_FEED) |
| `honeydb_ips.txt` | 11,272 | 89.6% | ⏭️ übersprungen (LOCAL_FEED) |
| `vpn_proxy_ranges.txt` | 1 | 0.0% | 🗑️ 1 entfernt |
| `bot_detector_blacklist_ipv4.txt` | 2,462 | 13.7% | ⏭️ übersprungen (LOCAL_FEED) |

---
## Sub-Listen Überschneidungen (nur Info)

| Paar | Gemeinsame IPs |
|---|---|
| `cve∩honeypot` | 9,047 |
| `cve∩honeydb` | 5,747 |
| `honeypot∩honeydb` | 2,877 |
| `tor∩cve` | 726 |
| `cve∩botdet` | 493 |
| `tor∩honeypot` | 24 |
| `honeypot∩botdet` | 24 |
| `tor∩honeydb` | 18 |
| `honeydb∩botdet` | 14 |
| `tor∩botdet` | 1 |
| `honeydb∩vpn` | 1 |

*Sub-Listen-Duplikate werden nicht entfernt – combined dedupliziert automatisch.*

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Duplikate entfernt (nur vpn_proxy_ranges) | **1** |
| Combined Blacklist (unverändert) | **3,935,441** |

---
*Generiert: 2026-03-17 06:37 UTC*