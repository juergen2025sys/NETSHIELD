# Duplicate Cleaner – Report
**Aktualisiert:** 2026-03-16 06:50 UTC

---
## Dateigrößen

| Datei | IPs |
|---|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | 3,922,014 |
| ✅ `tor_exit_nodes.txt` | 7,839 |
| ✅ `cve_exploit_ips.txt` | 228,547 |
| ✅ `honeypot_ips.txt` | 13,956 |
| ✅ `honeydb_ips.txt` | 11,306 |
| ✅ `vpn_proxy_ranges.txt` | 62,467 |
| ✅ `bot_detector_blacklist_ipv4.txt` | 17,954 |

---
## Überschneidungen mit combined_threat_blacklist

> LOCAL_FEEDS (tor/cve/honeypot/honeydb/botdet) werden nicht bereinigt –

> combined liest sie direkt ein. Nur `vpn_proxy_ranges.txt` wird bereinigt.

| Sub-Liste | Gemeinsame IPs | Anteil | Aktion |
|---|---|---|---|
| `tor_exit_nodes.txt` | 7,839 | 100.0% | ⏭️ übersprungen (LOCAL_FEED) |
| `cve_exploit_ips.txt` | 228,517 | 100.0% | ⏭️ übersprungen (LOCAL_FEED) |
| `honeypot_ips.txt` | 13,953 | 100.0% | ⏭️ übersprungen (LOCAL_FEED) |
| `honeydb_ips.txt` | 11,306 | 100.0% | ⏭️ übersprungen (LOCAL_FEED) |
| `vpn_proxy_ranges.txt` | 5,762 | 9.2% | 🗑️ 5762 entfernt |
| `bot_detector_blacklist_ipv4.txt` | 2,456 | 13.7% | ⏭️ übersprungen (LOCAL_FEED) |

---
## Sub-Listen Überschneidungen (nur Info)

| Paar | Gemeinsame IPs |
|---|---|
| `cve∩honeypot` | 9,113 |
| `cve∩honeydb` | 6,159 |
| `honeypot∩honeydb` | 2,941 |
| `tor∩cve` | 722 |
| `cve∩botdet` | 494 |
| `honeydb∩botdet` | 55 |
| `cve∩vpn` | 49 |
| `honeypot∩botdet` | 25 |
| `tor∩honeydb` | 19 |
| `tor∩honeypot` | 17 |
| `honeydb∩vpn` | 4 |
| `tor∩botdet` | 1 |
| `honeypot∩vpn` | 1 |
| `vpn∩botdet` | 1 |

*Sub-Listen-Duplikate werden nicht entfernt – combined dedupliziert automatisch.*

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Duplikate entfernt (nur vpn_proxy_ranges) | **5,762** |
| Combined Blacklist (unverändert) | **3,922,014** |

---
*Generiert: 2026-03-16 06:50 UTC*