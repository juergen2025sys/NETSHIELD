# Duplicate Cleaner – Report
**Aktualisiert:** 2026-03-15 06:32 UTC

---
## Dateigrößen

| Datei | IPs |
|---|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | 2,909,100 |
| ✅ `tor_exit_nodes.txt` | 194 |
| ✅ `cve_exploit_ips.txt` | 2,692 |
| ✅ `honeypot_ips.txt` | 2,930 |
| ✅ `honeydb_ips.txt` | 3,702 |
| ✅ `vpn_proxy_ranges.txt` | 55,442 |
| ✅ `bot_detector_blacklist_ipv4.txt` | 16,195 |

---
## Überschneidungen mit combined_threat_blacklist

| Sub-Liste | Gemeinsame IPs | Anteil | Aktion |
|---|---|---|---|
| `tor_exit_nodes.txt` | 7,461 | 3845.9% | 🗑️ 7461 entfernt |
| `cve_exploit_ips.txt` | 223,982 | 8320.3% | 🗑️ 223982 entfernt |
| `honeypot_ips.txt` | 10,871 | 371.0% | 🗑️ 10871 entfernt |
| `honeydb_ips.txt` | 7,331 | 198.0% | 🗑️ 7331 entfernt |
| `vpn_proxy_ranges.txt` | 1 | 0.0% | 🗑️ 1 entfernt |
| `bot_detector_blacklist_ipv4.txt` | 1,759 | 10.9% | 🗑️ 1759 entfernt |

---
## Sub-Listen Überschneidungen (nur Info)

| Paar | Gemeinsame IPs |
|---|---|
| `cve∩honeypot` | 8,994 |
| `cve∩honeydb` | 6,019 |
| `honeypot∩honeydb` | 2,960 |
| `tor∩cve` | 725 |
| `cve∩botdet` | 498 |
| `honeydb∩botdet` | 59 |
| `tor∩honeydb` | 41 |
| `honeypot∩botdet` | 31 |
| `tor∩honeypot` | 12 |
| `tor∩botdet` | 1 |

*Sub-Listen-Duplikate werden nicht entfernt – combined dedupliziert automatisch.*

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Duplikate entfernt (alle Sub-Listen) | **251,405** |
| Combined Blacklist (unverändert) | **2,909,100** |

---
*Generiert: 2026-03-15 06:32 UTC*