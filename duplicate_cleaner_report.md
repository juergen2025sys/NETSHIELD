# Duplicate Cleaner – Report
**Aktualisiert:** 2026-03-11 05:35 UTC

---
## Dateigrößen

| Datei | IPs |
|---|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | 2,798,654 |
| ✅ `tor_exit_nodes.txt` | 7,927 |
| ✅ `cve_exploit_ips.txt` | 222,811 |
| ✅ `vpn_proxy_ranges.txt` | 57,800 |
| ✅ `bot_detector_blacklist_ipv4.txt` | 15,534 |

---
## Überschneidungen mit combined_threat_blacklist

| Sub-Liste | Gemeinsame IPs | Anteil | Aktion |
|---|---|---|---|
| `tor_exit_nodes.txt` | 7,927 | 100.0% | 🔒 behalten (HQ-Feed) |
| `cve_exploit_ips.txt` | 222,731 | 100.0% | 🔒 behalten (HQ-Feed) |
| `vpn_proxy_ranges.txt` | 2 | 0.0% | 🗑️ 2 entfernt |
| `bot_detector_blacklist_ipv4.txt` | 2,420 | 15.6% | 🗑️ 2420 entfernt |

---
## Sub-Listen Überschneidungen (nur Info)

| Paar | Gemeinsame IPs |
|---|---|
| `tor∩cve` | 728 |
| `cve∩botdet` | 461 |
| `tor∩botdet` | 1 |

*Sub-Listen-Duplikate werden nicht entfernt – combined dedupliziert automatisch.*

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Duplikate entfernt (vpn + botdet) | **2,422** |
| Tor/CVE behalten (HQ-Markierung) | **230,658** |
| Combined Blacklist (unverändert) | **2,798,654** |

---
*Generiert: 2026-03-11 05:35 UTC*