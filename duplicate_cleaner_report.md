# Duplicate Cleaner – Report
**Aktualisiert:** 2026-03-09 17:41 UTC

---
## Dateigrößen

| Datei | IPs |
|---|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | 2,344,956 |
| ✅ `tor_exit_nodes.txt` | 20,120 |
| ✅ `cve_exploit_ips.txt` | 220,881 |
| ✅ `vpn_proxy_ranges.txt` | 111,959 |
| ✅ `bot_detector_blacklist_ipv4.txt` | 15,912 |

---
## Überschneidungen mit combined_threat_blacklist

| Sub-Liste | Gemeinsame IPs | Anteil | Aktion |
|---|---|---|---|
| `tor_exit_nodes.txt` | 20,120 | 100.0% | 🔒 behalten (HQ-Feed) |
| `cve_exploit_ips.txt` | 220,880 | 100.0% | 🔒 behalten (HQ-Feed) |
| `vpn_proxy_ranges.txt` | 15 | 0.0% | 🗑️ 15 entfernt |
| `bot_detector_blacklist_ipv4.txt` | 2,042 | 12.8% | 🗑️ 2042 entfernt |

---
## Sub-Listen Überschneidungen (nur Info)

| Paar | Gemeinsame IPs |
|---|---|
| `tor∩cve` | 18,577 |
| `cve∩botdet` | 440 |
| `tor∩botdet` | 47 |
| `cve∩vpn` | 2 |

*Sub-Listen-Duplikate werden nicht entfernt – combined dedupliziert automatisch.*

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Duplikate entfernt (vpn + botdet) | **2,057** |
| Tor/CVE behalten (HQ-Markierung) | **241,000** |
| Combined Blacklist (unverändert) | **2,344,956** |

---
*Generiert: 2026-03-09 17:41 UTC*