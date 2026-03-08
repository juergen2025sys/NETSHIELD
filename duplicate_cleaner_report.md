# Duplicate Cleaner – Report
**Aktualisiert:** 2026-03-08 21:19 UTC

---
## Dateigrößen

| Datei | IPs |
|---|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | 2,308,314 |
| ✅ `tor_exit_nodes.txt` | 20,365 |
| ✅ `cve_exploit_ips.txt` | 205,073 |
| ✅ `vpn_proxy_ranges.txt` | 112,345 |
| ✅ `bot_detector_blacklist_ipv4.txt` | 16,357 |

---
## Überschneidungen mit combined_threat_blacklist

| Sub-Liste | Gemeinsame IPs | Anteil | Aktion |
|---|---|---|---|
| `tor_exit_nodes.txt` | 19,857 | 97.5% | 🔒 behalten (HQ-Feed) |
| `cve_exploit_ips.txt` | 203,831 | 99.4% | 🔒 behalten (HQ-Feed) |
| `vpn_proxy_ranges.txt` | 3,651 | 3.2% | 🗑️ 3651 entfernt |
| `bot_detector_blacklist_ipv4.txt` | 1,031 | 6.3% | 🗑️ 1031 entfernt |

---
## Sub-Listen Überschneidungen (nur Info)

| Paar | Gemeinsame IPs |
|---|---|
| `tor∩cve` | 18,786 |
| `cve∩botdet` | 410 |
| `cve∩vpn` | 129 |
| `tor∩botdet` | 45 |
| `tor∩vpn` | 10 |
| `vpn∩botdet` | 1 |

*Sub-Listen-Duplikate werden nicht entfernt – combined dedupliziert automatisch.*

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Duplikate entfernt (vpn + botdet) | **4,682** |
| Tor/CVE behalten (HQ-Markierung) | **223,688** |
| Combined Blacklist (unverändert) | **2,308,314** |

---
*Generiert: 2026-03-08 21:19 UTC*