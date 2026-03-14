# Duplicate Cleaner – Report
**Aktualisiert:** 2026-03-14 06:04 UTC

---
## Dateigrößen

| Datei | IPs |
|---|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | 3,239,203 |
| ✅ `tor_exit_nodes.txt` | 7,768 |
| ✅ `cve_exploit_ips.txt` | 226,095 |
| ✅ `vpn_proxy_ranges.txt` | 57,778 |
| ✅ `bot_detector_blacklist_ipv4.txt` | 15,520 |

---
## Überschneidungen mit combined_threat_blacklist

| Sub-Liste | Gemeinsame IPs | Anteil | Aktion |
|---|---|---|---|
| `tor_exit_nodes.txt` | 7,767 | 100.0% | 🔒 behalten (HQ-Feed) |
| `cve_exploit_ips.txt` | 224,226 | 99.2% | 🔒 behalten (HQ-Feed) |
| `vpn_proxy_ranges.txt` | 3 | 0.0% | 🗑️ 3 entfernt |
| `bot_detector_blacklist_ipv4.txt` | 2,434 | 15.7% | 🗑️ 2434 entfernt |

---
## Sub-Listen Überschneidungen (nur Info)

| Paar | Gemeinsame IPs |
|---|---|
| `tor∩cve` | 725 |
| `cve∩botdet` | 496 |
| `tor∩botdet` | 1 |

*Sub-Listen-Duplikate werden nicht entfernt – combined dedupliziert automatisch.*

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Duplikate entfernt (vpn + botdet) | **2,437** |
| Tor/CVE behalten (HQ-Markierung) | **231,993** |
| Combined Blacklist (unverändert) | **3,239,203** |

---
*Generiert: 2026-03-14 06:04 UTC*