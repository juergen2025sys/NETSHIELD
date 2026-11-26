# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-11-26 02:04 CET (Europe/Berlin)

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ [combined_threat_blacklist_ipv4_part1.txt](../combined_threat_blacklist_ipv4_part1.txt) + [combined_threat_blacklist_ipv4_part2.txt](../combined_threat_blacklist_ipv4_part2.txt) | Stufe 1 – Alle IPs (180 Tage) | **11,268,343** | 2026-11-26 01:52 CET (Europe/Berlin) |
| ✅ [active_blacklist_ipv4.txt](../active_blacklist_ipv4.txt) | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **327,372** | 2026-11-26 01:52 CET (Europe/Berlin) |
| ✅ [blacklist_confidence40_ipv4_part1.txt](../blacklist_confidence40_ipv4_part1.txt) + [blacklist_confidence40_ipv4_part2.txt](../blacklist_confidence40_ipv4_part2.txt) | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **7,897,382** | 2026-11-26 01:58 CET (Europe/Berlin) |
| ✅ [watchlist_confidence25to39_ipv4.txt](../watchlist_confidence25to39_ipv4.txt) | Watchlist (Score 25-39/100) | **3,370,961** | 2026-11-26 01:58 CET (Europe/Berlin) |
| ✅ [cve_exploit_ips.txt](../cve_exploit_ips.txt) | CVE Exploit IPs | **35,288** | 2026-11-26 00:52 CET (Europe/Berlin) |
| ✅ [bot_detector_blacklist_ipv4.txt](../bot_detector_blacklist_ipv4.txt) | Bot-Detector Blacklist | **1,213,131** | 2026-11-26 01:59 CET (Europe/Berlin) |
| ✅ [honeypot_ips.txt](../honeypot_ips.txt) | Honeypot IPs | **2,142,264** | 2026-11-26 01:58 CET (Europe/Berlin) |
| ✅ [honigtopf_ips.txt](../honigtopf_ips.txt) | Honigtopf Community Honeypot (API) | **18,581** | 2026-11-26 01:24 CET (Europe/Berlin) |

---
## 🔍 Feed Health: ✅ 100 OK | ⚠️ 2 leer | ❌ 1 Fehler

**❌ Ausgefallen:** `data_shield`

**⚠️ Leer:** `bsdly_traplist`, `greedybear_recur`

**🧊 Eingefroren (3):** `ffraud_confirmed` 21T, `firehol_webserver` 15T, `myip_ms` 15T

*1 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-11-25 10:25 CET (Europe/Berlin) – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-11-26 02:04 CET (Europe/Berlin)*