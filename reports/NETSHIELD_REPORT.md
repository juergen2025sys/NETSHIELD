# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-10-03 10:26 CEST (Europe/Berlin)

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ [combined_threat_blacklist_ipv4_part1.txt](../combined_threat_blacklist_ipv4_part1.txt) + [combined_threat_blacklist_ipv4_part2.txt](../combined_threat_blacklist_ipv4_part2.txt) | Stufe 1 – Alle IPs (180 Tage) | **12,124,712** | 2026-10-03 09:26 CEST (Europe/Berlin) |
| ✅ [active_blacklist_ipv4.txt](../active_blacklist_ipv4.txt) | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **1,005,983** | 2026-10-03 09:26 CEST (Europe/Berlin) |
| ✅ [blacklist_confidence40_ipv4_part1.txt](../blacklist_confidence40_ipv4_part1.txt) + [blacklist_confidence40_ipv4_part2.txt](../blacklist_confidence40_ipv4_part2.txt) | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **9,182,982** | 2026-10-03 09:31 CEST (Europe/Berlin) |
| ✅ [watchlist_confidence25to39_ipv4.txt](../watchlist_confidence25to39_ipv4.txt) | Watchlist (Score 25-39/100) | **2,941,730** | 2026-10-03 09:31 CEST (Europe/Berlin) |
| ✅ [cve_exploit_ips.txt](../cve_exploit_ips.txt) | CVE Exploit IPs | **25,699** | 2026-10-03 10:17 CEST (Europe/Berlin) |
| ✅ [bot_detector_blacklist_ipv4.txt](../bot_detector_blacklist_ipv4.txt) | Bot-Detector Blacklist | **1,136,517** | 2026-10-03 09:40 CEST (Europe/Berlin) |
| ✅ [honeypot_ips.txt](../honeypot_ips.txt) | Honeypot IPs | **2,277,317** | 2026-10-03 09:40 CEST (Europe/Berlin) |
| ✅ [honigtopf_ips.txt](../honigtopf_ips.txt) | Honigtopf Community Honeypot (API) | **14,276** | 2026-10-03 10:16 CEST (Europe/Berlin) |

---
## 🔍 Feed Health: ✅ 99 OK | ⚠️ 1 leer | ❌ 3 Fehler

**❌ Ausgefallen:** `abuseipdb_tmiland`, `edanwong`, `fortigate_azure`

**⚠️ Leer:** `blocklist_de_ssh`

**🧊 Eingefroren (1):** `ashleykleynhans_abuseipdb` 59T

*1 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-10-03 07:56 CEST (Europe/Berlin) – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-10-03 10:26 CEST (Europe/Berlin)*