# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-10-28 20:34 CET (Europe/Berlin)

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ [combined_threat_blacklist_ipv4_part1.txt](../combined_threat_blacklist_ipv4_part1.txt) + [combined_threat_blacklist_ipv4_part2.txt](../combined_threat_blacklist_ipv4_part2.txt) | Stufe 1 – Alle IPs (180 Tage) | **11,208,279** | 2026-10-28 20:21 CET (Europe/Berlin) |
| ✅ [active_blacklist_ipv4.txt](../active_blacklist_ipv4.txt) | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **805,161** | 2026-10-28 20:21 CET (Europe/Berlin) |
| ✅ [blacklist_confidence40_ipv4_part1.txt](../blacklist_confidence40_ipv4_part1.txt) + [blacklist_confidence40_ipv4_part2.txt](../blacklist_confidence40_ipv4_part2.txt) | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **8,049,390** | 2026-10-28 20:27 CET (Europe/Berlin) |
| ✅ [watchlist_confidence25to39_ipv4.txt](../watchlist_confidence25to39_ipv4.txt) | Watchlist (Score 25-39/100) | **3,158,889** | 2026-10-28 20:27 CET (Europe/Berlin) |
| ✅ [cve_exploit_ips.txt](../cve_exploit_ips.txt) | CVE Exploit IPs | **24,837** | 2026-10-28 18:21 CET (Europe/Berlin) |
| ✅ [bot_detector_blacklist_ipv4.txt](../bot_detector_blacklist_ipv4.txt) | Bot-Detector Blacklist | **1,176,804** | 2026-10-28 20:08 CET (Europe/Berlin) |
| ✅ [honeypot_ips.txt](../honeypot_ips.txt) | Honeypot IPs | **2,350,010** | 2026-10-28 20:08 CET (Europe/Berlin) |
| ✅ [honigtopf_ips.txt](../honigtopf_ips.txt) | Honigtopf Community Honeypot (API) | **20,807** | 2026-10-28 20:11 CET (Europe/Berlin) |

---
## 🔍 Feed Health: ✅ 92 OK | ⚠️ 2 leer | ❌ 4 Fehler

**❌ Ausgefallen:** `blocklist_de_all`, `blocklist_net_ua`, `rtbh_com_tr`, `urlhaus_ips`

**⚠️ Leer:** `greedybear_recent`, `romainmarcoux_outgoing_ab`

**🧊 Eingefroren (3):** `black_mirror` 25T, `ultimate_hosts_ips0` 25T, `amitambekar_threats_aa` 21T

*3 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-10-28 07:28 CET (Europe/Berlin) – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-10-28 20:34 CET (Europe/Berlin)*