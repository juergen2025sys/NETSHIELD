# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-11-01 10:58 CET (Europe/Berlin)

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ [combined_threat_blacklist_ipv4_part1.txt](../combined_threat_blacklist_ipv4_part1.txt) + [combined_threat_blacklist_ipv4_part2.txt](../combined_threat_blacklist_ipv4_part2.txt) | Stufe 1 – Alle IPs (180 Tage) | **11,164,109** | 2026-11-01 10:45 CET (Europe/Berlin) |
| ✅ [active_blacklist_ipv4.txt](../active_blacklist_ipv4.txt) | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **769,944** | 2026-11-01 10:45 CET (Europe/Berlin) |
| ✅ [blacklist_confidence40_ipv4_part1.txt](../blacklist_confidence40_ipv4_part1.txt) + [blacklist_confidence40_ipv4_part2.txt](../blacklist_confidence40_ipv4_part2.txt) | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **7,979,670** | 2026-11-01 10:50 CET (Europe/Berlin) |
| ✅ [watchlist_confidence25to39_ipv4.txt](../watchlist_confidence25to39_ipv4.txt) | Watchlist (Score 25-39/100) | **3,184,439** | 2026-11-01 10:50 CET (Europe/Berlin) |
| ✅ [cve_exploit_ips.txt](../cve_exploit_ips.txt) | CVE Exploit IPs | **27,570** | 2026-11-01 09:15 CET (Europe/Berlin) |
| ✅ [bot_detector_blacklist_ipv4.txt](../bot_detector_blacklist_ipv4.txt) | Bot-Detector Blacklist | **1,175,180** | 2026-11-01 09:18 CET (Europe/Berlin) |
| ✅ [honeypot_ips.txt](../honeypot_ips.txt) | Honeypot IPs | **2,190,755** | 2026-11-01 09:18 CET (Europe/Berlin) |
| ✅ [honigtopf_ips.txt](../honigtopf_ips.txt) | Honigtopf Community Honeypot (API) | **16,127** | 2026-11-01 09:14 CET (Europe/Berlin) |

---
## 🔍 Feed Health: ✅ 94 OK | ⚠️ 2 leer | ❌ 2 Fehler

**❌ Ausgefallen:** `greensnow`, `urlhaus_ips`

**⚠️ Leer:** `greedybear_recent`, `romainmarcoux_outgoing_ab`

**🧊 Eingefroren (4):** `black_mirror` 30T, `ultimate_hosts_ips0` 29T, `amitambekar_threats_aa` 25T, `fadouse_worm` 16T

*3 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-11-01 08:00 CET (Europe/Berlin) – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-11-01 10:58 CET (Europe/Berlin)*