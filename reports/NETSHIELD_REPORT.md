# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-10-30 14:57 CET (Europe/Berlin)

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ [combined_threat_blacklist_ipv4_part1.txt](../combined_threat_blacklist_ipv4_part1.txt) + [combined_threat_blacklist_ipv4_part2.txt](../combined_threat_blacklist_ipv4_part2.txt) | Stufe 1 – Alle IPs (180 Tage) | **11,219,800** | 2026-10-30 14:46 CET (Europe/Berlin) |
| ✅ [active_blacklist_ipv4.txt](../active_blacklist_ipv4.txt) | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **803,665** | 2026-10-30 14:46 CET (Europe/Berlin) |
| ✅ [blacklist_confidence40_ipv4_part1.txt](../blacklist_confidence40_ipv4_part1.txt) + [blacklist_confidence40_ipv4_part2.txt](../blacklist_confidence40_ipv4_part2.txt) | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **8,047,571** | 2026-10-30 14:51 CET (Europe/Berlin) |
| ✅ [watchlist_confidence25to39_ipv4.txt](../watchlist_confidence25to39_ipv4.txt) | Watchlist (Score 25-39/100) | **3,172,229** | 2026-10-30 14:51 CET (Europe/Berlin) |
| ✅ [cve_exploit_ips.txt](../cve_exploit_ips.txt) | CVE Exploit IPs | **24,857** | 2026-10-30 11:35 CET (Europe/Berlin) |
| ✅ [bot_detector_blacklist_ipv4.txt](../bot_detector_blacklist_ipv4.txt) | Bot-Detector Blacklist | **1,178,555** | 2026-10-30 11:16 CET (Europe/Berlin) |
| ✅ [honeypot_ips.txt](../honeypot_ips.txt) | Honeypot IPs | **2,377,264** | 2026-10-30 12:04 CET (Europe/Berlin) |
| ✅ [honigtopf_ips.txt](../honigtopf_ips.txt) | Honigtopf Community Honeypot (API) | **17,023** | 2026-10-30 10:55 CET (Europe/Berlin) |

---
## 🔍 Feed Health: ✅ 95 OK | ⚠️ 2 leer | ❌ 1 Fehler

**❌ Ausgefallen:** `urlhaus_ips`

**⚠️ Leer:** `greedybear_recent`, `romainmarcoux_outgoing_ab`

**🧊 Eingefroren (4):** `black_mirror` 28T, `ultimate_hosts_ips0` 27T, `amitambekar_threats_aa` 23T, `fadouse_worm` 14T

*3 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-10-30 07:40 CET (Europe/Berlin) – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-10-30 14:57 CET (Europe/Berlin)*