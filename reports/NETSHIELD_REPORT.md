# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-10-24 09:40 CEST (Europe/Berlin)

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ [combined_threat_blacklist_ipv4_part1.txt](../combined_threat_blacklist_ipv4_part1.txt) + [combined_threat_blacklist_ipv4_part2.txt](../combined_threat_blacklist_ipv4_part2.txt) | Stufe 1 – Alle IPs (180 Tage) | **11,108,021** | 2026-10-24 08:45 CEST (Europe/Berlin) |
| ✅ [active_blacklist_ipv4.txt](../active_blacklist_ipv4.txt) | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **901,699** | 2026-10-24 08:45 CEST (Europe/Berlin) |
| ✅ [blacklist_confidence40_ipv4_part1.txt](../blacklist_confidence40_ipv4_part1.txt) + [blacklist_confidence40_ipv4_part2.txt](../blacklist_confidence40_ipv4_part2.txt) | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **7,966,277** | 2026-10-24 08:28 CEST (Europe/Berlin) |
| ✅ [watchlist_confidence25to39_ipv4.txt](../watchlist_confidence25to39_ipv4.txt) | Watchlist (Score 25-39/100) | **3,134,396** | 2026-10-24 08:28 CEST (Europe/Berlin) |
| ✅ [cve_exploit_ips.txt](../cve_exploit_ips.txt) | CVE Exploit IPs | **24,795** | 2026-10-24 04:13 CEST (Europe/Berlin) |
| ✅ [bot_detector_blacklist_ipv4.txt](../bot_detector_blacklist_ipv4.txt) | Bot-Detector Blacklist | **1,163,757** | 2026-10-24 08:36 CEST (Europe/Berlin) |
| ✅ [honeypot_ips.txt](../honeypot_ips.txt) | Honeypot IPs | **2,362,439** | 2026-10-24 08:36 CEST (Europe/Berlin) |
| ✅ [honigtopf_ips.txt](../honigtopf_ips.txt) | Honigtopf Community Honeypot (API) | **15,807** | 2026-10-24 08:27 CEST (Europe/Berlin) |

---
## 🔍 Feed Health: ✅ 95 OK | ⚠️ 2 leer | ❌ 1 Fehler

**❌ Ausgefallen:** `urlhaus_ips`

**⚠️ Leer:** `greedybear_recent`, `romainmarcoux_outgoing_ab`

**🧊 Eingefroren (3):** `black_mirror` 21T, `ultimate_hosts_ips0` 20T, `amitambekar_threats_aa` 17T

*1 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-10-24 07:15 CEST (Europe/Berlin) – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-10-24 09:40 CEST (Europe/Berlin)*