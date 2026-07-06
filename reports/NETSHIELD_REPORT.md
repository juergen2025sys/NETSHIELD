# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-07-06 16:49 UTC

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | Stufe 1 – Alle IPs (180 Tage) | **7,378,864** | 2026-07-06 16:28 CEST (Europe/Berlin) |
| ✅ `active_blacklist_ipv4.txt` | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **394,081** | 2026-07-06 16:28 CEST (Europe/Berlin) |
| ✅ `blacklist_confidence40_ipv4.txt` | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **5,706,985** | 2026-07-06 16:44 UTC |
| ✅ `watchlist_confidence25to39_ipv4.txt` | Watchlist (Score 25-39/100) | **49,322** | 2026-07-06 16:44 UTC |
| ✅ `cve_exploit_ips.txt` | CVE Exploit IPs | **32,565** | 2026-07-06 08:10 UTC |
| ✅ `bot_detector_blacklist_ipv4.txt` | Bot-Detector Blacklist | **1,263,387** | 2026-07-06 16:40 CEST (Europe/Berlin) |
| ✅ `honeypot_ips.txt` | Honeypot IPs | **118,403** | 2026-07-06 14:18 UTC |
| ✅ `honigtopf_ips.txt` | Honigtopf Community Honeypot (API) | **14,727** | 2026-07-06 16:43 UTC |

---
## 🔍 Feed Health: ✅ 119 OK | ⚠️ 0 leer | ❌ 1 Fehler

**❌ Ausgefallen:** `rutgers_drop`

**🧊 Eingefroren (16):** `amitambekar_threats` 22T, `bbcan177` 22T, `binaryedge_scanners` 22T, `blacksnowdot_packets` 22T, `cloudzy` 22T, `et_block` 22T, `feodo_aggressive` 22T, `feodo_recommended` 22T, `firehol_level1` 22T, `l7_ddos` 22T…

*15 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-07-06 05:04 UTC – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-07-06 16:49 UTC*