# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-07-05 12:08 UTC

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | Stufe 1 – Alle IPs (180 Tage) | **7,265,244** | 2026-07-05 11:49 CEST (Europe/Berlin) |
| ✅ `active_blacklist_ipv4.txt` | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **389,210** | 2026-07-05 11:49 CEST (Europe/Berlin) |
| ✅ `blacklist_confidence40_ipv4.txt` | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **5,681,641** | 2026-07-05 12:03 UTC |
| ✅ `watchlist_confidence25to39_ipv4.txt` | Watchlist (Score 25-39/100) | **49,176** | 2026-07-05 12:03 UTC |
| ✅ `cve_exploit_ips.txt` | CVE Exploit IPs | **32,774** | 2026-07-05 07:00 UTC |
| ✅ `bot_detector_blacklist_ipv4.txt` | Bot-Detector Blacklist | **200,664** | 2026-07-05 13:55 CEST (Europe/Berlin) |
| ✅ `honeypot_ips.txt` | Honeypot IPs | **116,570** | 2026-07-05 12:07 UTC |
| ✅ `honigtopf_ips.txt` | Honigtopf Community Honeypot (API) | **12,078** | 2026-07-05 11:13 UTC |

---
## 🔍 Feed Health: ✅ 119 OK | ⚠️ 0 leer | ❌ 1 Fehler

**❌ Ausgefallen:** `rutgers_drop`

**🧊 Eingefroren (17):** `amitambekar_threats` 21T, `bbcan177` 21T, `binaryedge_scanners` 21T, `blacksnowdot_packets` 21T, `cloudzy` 21T, `et_block` 21T, `fadouse_worm` 21T, `feodo_aggressive` 21T, `feodo_recommended` 21T, `firehol_level1` 21T…

*15 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-07-05 04:51 UTC – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-07-05 12:08 UTC*