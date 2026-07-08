# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-07-08 11:54 UTC

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | Stufe 1 – Alle IPs (180 Tage) | **7,455,568** | 2026-07-08 13:43 CEST (Europe/Berlin) |
| ✅ `active_blacklist_ipv4.txt` | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **413,366** | 2026-07-08 13:43 CEST (Europe/Berlin) |
| ✅ `blacklist_confidence40_ipv4.txt` | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **5,763,404** | 2026-07-08 11:48 UTC |
| ✅ `watchlist_confidence25to39_ipv4.txt` | Watchlist (Score 25-39/100) | **50,864** | 2026-07-08 11:48 UTC |
| ✅ `cve_exploit_ips.txt` | CVE Exploit IPs | **32,452** | 2026-07-08 06:22 UTC |
| ✅ `bot_detector_blacklist_ipv4.txt` | Bot-Detector Blacklist | **1,263,127** | 2026-07-08 12:35 CEST (Europe/Berlin) |
| ✅ `honeypot_ips.txt` | Honeypot IPs | **120,787** | 2026-07-08 07:21 UTC |
| ✅ `honigtopf_ips.txt` | Honigtopf Community Honeypot (API) | **14,256** | 2026-07-08 10:35 UTC |

---
## 🔍 Feed Health: ✅ 117 OK | ⚠️ 0 leer | ❌ 3 Fehler

**❌ Ausgefallen:** `4ip_high_security`, `fadouse_loader`, `fadouse_stealer`

**🧊 Eingefroren (17):** `amitambekar_threats` 24T, `bbcan177` 24T, `binaryedge_scanners` 24T, `blacksnowdot_packets` 24T, `cloudzy` 24T, `et_block` 24T, `feodo_aggressive` 24T, `feodo_recommended` 24T, `firehol_level1` 24T, `l7_ddos` 24T…

*15 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-07-08 04:09 UTC – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-07-08 11:54 UTC*