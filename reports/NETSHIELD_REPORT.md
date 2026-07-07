# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-07-07 16:16 UTC

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | Stufe 1 – Alle IPs (180 Tage) | **7,428,826** | 2026-07-07 17:29 CEST (Europe/Berlin) |
| ✅ `active_blacklist_ipv4.txt` | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **411,106** | 2026-07-07 17:29 CEST (Europe/Berlin) |
| ✅ `blacklist_confidence40_ipv4.txt` | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **5,742,317** | 2026-07-07 16:11 UTC |
| ✅ `watchlist_confidence25to39_ipv4.txt` | Watchlist (Score 25-39/100) | **50,080** | 2026-07-07 16:11 UTC |
| ✅ `cve_exploit_ips.txt` | CVE Exploit IPs | **32,478** | 2026-07-07 07:29 UTC |
| ✅ `bot_detector_blacklist_ipv4.txt` | Bot-Detector Blacklist | **1,266,895** | 2026-07-07 18:01 CEST (Europe/Berlin) |
| ✅ `honeypot_ips.txt` | Honeypot IPs | **119,820** | 2026-07-07 13:09 UTC |
| ✅ `honigtopf_ips.txt` | Honigtopf Community Honeypot (API) | **15,630** | 2026-07-07 16:01 UTC |

---
## 🔍 Feed Health: ✅ 119 OK | ⚠️ 0 leer | ❌ 1 Fehler

**❌ Ausgefallen:** `rutgers_drop`

**🧊 Eingefroren (17):** `amitambekar_threats` 23T, `bbcan177` 23T, `binaryedge_scanners` 23T, `blacksnowdot_packets` 23T, `cloudzy` 23T, `et_block` 23T, `feodo_aggressive` 23T, `feodo_recommended` 23T, `firehol_level1` 23T, `l7_ddos` 23T…

*15 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-07-07 04:43 UTC – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-07-07 16:16 UTC*