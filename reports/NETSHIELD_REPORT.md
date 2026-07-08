# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-07-08 22:13 UTC

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | Stufe 1 – Alle IPs (180 Tage) | **7,491,612** | 2026-07-09 00:02 CEST (Europe/Berlin) |
| ✅ `active_blacklist_ipv4.txt` | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **421,654** | 2026-07-09 00:02 CEST (Europe/Berlin) |
| ✅ `blacklist_confidence40_ipv4.txt` | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **5,770,221** | 2026-07-08 21:07 UTC |
| ✅ `watchlist_confidence25to39_ipv4.txt` | Watchlist (Score 25-39/100) | **50,752** | 2026-07-08 21:07 UTC |
| ✅ `cve_exploit_ips.txt` | CVE Exploit IPs | **32,452** | 2026-07-08 06:22 UTC |
| ✅ `bot_detector_blacklist_ipv4.txt` | Bot-Detector Blacklist | **1,268,728** | 2026-07-08 23:41 CEST (Europe/Berlin) |
| ✅ `honeypot_ips.txt` | Honeypot IPs | **140,429** | 2026-07-08 18:12 UTC |
| ✅ `honigtopf_ips.txt` | Honigtopf Community Honeypot (API) | **16,895** | 2026-07-08 21:34 UTC |

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
*Automatisch generiert von NETSHIELD Report Generator · 2026-07-08 22:13 UTC*