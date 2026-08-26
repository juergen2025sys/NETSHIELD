# 🛡 NETSHIELD Report
**Aktualisiert:** 2026-08-26 21:27 CEST (Europe/Berlin)

---
## 📊 Listen-Übersicht

| Datei | Beschreibung | IPs | Letzte Änderung |
|---|---|---:|---|
| ✅ `combined_threat_blacklist_ipv4.txt` | Stufe 1 – Alle IPs (180 Tage) | **9,614,716** | 2026-08-26 21:14 CEST (Europe/Berlin) |
| ✅ `active_blacklist_ipv4.txt` | Stufe 2 – Aktiv (30 Tage + Conf≥65) | **883,170** | 2026-08-26 21:14 CEST (Europe/Berlin) |
| ❌ `blacklist_confidence40_ipv4.txt` | Mittleres/Hohes Vertrauen (≥40/100) → OPNsense | **0** | – |
| ✅ `watchlist_confidence25to39_ipv4.txt` | Watchlist (Score 25-39/100) | **61,051** | 2026-08-26 21:20 CEST (Europe/Berlin) |
| ✅ `cve_exploit_ips.txt` | CVE Exploit IPs | **29,235** | 2026-08-26 06:30 CEST (Europe/Berlin) |
| ✅ `bot_detector_blacklist_ipv4.txt` | Bot-Detector Blacklist | **1,310,351** | 2026-08-26 20:33 CEST (Europe/Berlin) |
| ✅ `honeypot_ips.txt` | Honeypot IPs | **1,814,667** | 2026-08-26 20:34 CEST (Europe/Berlin) |
| ✅ `honigtopf_ips.txt` | Honigtopf Community Honeypot (API) | **14,490** | 2026-08-26 20:55 CEST (Europe/Berlin) |

---
## 🔍 Feed Health: ✅ 99 OK | ⚠️ 0 leer | ❌ 1 Fehler

**❌ Ausgefallen:** `threat_live`

**🧊 Eingefroren (2):** `ashleykleynhans_abuseipdb` 21T, `blacksnowdot_packets` 21T

*2 davon ≥21 Tage → im Combined automatisch in Quarantäne (eingefrorene HQ-Feeds zählen nicht mehr als frische Bestätigung, betroffene IPs altern normal aus). Details: [reports/stale_feed_report.md](reports/stale_feed_report.md)*

*Letzter Check: 2026-08-26 04:20 CEST (Europe/Berlin) – Details: [reports/feed_health_report.md](reports/feed_health_report.md)*

---
## ⚙️ Workflow Health

*Details: [reports/workflow_health_report.md](reports/workflow_health_report.md)*

---
*Automatisch generiert von NETSHIELD Report Generator · 2026-08-26 21:27 CEST (Europe/Berlin)*