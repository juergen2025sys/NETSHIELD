# Workflow Health Checker – Report
**Aktualisiert:** 2026-11-27 18:27 CET (Europe/Berlin)

**Workflows:** 36 | ✅ 36 OK | ⚠️ 0 Warnung | ❌ 1 Fehler

---
## Regressionstests

✅ Commit: `066eb1fe5dcce9668dcf09a0e5ece16c38372fe6`

500 Tests; 0 Fehlschlaege, 0 Ausfuehrungsfehler, 0 uebersprungen, 0 unerwartete Testerfolge, 0 fehlende Pflichtpruefungen, 0 Pflichtpruefungen nicht bestanden.

Diese Pruefung meldet nur Warnungen. Sie prueft bekannte Fehlerfaelle; sie garantiert keine vollstaendige Fehlerfreiheit.

## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | Whitelist-Leak: combined_threat_blacklist_ipv4.txt | combined_threat_blacklist_ipv4.txt enthält whitelisted IPs: 18.155.145.96, 23.227.39.20, 34.128.177.21, 34.144.250.199, 35.157.26.135… – Filterung wirkungslos! |
| `Production Health` | Whitelist-Leak: blacklist_confidence40_ipv4.txt | blacklist_confidence40_ipv4.txt enthält whitelisted IPs: 35.157.26.135, 34.128.177.21, 34.144.250.199, 18.155.145.96, 63.176.8.218… – Filterung wirkungslos! |

## 🏥 Production Health

**Status:** 🔴 2 CRITICAL | 🟡 0 WARN

| Level | Check | Detail |
|---|---|---|
| 🔴 CRITICAL | Whitelist-Leak: combined_threat_blacklist_ipv4.txt | combined_threat_blacklist_ipv4.txt enthält whitelisted IPs: 18.155.145.96, 23.227.39.20, 34.128.177.21, 34.144.250.199, 35.157.26.135… – Filterung wirkungslos! |
| 🔴 CRITICAL | Whitelist-Leak: blacklist_confidence40_ipv4.txt | blacklist_confidence40_ipv4.txt enthält whitelisted IPs: 35.157.26.135, 34.128.177.21, 34.144.250.199, 18.155.145.96, 63.176.8.218… – Filterung wirkungslos! |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `asn_drop.yml` | ✅ OK | 0 | 0 | `15 4 * * *`, `15 6 * * *` |
| `auto_feed_discovery.yml` | ✅ OK | 0 | 0 | `37 4 * * 0`, `23 7 * * 0`, `47 11 * * 0` |
| `auto_feed_refresh.yml` | ✅ OK | 0 | 0 | `15 2 * * *` |
| `codeql.yml` | ✅ OK | 0 | 0 | `0 3 * * 0` |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ✅ OK | 0 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | `17 4 * * *` |
| `dns_blocklist_finder.yml` | ✅ OK | 0 | 0 | `40 4 * * *` |
| `dns_list_mirror.yml` | ✅ OK | 0 | 0 | `35 */2 * * *` |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `feed_ip_finder.yml` | ✅ OK | 0 | 0 | – |
| `feed_overlap_report.yml` | ✅ OK | 0 | 0 | `25 3 * * 0` |
| `force_cancel_stuck_runs.yml` | ✅ OK | 0 | 0 | – |
| `history_fresh_start.yml` | ✅ OK | 0 | 0 | `20 5 1 * *` |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `0 5,11,17,23 * * *` |
| `honigtopf.yml` | ✅ OK | 0 | 0 | `17 */2 * * *` |
| `ip_ablauf.yml` | ✅ OK | 0 | 0 | `30 6 * * 1`, `55 */3 * * *` |
| `ledger_diagnose.yml` | ✅ OK | 0 | 0 | – |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *`, `45 * * * *`, `55 * * * *` |
| `open_proxies.yml` | ✅ OK | 0 | 0 | `40 */2 * * *` |
| `repo_size_check.yml` | ✅ OK | 0 | 0 | – |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
| `runner_image_watch.yml` | ✅ OK | 0 | 0 | `0 2 * * 0` |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `sniffcat_fetch.yml` | ✅ OK | 0 | 0 | – |
| `tweetfeed_monitor.yml` | ✅ OK | 0 | 0 | `45 2 * * *` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `35 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `7 */3 * * *`, `27 */3 * * *`, `47 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `47 1,4,7,10,13,16,19,22 * * *` |
| `watchdog_combined.yml` | ✅ OK | 0 | 0 | `*/15 * * * *` |
| `watchdog_ip_ablauf.yml` | ✅ OK | 0 | 0 | `*/30 * * * *` |
| `wireguard_test.yml` | ✅ OK | 0 | 0 | – |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |
| `workflow_health_dashboard.yml` | ✅ OK | 0 | 0 | `5 */6 * * *` |

---
*Generiert: 2026-11-27 18:27 CET (Europe/Berlin) | 36 Workflow-Dateien geprüft*