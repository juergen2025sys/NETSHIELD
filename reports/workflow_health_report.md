# Workflow Health Checker – Report
**Aktualisiert:** 2026-08-10 21:58 CEST (Europe/Berlin)

**Workflows:** 26 | ✅ 26 OK | ⚠️ 3 Warnung | ❌ 0 Fehler

---
## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `honigtopf.yml → update_bot_detector.yml` | Workflow-Reihenfolge / Puffer zu knapp | 22:40 UTC → 22:45 UTC (5min < 15min) |
| `honigtopf.yml → update_combined_blacklist.yml` | Sub-Workflow Puffer zu knapp | Sub-Workflow laueft zu knapp vor Combined – Output moeglicherweise nicht rechtzeitig verfuegbar: 00:00 UTC → 00:07 UTC (7min < 60min Mindestpuffer); 00:20 UTC → 00:27 UTC (7min < 60min Mindestpuffer); 00:40 UTC → 00:47 UTC (7min < 60min Mindestpuffer); 02:20 UTC → 03:07 UTC (47min < 60min Mindestpuffer); 02:40 UTC → 03:07 UTC (27min < 60min Mindestpuffer) |
| `Production Health` | Feed-Ausfälle | 2 von 102 Feeds ausgefallen: hagezi_tif, interserver |

## 🏥 Production Health

**Status:** 🔴 0 CRITICAL | 🟡 1 WARN

| Level | Check | Detail |
|---|---|---|
| 🟡 WARN | Feed-Ausfälle | 2 von 102 Feeds ausgefallen: hagezi_tif, interserver |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `auto_feed_discovery.yml` | ✅ OK | 0 | 0 | `37 4 * * 0`, `23 7 * * 0`, `47 11 * * 0` |
| `codeql.yml` | ✅ OK | 0 | 0 | `0 3 * * 0` |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ✅ OK | 0 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | – |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `feed_ip_finder.yml` | ✅ OK | 0 | 0 | – |
| `feed_overlap_report.yml` | ✅ OK | 0 | 0 | `25 3 * * 0` |
| `history_fresh_start.yml` | ✅ OK | 0 | 0 | `15 3 1 * *` |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `0 5,11,17,23 * * *` |
| `honigtopf.yml` | ✅ OK | 0 | 0 | `*/20 * * * *`, `15 22 * * *` |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *` |
| `repo_size_check.yml` | ✅ OK | 0 | 0 | – |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `seen_db_expiry_forecast.yml` | ✅ OK | 0 | 0 | `30 6 * * 1` |
| `tweetfeed_monitor.yml` | ✅ OK | 0 | 0 | `45 2 * * *` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `45 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `7 */3 * * *`, `27 */3 * * *`, `47 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `47 1,4,7,10,13,16,19,22 * * *` |
| `watchdog_combined.yml` | ✅ OK | 0 | 0 | `*/15 * * * *` |
| `watchdog_honigtopf.yml` | ✅ OK | 0 | 0 | `7,22,37,52 * * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |
| `workflow_health_report.yml` | ✅ OK | 0 | 0 | `5 */6 * * *` |

---
*Generiert: 2026-08-10 21:58 CEST (Europe/Berlin) | 26 Workflow-Dateien geprüft*