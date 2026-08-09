# Workflow Health Checker – Report
**Aktualisiert:** 2026-08-09 03:06 UTC

**Workflows:** 26 | ✅ 23 OK | ⚠️ 4 Warnung | ❌ 0 Fehler

---
## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `auto_feed_discovery.yml` | timeout-minutes fehlt | Job 'discover' hat kein timeout-minutes – haengende Runs verbrauchen bis zu 360min |
| `feed_overlap_report.yml` | Node24 env fehlt | FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 env-Variable fehlt – Node.js Kompatibilitaetsproblem moeglich |
| `update_combined_blacklist.yml` | HIGH_QUALITY ↔ SOURCES Drift | In HIGH_QUALITY aber nicht hq=True in SOURCES: cloudzy, et_block, feodo_aggressive, feodo_recommended, firehol_cybercrime, firehol_level1, firehol_webclient – toter Code |
| `update_combined_blacklist.yml` | Untrusted Feed hq=True | 2 Feed(s) mit hq=True ohne bekannten Betreiber – IPs bleiben dauerhaft in active_blacklist ohne Score-Altern: "threatslist_paloalto_edl" (https://threatslist.github.io/Palo-Alto-EDL/edl_list.txt); "threat_live" (https://list.threat.live/) |
| `Cross-Workflow` | Doppelte Feed-URLs | 1 URL(s) in mehreren Workflows – today_count Aufblaehung moeglich: greylist-latest.csv in honeypot_monitor.yml+update_combined_blacklist.yml |

## 🏥 Production Health

**Status:** 🔴 0 CRITICAL | 🟡 0 WARN

*Alle Production Health Checks bestanden.*

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `auto_feed_discovery.yml` | ⚠️ | 0 | 1 | `37 4 * * 0`, `23 7 * * 0`, `47 11 * * 0` |
| `codeql.yml` | ✅ OK | 0 | 0 | `0 3 * * 0` |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ✅ OK | 0 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | – |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `feed_ip_finder.yml` | ✅ OK | 0 | 0 | – |
| `feed_overlap_report.yml` | ⚠️ | 0 | 1 | `25 3 * * 0` |
| `history_fresh_start.yml` | ✅ OK | 0 | 0 | `15 3 1 * *` |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `0 5,11,17,23 * * *` |
| `honigtopf.yml` | ✅ OK | 0 | 0 | `15 22 * * *` |
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
*Generiert: 2026-08-09 03:06 UTC | 26 Workflow-Dateien geprüft*