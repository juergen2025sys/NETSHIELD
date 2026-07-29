# Workflow Health Checker – Report
**Aktualisiert:** 2026-07-29 15:18 UTC

**Workflows:** 23 | ✅ 21 OK | ⚠️ 2 Warnung | ❌ 2 Fehler

---
## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `feed_overlap_report.yml` | persist-credentials fehlt | git push verwendet aber checkout ohne persist-credentials: true – Push wird fehlschlagen |
| `Production Health` | Push-Limit Naehe | combined_threat_blacklist_ipv4.txt: 110.9 MB (>= 95 MB) – naechster git push kann am 100 MB Limit scheitern. Splitting/Truncate-Logik fehlt oder Schwelle anpassen. |
| `Production Health` | Push-Limit Naehe | state/seen_db_backup.json.gz.part000: 95.0 MB (>= 95 MB) – naechster git push kann am 100 MB Limit scheitern. Splitting/Truncate-Logik fehlt oder Schwelle anpassen. |

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `feed_overlap_report.yml` | Node24 env fehlt | FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 env-Variable fehlt – Node.js Kompatibilitaetsproblem moeglich |
| `update_combined_blacklist.yml` | Untrusted Feed hq=True | 1 Feed(s) mit hq=True ohne bekannten Betreiber – IPs bleiben dauerhaft in active_blacklist ohne Score-Altern: "threat_live" (https://list.threat.live/) |
| `Cross-Workflow` | Doppelte Feed-URLs | 1 URL(s) in mehreren Workflows – today_count Aufblaehung moeglich: greylist-latest.csv in honeypot_monitor.yml+update_combined_blacklist.yml |
| `Production Health` | Push-Limit Naehe | blacklist_confidence40_ipv4.txt: 87.0 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |

## 🏥 Production Health

**Status:** 🔴 2 CRITICAL | 🟡 1 WARN

| Level | Check | Detail |
|---|---|---|
| 🔴 CRITICAL | Push-Limit Naehe | combined_threat_blacklist_ipv4.txt: 110.9 MB (>= 95 MB) – naechster git push kann am 100 MB Limit scheitern. Splitting/Truncate-Logik fehlt oder Schwelle anpassen. |
| 🔴 CRITICAL | Push-Limit Naehe | state/seen_db_backup.json.gz.part000: 95.0 MB (>= 95 MB) – naechster git push kann am 100 MB Limit scheitern. Splitting/Truncate-Logik fehlt oder Schwelle anpassen. |
| 🟡 WARN | Push-Limit Naehe | blacklist_confidence40_ipv4.txt: 87.0 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |

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
| `feed_overlap_report.yml` | ❌ | 1 | 1 | `25 3 * * 0` |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `0 5,11,17,23 * * *` |
| `honigtopf.yml` | ✅ OK | 0 | 0 | `15 22 * * *` |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *` |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
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
*Generiert: 2026-07-29 15:18 UTC | 23 Workflow-Dateien geprüft*