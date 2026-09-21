# Workflow Health Checker – Report
**Aktualisiert:** 2026-09-21 20:39 CEST (Europe/Berlin)

**Workflows:** 31 | ✅ 29 OK | ⚠️ 2 Warnung | ❌ 1 Fehler

---
## Regressionstests

✅ Commit: `ce667cc5f3b0f1a99cdfc790c1912a67dea5fe7b`

460 Tests; 0 Fehlschlaege, 0 Ausfuehrungsfehler, 0 uebersprungen, 0 unerwartete Testerfolge, 0 fehlende Pflichtpruefungen, 0 Pflichtpruefungen nicht bestanden.

Diese Pruefung meldet nur Warnungen. Sie prueft bekannte Fehlerfaelle; sie garantiert keine vollstaendige Fehlerfreiheit.

## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `runner_image_watch.yml` | persist-credentials fehlt | git push verwendet aber checkout ohne persist-credentials: true – Push wird fehlschlagen |

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `netshield_report_generator.yml` | Doppelter Import | Block 0: Doppelte Imports: ((2x) – moeglicherweise Copy-Paste-Artefakt |
| `runner_image_watch.yml` | Git Push ohne Retry-Schleife | git push ohne Retry-Schleife – Race-Condition bei parallelen Runs (kein 'for attempt in ...') |
| `Production Health` | Feed-Ausfälle | 2 von 100 Feeds ausgefallen: abuseipdb_tmiland, fortigate_azure |

## 🏥 Production Health

**Status:** 🔴 0 CRITICAL | 🟡 1 WARN

| Level | Check | Detail |
|---|---|---|
| 🟡 WARN | Feed-Ausfälle | 2 von 100 Feeds ausgefallen: abuseipdb_tmiland, fortigate_azure |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `auto_feed_discovery.yml` | ✅ OK | 0 | 0 | `37 4 * * 0`, `23 7 * * 0`, `47 11 * * 0` |
| `auto_feed_refresh.yml` | ✅ OK | 0 | 0 | `15 2 * * *` |
| `codeql.yml` | ✅ OK | 0 | 0 | `0 3 * * 0` |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ✅ OK | 0 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | – |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `feed_ip_finder.yml` | ✅ OK | 0 | 0 | – |
| `feed_overlap_report.yml` | ✅ OK | 0 | 0 | `25 3 * * 0` |
| `force_cancel_stuck_runs.yml` | ✅ OK | 0 | 0 | – |
| `history_fresh_start.yml` | ✅ OK | 0 | 0 | `20 5 1 * *` |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `0 5,11,17,23 * * *` |
| `honigtopf.yml` | ✅ OK | 0 | 0 | `*/20 * * * *`, `5,25,45 * * * *`, `10,30,50 * * * *` |
| `ip_ablauf.yml` | ✅ OK | 0 | 0 | `30 6 * * 1`, `55 */3 * * *` |
| `ledger_diagnose.yml` | ✅ OK | 0 | 0 | – |
| `netshield_report_generator.yml` | ⚠️ | 0 | 1 | `30 * * * *`, `45 * * * *`, `55 * * * *` |
| `repo_size_check.yml` | ✅ OK | 0 | 0 | – |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
| `runner_image_watch.yml` | ❌ | 1 | 1 | `43 5 * * *` |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `sniffcat_fetch.yml` | ✅ OK | 0 | 0 | – |
| `tweetfeed_monitor.yml` | ✅ OK | 0 | 0 | `45 2 * * *` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `35 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `7 */3 * * *`, `27 */3 * * *`, `47 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `47 1,4,7,10,13,16,19,22 * * *` |
| `watchdog_combined.yml` | ✅ OK | 0 | 0 | `*/15 * * * *` |
| `watchdog_ip_ablauf.yml` | ✅ OK | 0 | 0 | `*/30 * * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |
| `workflow_health_dashboard.yml` | ✅ OK | 0 | 0 | `5 */6 * * *` |

---
*Generiert: 2026-09-21 20:39 CEST (Europe/Berlin) | 31 Workflow-Dateien geprüft*