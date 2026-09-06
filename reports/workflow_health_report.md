# Workflow Health Checker – Report
**Aktualisiert:** 2026-09-06 18:14 CEST (Europe/Berlin)

**Workflows:** 30 | ✅ 30 OK | ⚠️ 0 Warnung | ❌ 1 Fehler

---
## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | active ⊆ conf40 Subset-Invariante verletzt | 2,843 IPs in active fehlen in conf40 (0.345% von active). Ursache vermutlich Cache-Drift zwischen combined- und confidence-Workflow (siehe BUG-CACHE-DRIFT). Der Heilungs-Pfad in update_confidence_blacklist.yml hat entweder nicht gegriffen (Cap >10%) oder wurde umgangen. |

## 🏥 Production Health

**Status:** 🔴 1 CRITICAL | 🟡 0 WARN

| Level | Check | Detail |
|---|---|---|
| 🔴 CRITICAL | active ⊆ conf40 Subset-Invariante verletzt | 2,843 IPs in active fehlen in conf40 (0.345% von active). Ursache vermutlich Cache-Drift zwischen combined- und confidence-Workflow (siehe BUG-CACHE-DRIFT). Der Heilungs-Pfad in update_confidence_blacklist.yml hat entweder nicht gegriffen (Cap >10%) oder wurde umgangen. |

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
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *`, `45 * * * *`, `55 * * * *` |
| `repo_size_check.yml` | ✅ OK | 0 | 0 | – |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
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
*Generiert: 2026-09-06 18:14 CEST (Europe/Berlin) | 30 Workflow-Dateien geprüft*