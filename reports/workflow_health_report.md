# Workflow Health Checker – Report
**Aktualisiert:** 2026-06-28 10:08 UTC

**Workflows:** 23 | ✅ 23 OK | ⚠️ 1 Warnung | ❌ 0 Fehler

---
## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | Push-Limit Naehe | combined_threat_blacklist_ipv4.txt: 90.2 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |
| `Production Health` | Push-Limit Naehe | state/seen_db_backup.json.gz.part000: 93.9 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |
| `Production Health` | Push-Limit Naehe | geo_enriched/blacklist_geo_enriched.json: 94.8 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |

## 🏥 Production Health

**Status:** 🔴 0 CRITICAL | 🟡 3 WARN

| Level | Check | Detail |
|---|---|---|
| 🟡 WARN | Push-Limit Naehe | combined_threat_blacklist_ipv4.txt: 90.2 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |
| 🟡 WARN | Push-Limit Naehe | state/seen_db_backup.json.gz.part000: 93.9 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |
| 🟡 WARN | Push-Limit Naehe | geo_enriched/blacklist_geo_enriched.json: 94.8 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `asn_reputation_scorer.yml` | ✅ OK | 0 | 0 | `0 2 * * *` |
| `auto_feed_discovery.yml` | ✅ OK | 0 | 0 | `37 4 * * 0`, `23 7 * * 0`, `47 11 * * 0` |
| `codeql.yml` | ✅ OK | 0 | 0 | `0 3 * * 0` |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ✅ OK | 0 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | – |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `geo_tagger.yml` | ✅ OK | 0 | 0 | `45 7 * * 0` |
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
*Generiert: 2026-06-28 10:08 UTC | 23 Workflow-Dateien geprüft*