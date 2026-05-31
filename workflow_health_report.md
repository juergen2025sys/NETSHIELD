# Workflow Health Checker – Report
**Aktualisiert:** 2026-05-31 05:44 UTC

**Workflows:** 23 | ✅ 22 OK | ⚠️ 3 Warnung | ❌ 0 Fehler

---
## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `honeypot_monitor.yml → update_combined_blacklist.yml` | Workflow-Reihenfolge / Puffer zu knapp | 00:30 UTC → 00:47 UTC (17min < 60min); 06:30 UTC → 06:47 UTC (17min < 60min); 12:30 UTC → 12:47 UTC (17min < 60min); 18:30 UTC → 18:47 UTC (17min < 60min) |
| `update_combined_blacklist.yml` | Untrusted Feed hq=True | 6 Feed(s) mit hq=True ohne bekannten Betreiber – IPs bleiben dauerhaft in active_blacklist ohne Score-Altern: "fadouse_malware" (https://raw.githubusercontent.com/Fadouse/clash-threat-intel); "fadouse_c2" (https://raw.githubusercontent.com/Fadouse/clash-threat-intel); "fadouse_rat" (https://raw.githubusercontent.com/Fadouse/clash-threat-intel); "fadouse_stealer" (https://raw.githubusercontent.com/Fadouse/clash-threat-intel); "fadouse_loader" (https://raw.githubusercontent.com/Fadouse/clash-threat-intel); "fadouse_worm" (https://raw.githubusercontent.com/Fadouse/clash-threat-intel) |
| `honeypot_monitor.yml → update_combined_blacklist.yml` | Sub-Workflow Puffer zu knapp | Sub-Workflow laueft zu knapp vor Combined – Output moeglicherweise nicht rechtzeitig verfuegbar: 00:30 UTC → 00:47 UTC (17min < 60min Mindestpuffer); 06:30 UTC → 06:47 UTC (17min < 60min Mindestpuffer); 12:30 UTC → 12:47 UTC (17min < 60min Mindestpuffer); 18:30 UTC → 18:47 UTC (17min < 60min Mindestpuffer) |
| `Production Health` | Push-Limit Naehe | seen_db_backup.json.gz: 80.8 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |
| `Production Health` | Push-Limit Naehe | blacklist_geo_enriched.json: 84.0 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |

## 🏥 Production Health

**Status:** 🔴 0 CRITICAL | 🟡 2 WARN

| Level | Check | Detail |
|---|---|---|
| 🟡 WARN | Push-Limit Naehe | seen_db_backup.json.gz: 80.8 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |
| 🟡 WARN | Push-Limit Naehe | blacklist_geo_enriched.json: 84.0 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `asn_reputation_scorer.yml` | ✅ OK | 0 | 0 | `0 2 * * *` |
| `auto_feed_discovery.yml` | ✅ OK | 0 | 0 | `37 4 * * 0`, `23 7 * * 0`, `47 11 * * 0` |
| `codeql.yml` | ✅ OK | 0 | 0 | `0 3 * * 0` |
| `community_ip_report.yml` | ✅ OK | 0 | 0 | – |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ✅ OK | 0 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | – |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `geo_tagger.yml` | ✅ OK | 0 | 0 | `45 7 * * 0` |
| `honeydb_monitor.yml` | ✅ OK | 0 | 0 | `15 22 * * *`, `15 4,10,16 * * *` |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `30 */6 * * *` |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *` |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `tweetfeed_monitor.yml` | ✅ OK | 0 | 0 | `45 2 * * *` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `45 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `7 */3 * * *`, `27 */3 * * *`, `47 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | – |
| `watchdog_combined.yml` | ✅ OK | 0 | 0 | `*/15 * * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |
| `workflow_health_report.yml` | ✅ OK | 0 | 0 | `5 */6 * * *` |

---
*Generiert: 2026-05-31 05:44 UTC | 23 Workflow-Dateien geprüft*