# Workflow Health Checker – Report
**Aktualisiert:** 2026-07-08 20:36 UTC

**Workflows:** 24 | ✅ 23 OK | ⚠️ 0 Warnung | ❌ 2 Fehler

---
## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `feed_overlap_report.yml` | persist-credentials fehlt | git push verwendet aber checkout ohne persist-credentials: true – Push wird fehlschlagen |
| `Production Health` | Push-Limit Naehe | combined_threat_blacklist_ipv4.txt: 101.9 MB (>= 95 MB) – naechster git push kann am 100 MB Limit scheitern. Splitting/Truncate-Logik fehlt oder Schwelle anpassen. |
| `Production Health` | Push-Limit Naehe | state/seen_db_backup.json.gz.part000: 95.0 MB (>= 95 MB) – naechster git push kann am 100 MB Limit scheitern. Splitting/Truncate-Logik fehlt oder Schwelle anpassen. |

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `feed_overlap_report.yml` | Node24 env fehlt | FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 env-Variable fehlt – Node.js Kompatibilitaetsproblem moeglich |
| `Production Health` | Feed-Ausfälle | 3 von 120 Feeds ausgefallen: 4ip_high_security, fadouse_loader, fadouse_stealer |
| `Production Health` | Push-Limit Naehe | geo_enriched/blacklist_geo_enriched.json: 94.5 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |

## 🏥 Production Health

**Status:** 🔴 2 CRITICAL | 🟡 2 WARN

| Level | Check | Detail |
|---|---|---|
| 🔴 CRITICAL | Push-Limit Naehe | combined_threat_blacklist_ipv4.txt: 101.9 MB (>= 95 MB) – naechster git push kann am 100 MB Limit scheitern. Splitting/Truncate-Logik fehlt oder Schwelle anpassen. |
| 🔴 CRITICAL | Push-Limit Naehe | state/seen_db_backup.json.gz.part000: 95.0 MB (>= 95 MB) – naechster git push kann am 100 MB Limit scheitern. Splitting/Truncate-Logik fehlt oder Schwelle anpassen. |
| 🟡 WARN | Feed-Ausfälle | 3 von 120 Feeds ausgefallen: 4ip_high_security, fadouse_loader, fadouse_stealer |
| 🟡 WARN | Push-Limit Naehe | geo_enriched/blacklist_geo_enriched.json: 94.5 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |

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
| `feed_overlap_report.yml` | ❌ | 1 | 1 | `25 3 * * 0` |
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
*Generiert: 2026-07-08 20:36 UTC | 24 Workflow-Dateien geprüft*