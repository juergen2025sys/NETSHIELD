# Workflow Health Checker – Report
**Aktualisiert:** 2026-04-04 18:51 UTC

**Workflows:** 16 | ✅ 7 OK | ⚠️ 4 Warnung | ❌ 5 Fehler

---
## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `asn_reputation_scorer.yml` | Report nach Guard-Exit | Block 0 L~241: sys.exit(1) vor Report/Status-Write (asn_reputation_db.json, asn_reputation_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |
| `geo_tagger.yml` | Report nach Guard-Exit | Block 0 L~170: sys.exit(1) vor Report/Status-Write (blacklist_geo_enriched.json, geo_tagger_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |
| `honeydb_monitor.yml` | Report nach Guard-Exit | Block 0 L~213: sys.exit(1) vor Report/Status-Write (honeydb_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |
| `honeypot_monitor.yml` | Report nach Guard-Exit | Block 0 L~134: sys.exit(1) vor Report/Status-Write (honeypot_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |
| `update_bot_detector.yml` | Report nach Guard-Exit | Block 0 L~69: sys.exit(1) vor Report/Status-Write (bot_detector_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `auto_feed_discovery.yml` | Commit-Step nicht always() | Workflow hat MIN_* Guard + Report/Status-Dateien im Commit-Step, aber kein 'if: always()' am Commit-Step – Guard-Fail kann stale Reports hinterlassen |
| `community_ip_report.yml` | Commit-Step Pattern A | Commit-Step nutzt Pattern A – Push-Loop läuft auch ohne Commit. Bevorzuge 'if git diff --staged --quiet; then echo ...; else git commit; push-loop; fi' |
| `cve_to_ip_mapper.yml` | Commit-Step Pattern A | Commit-Step nutzt Pattern A – Push-Loop läuft auch ohne Commit. Bevorzuge 'if git diff --staged --quiet; then echo ...; else git commit; push-loop; fi' |
| `false_positive_checker.yml` | Commit-Step Pattern A | Commit-Step nutzt Pattern A – Push-Loop läuft auch ohne Commit. Bevorzuge 'if git diff --staged --quiet; then echo ...; else git commit; push-loop; fi' |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `asn_reputation_scorer.yml` | ❌ | 1 | 0 | `0 2 * * *` |
| `auto_feed_discovery.yml` | ⚠️ | 0 | 1 | `30 4 * * 0` |
| `community_ip_report.yml` | ⚠️ | 0 | 1 | – |
| `cve_to_ip_mapper.yml` | ⚠️ | 0 | 1 | `0 4 * * *` |
| `false_positive_checker.yml` | ⚠️ | 0 | 1 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `geo_tagger.yml` | ❌ | 1 | 0 | `45 7 * * 0` |
| `honeydb_monitor.yml` | ❌ | 1 | 0 | `15 22 * * *` |
| `honeypot_monitor.yml` | ❌ | 1 | 0 | `0 23 * * *` |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *` |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ❌ | 1 | 0 | `45 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `0 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `45 0 * * *`, `45 3 * * *`, `45 6 * * *`, `45 9 * * *`, `45 12 * * *`, `45 15 * * *`, `45 18 * * *`, `45 21 * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |

---
*Generiert: 2026-04-04 18:51 UTC | 16 Workflow-Dateien geprüft*