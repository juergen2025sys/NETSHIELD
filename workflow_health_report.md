# Workflow Health Checker – Report
**Aktualisiert:** 2026-04-17 04:21 UTC

**Workflows:** 19 | ✅ 17 OK | ⚠️ 2 Warnung | ❌ 0 Fehler

---
## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `dependabot-auto-merge.yml` | timeout-minutes fehlt | Job 'automerge' hat kein timeout-minutes – haengende Runs verbrauchen bis zu 360min |
| `dependabot-auto-merge.yml` | Permissions zu breit | permissions: contents: write gesetzt aber kein git commit/push erkennbar – Least-Privilege-Verletzung |
| `dependabot-heal-conflicts.yml` | Concurrency fehlt | Kein concurrency-Block – parallele Runs möglich bei manuell + scheduled gleichzeitig |
| `dependabot-heal-conflicts.yml` | timeout-minutes fehlt | Job 'heal' hat kein timeout-minutes – haengende Runs verbrauchen bis zu 360min |
| `Cross-Workflow` | WATCHLIST_EXPIRY_DAYS Inkonsistenz | Verschiedene WATCHLIST_EXPIRY_DAYS: 30d in update_combined_blacklist.yml; 180d in auto_feed_discovery.yml |
| `Production Health` | Feed-Ausfälle | 2 von 99 Feeds ausgefallen: abuseipdb_tmiland, c2_tracker |

## 🏥 Production Health

**Status:** 🔴 0 CRITICAL | 🟡 1 WARN

| Level | Check | Detail |
|---|---|---|
| 🟡 WARN | Feed-Ausfälle | 2 von 99 Feeds ausgefallen: abuseipdb_tmiland, c2_tracker |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `asn_reputation_scorer.yml` | ✅ OK | 0 | 0 | `0 2 * * *` |
| `auto_feed_discovery.yml` | ✅ OK | 0 | 0 | `30 4 * * 0` |
| `community_ip_report.yml` | ✅ OK | 0 | 0 | – |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ⚠️ | 0 | 2 | – |
| `dependabot-heal-conflicts.yml` | ⚠️ | 0 | 2 | – |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `geo_tagger.yml` | ✅ OK | 0 | 0 | `45 7 * * 0` |
| `honeydb_monitor.yml` | ✅ OK | 0 | 0 | `15 22 * * *` |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `0 23 * * *` |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *` |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `45 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `0 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `45 0 * * *`, `45 3 * * *`, `45 6 * * *`, `45 9 * * *`, `45 12 * * *`, `45 15 * * *`, `45 18 * * *`, `45 21 * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |

---
*Generiert: 2026-04-17 04:21 UTC | 19 Workflow-Dateien geprüft*