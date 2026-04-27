# Workflow Health Checker – Report
**Aktualisiert:** 2026-04-27 04:38 UTC

**Workflows:** 19 | ✅ 19 OK | ⚠️ 1 Warnung | ❌ 0 Fehler

---
## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | Aktualität: Active Blacklist (Stufe 2) | active_blacklist_ipv4.txt ist 7h alt (WARN-Schwelle: 6h) |
| `Production Health` | Aktualität: Combined Blacklist (Stufe 1) | combined_threat_blacklist_ipv4.txt ist 7h alt (WARN-Schwelle: 6h) |

## 🏥 Production Health

**Status:** 🔴 0 CRITICAL | 🟡 2 WARN

| Level | Check | Detail |
|---|---|---|
| 🟡 WARN | Aktualität: Active Blacklist (Stufe 2) | active_blacklist_ipv4.txt ist 7h alt (WARN-Schwelle: 6h) |
| 🟡 WARN | Aktualität: Combined Blacklist (Stufe 1) | combined_threat_blacklist_ipv4.txt ist 7h alt (WARN-Schwelle: 6h) |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `asn_reputation_scorer.yml` | ✅ OK | 0 | 0 | `0 2 * * *` |
| `auto_feed_discovery.yml` | ✅ OK | 0 | 0 | `30 4 * * 0` |
| `community_ip_report.yml` | ✅ OK | 0 | 0 | – |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ✅ OK | 0 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | – |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `geo_tagger.yml` | ✅ OK | 0 | 0 | `45 7 * * 0` |
| `honeydb_monitor.yml` | ✅ OK | 0 | 0 | `15 22 * * *`, `15 4,10,16 * * *` |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `0 */6 * * *` |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *` |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `45 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `0 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `45 0 * * *`, `45 3 * * *`, `45 6 * * *`, `45 9 * * *`, `45 12 * * *`, `45 15 * * *`, `45 18 * * *`, `45 21 * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |

---
*Generiert: 2026-04-27 04:38 UTC | 19 Workflow-Dateien geprüft*