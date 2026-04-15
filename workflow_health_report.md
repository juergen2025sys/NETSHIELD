# Workflow Health Checker – Report
**Aktualisiert:** 2026-04-15 14:49 UTC

**Workflows:** 17 | ✅ 16 OK | ⚠️ 1 Warnung | ❌ 0 Fehler

---
## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | Whitelist-Leak: combined_threat_blacklist_ipv4.txt | combined_threat_blacklist_ipv4.txt enthält whitelisted IPs: 1.0.0.1, 1.1.1.1, 3.120.0.132, 3.121.0.15, 3.121.0.226… – Filterung wirkungslos! |
| `Production Health` | Whitelist-Leak: active_blacklist_ipv4.txt | active_blacklist_ipv4.txt enthält whitelisted IPs: 1.0.0.1, 3.120.0.132, 3.121.0.15, 3.121.0.226, 3.126.198.87… – Filterung wirkungslos! |

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `run_tests.yml` | Node24 env fehlt | FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 env-Variable fehlt – Node.js Kompatibilitaetsproblem moeglich |
| `Production Health` | Aktualität: Confidence-40 Blacklist | blacklist_confidence40_ipv4.txt ist 9h alt (WARN-Schwelle: 6h) |

## 🏥 Production Health

**Status:** 🔴 2 CRITICAL | 🟡 1 WARN

| Level | Check | Detail |
|---|---|---|
| 🔴 CRITICAL | Whitelist-Leak: combined_threat_blacklist_ipv4.txt | combined_threat_blacklist_ipv4.txt enthält whitelisted IPs: 1.0.0.1, 1.1.1.1, 3.120.0.132, 3.121.0.15, 3.121.0.226… – Filterung wirkungslos! |
| 🔴 CRITICAL | Whitelist-Leak: active_blacklist_ipv4.txt | active_blacklist_ipv4.txt enthält whitelisted IPs: 1.0.0.1, 3.120.0.132, 3.121.0.15, 3.121.0.226, 3.126.198.87… – Filterung wirkungslos! |
| 🟡 WARN | Aktualität: Confidence-40 Blacklist | blacklist_confidence40_ipv4.txt ist 9h alt (WARN-Schwelle: 6h) |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `asn_reputation_scorer.yml` | ✅ OK | 0 | 0 | `0 2 * * *` |
| `auto_feed_discovery.yml` | ✅ OK | 0 | 0 | `30 4 * * 0` |
| `community_ip_report.yml` | ✅ OK | 0 | 0 | – |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `geo_tagger.yml` | ✅ OK | 0 | 0 | `45 7 * * 0` |
| `honeydb_monitor.yml` | ✅ OK | 0 | 0 | `15 22 * * *` |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `0 23 * * *` |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *` |
| `run_tests.yml` | ⚠️ | 0 | 1 | – |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `45 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `0 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `45 0 * * *`, `45 3 * * *`, `45 6 * * *`, `45 9 * * *`, `45 12 * * *`, `45 15 * * *`, `45 18 * * *`, `45 21 * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |

---
*Generiert: 2026-04-15 14:49 UTC | 17 Workflow-Dateien geprüft*