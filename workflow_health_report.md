# Workflow Health Checker – Report
**Aktualisiert:** 2026-04-26 08:37 UTC

**Workflows:** 19 | ✅ 19 OK | ⚠️ 0 Warnung | ❌ 1 Fehler

---
## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | Whitelist-Leak: combined_threat_blacklist_ipv4.txt | combined_threat_blacklist_ipv4.txt enthält whitelisted IPs: 52.123.128.14, 142.250.154.94, 142.250.154.95, 142.251.14.95, 142.251.20.95… – Filterung wirkungslos! |
| `Production Health` | Whitelist-Leak: active_blacklist_ipv4.txt | active_blacklist_ipv4.txt enthält whitelisted IPs: 142.250.154.94, 142.251.14.95, 142.251.20.95, 142.251.110.94, 142.251.127.84… – Filterung wirkungslos! |
| `Production Health` | Whitelist-Leak: blacklist_confidence40_ipv4.txt | blacklist_confidence40_ipv4.txt enthält whitelisted IPs: 142.250.154.94, 142.251.110.94, 142.251.127.84, 142.251.14.95, 142.251.151.119… – Filterung wirkungslos! |

## 🏥 Production Health

**Status:** 🔴 3 CRITICAL | 🟡 0 WARN

| Level | Check | Detail |
|---|---|---|
| 🔴 CRITICAL | Whitelist-Leak: combined_threat_blacklist_ipv4.txt | combined_threat_blacklist_ipv4.txt enthält whitelisted IPs: 52.123.128.14, 142.250.154.94, 142.250.154.95, 142.251.14.95, 142.251.20.95… – Filterung wirkungslos! |
| 🔴 CRITICAL | Whitelist-Leak: active_blacklist_ipv4.txt | active_blacklist_ipv4.txt enthält whitelisted IPs: 142.250.154.94, 142.251.14.95, 142.251.20.95, 142.251.110.94, 142.251.127.84… – Filterung wirkungslos! |
| 🔴 CRITICAL | Whitelist-Leak: blacklist_confidence40_ipv4.txt | blacklist_confidence40_ipv4.txt enthält whitelisted IPs: 142.250.154.94, 142.251.110.94, 142.251.127.84, 142.251.14.95, 142.251.151.119… – Filterung wirkungslos! |

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
*Generiert: 2026-04-26 08:37 UTC | 19 Workflow-Dateien geprüft*