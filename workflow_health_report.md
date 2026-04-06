# Workflow Health Checker – Report
**Aktualisiert:** 2026-04-06 20:16 UTC

**Workflows:** 16 | ✅ 15 OK | ⚠️ 1 Warnung | ❌ 0 Fehler

---
## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `update_combined_blacklist.yml` | Fehlende Fehlerbehandlung | Block 2: json.load() ohne try/except – crash bei korrupter Datei |
| `Cross-Workflow` | Doppelte Feed-URLs | 8 URL(s) in mehreren Workflows – today_count Aufblaehung moeglich: ipblocklist.txt in cve_to_ip_mapper.yml+update_combined_blacklist.yml; ipblocklist_aggressive.txt in auto_feed_discovery.yml+cve_to_ip_mapper.yml+update_combined_blacklist.yml; abuseipdb-s100-30d.ipv4 in auto_feed_discovery.yml+update_combined_blacklist.yml; IPC2s.csv in cve_to_ip_mapper.yml+update_combined_blacklist.yml; all.txt in cve_to_ip_mapper.yml+update_combined_blacklist.yml |
| `auto_feed_discovery.yml ↔ community_ip_report.yml ↔ update_combined_blacklist.yml ↔ update_confidence_blacklist.yml` | PROTECTED_CIDRS Drift | PROTECTED_CIDRS nicht identisch: community_ip_report.yml weichen von auto_feed_discovery.yml ab |

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
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `45 22 * * *` |
| `update_combined_blacklist.yml` | ⚠️ | 0 | 1 | `0 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `45 0 * * *`, `45 3 * * *`, `45 6 * * *`, `45 9 * * *`, `45 12 * * *`, `45 15 * * *`, `45 18 * * *`, `45 21 * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |

---
*Generiert: 2026-04-06 20:16 UTC | 16 Workflow-Dateien geprüft*