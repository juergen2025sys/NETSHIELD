# Workflow Health Checker – Report
**Aktualisiert:** 2026-03-09 19:38 UTC

**Workflows:** 17 | ✅ 16 OK | ⚠️ 0 Warnung | ❌ 1 Fehler

---
## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `active_filter.yml` | ✅ OK | 0 | 0 | `15 0 * * *` |
| `asn_reputation_scorer.yml` | ✅ OK | 0 | 0 | `0 2 * * *` |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `duplicate_cleaner.yml` | ✅ OK | 0 | 0 | `30 4 * * *` |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * 0` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `firewall_format_exporter.yml` | ✅ OK | 0 | 0 | `30 0 * * *` |
| `geo_tagger.yml` | ✅ OK | 0 | 0 | `0 6 * * 0` |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `50 0 * * *` |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `tor_exit_monitor.yml` | ✅ OK | 0 | 0 | `30 23 * * *` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `0 3 * * 1`, `0 3 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `45 23 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `0 0 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `15 0 * * *` |
| `vpn_proxy_detector.yml` | ✅ OK | 0 | 0 | `30 3 * * 1` |
| `workflow_health_checker.yml` | ❌ FEHLER | 1 | 1 | `0 1 * * *` |

---
## ❌ Fehler im Detail

### `workflow_health_checker.yml`

- 🔴 Zeile 142: `str(...).get(...)` – str hat kein .get(), führt zu AttributeError. Korrekt: `(dict_expr).get(...)`


---
*Generiert: 2026-03-09 19:38 UTC | 17 Workflow-Dateien geprüft*