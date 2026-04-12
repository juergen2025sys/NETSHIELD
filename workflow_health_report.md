# Workflow Health Checker – Report
**Aktualisiert:** 2026-04-12 19:50 UTC

**Workflows:** 16 | ✅ 16 OK | ⚠️ 0 Warnung | ❌ 0 Fehler

---
## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | Geo-Coverage | Geo-Enrichment deckt nur 0% der Combined-Blacklist ab (6/4,388,519) – GeoIP-DB veraltet oder Geo-Tagger gescheitert |

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | Aktualität: Confidence-40 Blacklist | blacklist_confidence40_ipv4.txt ist 9h alt (WARN-Schwelle: 6h) |

## 🏥 Production Health

**Status:** 🔴 1 CRITICAL | 🟡 1 WARN

| Level | Check | Detail |
|---|---|---|
| 🔴 CRITICAL | Geo-Coverage | Geo-Enrichment deckt nur 0% der Combined-Blacklist ab (6/4,388,519) – GeoIP-DB veraltet oder Geo-Tagger gescheitert |
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
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `45 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `0 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `45 0 * * *`, `45 3 * * *`, `45 6 * * *`, `45 9 * * *`, `45 12 * * *`, `45 15 * * *`, `45 18 * * *`, `45 21 * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |

---
*Generiert: 2026-04-12 19:50 UTC | 16 Workflow-Dateien geprüft*