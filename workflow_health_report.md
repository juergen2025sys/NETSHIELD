# Workflow Health Checker – Report
**Aktualisiert:** 2026-05-17 09:13 UTC

**Workflows:** 21 | ✅ 21 OK | ⚠️ 0 Warnung | ❌ 1 Fehler

---
## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | active ⊆ conf40 Subset-Invariante verletzt | 5,884 IPs in active fehlen in conf40 (1.406% von active). Ursache vermutlich Cache-Drift zwischen combined- und confidence-Workflow (siehe BUG-CACHE-DRIFT). Der Heilungs-Pfad in update_confidence_blacklist.yml hat entweder nicht gegriffen (Cap >10%) oder wurde umgangen. |

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | Push-Limit Naehe | blacklist_geo_enriched.json: 82.6 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |

## 🏥 Production Health

**Status:** 🔴 1 CRITICAL | 🟡 1 WARN

| Level | Check | Detail |
|---|---|---|
| 🔴 CRITICAL | active ⊆ conf40 Subset-Invariante verletzt | 5,884 IPs in active fehlen in conf40 (1.406% von active). Ursache vermutlich Cache-Drift zwischen combined- und confidence-Workflow (siehe BUG-CACHE-DRIFT). Der Heilungs-Pfad in update_confidence_blacklist.yml hat entweder nicht gegriffen (Cap >10%) oder wurde umgangen. |
| 🟡 WARN | Push-Limit Naehe | blacklist_geo_enriched.json: 82.6 MB (>= 80 MB) – Push-Limit-Reserve schrumpft, Splitting-Strategie pruefen. |

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
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `0 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `45 0 * * *`, `45 3 * * *`, `45 6 * * *`, `45 9 * * *`, `45 12 * * *`, `45 15 * * *`, `45 18 * * *`, `45 21 * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |

---
*Generiert: 2026-05-17 09:13 UTC | 21 Workflow-Dateien geprüft*