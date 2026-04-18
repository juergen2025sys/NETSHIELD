# Workflow Health Checker – Report
**Aktualisiert:** 2026-04-18 04:04 UTC

**Workflows:** 19 | ✅ 12 OK | ⚠️ 0 Warnung | ❌ 7 Fehler

---
## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `asn_reputation_scorer.yml` | Report nach Guard-Exit | Block 0 L~319: sys.exit(1) vor Report/Status-Write (asn_reputation_db.json, asn_reputation_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |
| `auto_feed_discovery.yml` | Dict-Mutation in Schleife | Block 0: 'del' in for-Schleife ohne list()-Kopie (_WHITELIST_ENTRIES) – RuntimeError bei Dict-Größenänderung |
| `auto_feed_discovery.yml` | Report nach Guard-Exit | Block 0 L~256: sys.exit(1) vor Report/Status-Write (auto_discovered_feeds.json, auto_feed_discovery_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |
| `cve_to_ip_mapper.yml` | Report nach Guard-Exit | Block 0 L~207: sys.exit(1) vor Report/Status-Write (cve_exploit_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |
| `dependabot-auto-merge.yml` | persist-credentials fehlt | git push verwendet aber checkout ohne persist-credentials: true – Push wird fehlschlagen |
| `geo_tagger.yml` | Report nach Guard-Exit | Block 0 L~248: sys.exit(1) vor Report/Status-Write (blacklist_geo_enriched.json, geo_tagger_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |
| `honeydb_monitor.yml` | Report nach Guard-Exit | Block 0 L~300: sys.exit(1) vor Report/Status-Write (honeydb_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |
| `honeypot_monitor.yml` | Report nach Guard-Exit | Block 0 L~183: sys.exit(1) vor Report/Status-Write (honeypot_report.md) – stale Report moeglich trotz Commit-Step mit if: always() |
| `update_combined_blacklist.yml ↔ update_confidence_blacklist.yml` | Score-Modell Divergenz | Unterschiedliche Schwellen in: score_a, score_c, score_d – active_blacklist und confidence40 bewerten IPs unterschiedlich |

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | Feed-Ausfälle | 2 von 99 Feeds ausgefallen: abuseipdb_tmiland, c2_tracker |

## 🏥 Production Health

**Status:** 🔴 0 CRITICAL | 🟡 1 WARN

| Level | Check | Detail |
|---|---|---|
| 🟡 WARN | Feed-Ausfälle | 2 von 99 Feeds ausgefallen: abuseipdb_tmiland, c2_tracker |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `asn_reputation_scorer.yml` | ❌ | 1 | 0 | `0 2 * * *` |
| `auto_feed_discovery.yml` | ❌ | 2 | 0 | `30 4 * * 0` |
| `community_ip_report.yml` | ✅ OK | 0 | 0 | – |
| `cve_to_ip_mapper.yml` | ❌ | 1 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ❌ | 1 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | – |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `geo_tagger.yml` | ❌ | 1 | 0 | `45 7 * * 0` |
| `honeydb_monitor.yml` | ❌ | 1 | 0 | `15 22 * * *` |
| `honeypot_monitor.yml` | ❌ | 1 | 0 | `0 23 * * *` |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *` |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `45 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `0 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `45 0 * * *`, `45 3 * * *`, `45 6 * * *`, `45 9 * * *`, `45 12 * * *`, `45 15 * * *`, `45 18 * * *`, `45 21 * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |

---
*Generiert: 2026-04-18 04:04 UTC | 19 Workflow-Dateien geprüft*