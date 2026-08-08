# Workflow Health Checker – Report
**Aktualisiert:** 2026-08-08 02:59 UTC

**Workflows:** 24 | ✅ 20 OK | ⚠️ 3 Warnung | ❌ 3 Fehler

---
## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `feed_overlap_report.yml` | persist-credentials fehlt | git push verwendet aber checkout ohne persist-credentials: true – Push wird fehlschlagen |
| `update_combined_blacklist.yml` | HIGH_QUALITY ↔ SOURCES Drift | hq=True in SOURCES aber nicht in HIGH_QUALITY: abuseipdb_tmiland, threatslist_paloalto_edl – IPs altern still aus (Bug-DP1) |
| `Production Health` | Drift: honeypot_ips.txt | honeypot_ips.txt: 123,737 → 1,138,324 (+820%) – extremes Wachstum, vermutlich Parser-/Dedup-Bug |
| `Production Health` | Push-Limit Naehe | combined_threat_blacklist_ipv4.txt: 118.5 MB (>= 95 MB) – naechster git push kann am 100 MB Limit scheitern. Splitting/Truncate-Logik fehlt oder Schwelle anpassen. |

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `auto_feed_discovery.yml` | timeout-minutes fehlt | Job 'discover' hat kein timeout-minutes – haengende Runs verbrauchen bis zu 360min |
| `feed_overlap_report.yml` | Node24 env fehlt | FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 env-Variable fehlt – Node.js Kompatibilitaetsproblem moeglich |
| `history_fresh_start.yml` | Node24 env fehlt | FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 env-Variable fehlt – Node.js Kompatibilitaetsproblem moeglich |
| `update_combined_blacklist.yml` | Untrusted Feed hq=True | 2 Feed(s) mit hq=True ohne bekannten Betreiber – IPs bleiben dauerhaft in active_blacklist ohne Score-Altern: "threatslist_paloalto_edl" (https://threatslist.github.io/Palo-Alto-EDL/edl_list.txt); "threat_live" (https://list.threat.live/) |
| `Cross-Workflow` | Doppelte Feed-URLs | 1 URL(s) in mehreren Workflows – today_count Aufblaehung moeglich: greylist-latest.csv in honeypot_monitor.yml+update_combined_blacklist.yml |
| `Production Health` | Aktualität: Confidence-40 Blacklist | blacklist_confidence40_ipv4.txt nicht vorhanden |
| `Production Health` | Drift: active_blacklist_ipv4.txt | active_blacklist_ipv4.txt: 441,542 → 715,657 (+62%) – ungewöhnliches Wachstum |

## 🏥 Production Health

**Status:** 🔴 2 CRITICAL | 🟡 2 WARN

| Level | Check | Detail |
|---|---|---|
| 🔴 CRITICAL | Drift: honeypot_ips.txt | honeypot_ips.txt: 123,737 → 1,138,324 (+820%) – extremes Wachstum, vermutlich Parser-/Dedup-Bug |
| 🔴 CRITICAL | Push-Limit Naehe | combined_threat_blacklist_ipv4.txt: 118.5 MB (>= 95 MB) – naechster git push kann am 100 MB Limit scheitern. Splitting/Truncate-Logik fehlt oder Schwelle anpassen. |
| 🟡 WARN | Aktualität: Confidence-40 Blacklist | blacklist_confidence40_ipv4.txt nicht vorhanden |
| 🟡 WARN | Drift: active_blacklist_ipv4.txt | active_blacklist_ipv4.txt: 441,542 → 715,657 (+62%) – ungewöhnliches Wachstum |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `auto_feed_discovery.yml` | ⚠️ | 0 | 1 | `37 4 * * 0`, `23 7 * * 0`, `47 11 * * 0` |
| `codeql.yml` | ✅ OK | 0 | 0 | `0 3 * * 0` |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ✅ OK | 0 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | – |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `feed_ip_finder.yml` | ✅ OK | 0 | 0 | – |
| `feed_overlap_report.yml` | ❌ | 1 | 1 | `25 3 * * 0` |
| `history_fresh_start.yml` | ⚠️ | 0 | 1 | – |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `0 5,11,17,23 * * *` |
| `honigtopf.yml` | ✅ OK | 0 | 0 | `15 22 * * *` |
| `netshield_report_generator.yml` | ✅ OK | 0 | 0 | `30 * * * *` |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `tweetfeed_monitor.yml` | ✅ OK | 0 | 0 | `45 2 * * *` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `45 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `7 */3 * * *`, `27 */3 * * *`, `47 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `47 1,4,7,10,13,16,19,22 * * *` |
| `watchdog_combined.yml` | ✅ OK | 0 | 0 | `*/15 * * * *` |
| `watchdog_honigtopf.yml` | ✅ OK | 0 | 0 | `7,22,37,52 * * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |
| `workflow_health_report.yml` | ✅ OK | 0 | 0 | `5 */6 * * *` |

---
*Generiert: 2026-08-08 02:59 UTC | 24 Workflow-Dateien geprüft*