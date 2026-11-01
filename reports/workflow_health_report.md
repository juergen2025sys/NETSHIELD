# Workflow Health Checker – Report
**Aktualisiert:** 2026-11-01 15:16 CET (Europe/Berlin)

**Workflows:** 33 | ✅ 30 OK | ⚠️ 3 Warnung | ❌ 1 Fehler

---
## Regressionstests

✅ Commit: `01dba656617f14df4fa6aa99c3b82d2461cc8983`

490 Tests; 0 Fehlschlaege, 0 Ausfuehrungsfehler, 0 uebersprungen, 0 unerwartete Testerfolge, 0 fehlende Pflichtpruefungen, 0 Pflichtpruefungen nicht bestanden.

Diese Pruefung meldet nur Warnungen. Sie prueft bekannte Fehlerfaelle; sie garantiert keine vollstaendige Fehlerfreiheit.

## ❌ Fehler (kritisch)

| Datei | Check | Detail |
|---|---|---|
| `Production Health` | Whitelist-Leak: combined_threat_blacklist_ipv4.txt | combined_threat_blacklist_ipv4.txt enthält whitelisted IPs: 84.17.59.115, 103.10.125.40, 103.28.54.189, 155.133.226.68, 155.133.226.87… – Filterung wirkungslos! |
| `Production Health` | Whitelist-Leak: active_blacklist_ipv4.txt | active_blacklist_ipv4.txt enthält whitelisted IPs: 84.17.59.115, 155.133.226.87, 162.254.196.66 – Filterung wirkungslos! |

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `auto_feed_discovery.yml` | Doppelter Import | Block 0: Doppelte Imports: ((2x) – moeglicherweise Copy-Paste-Artefakt |
| `dns_blocklist_finder.yml` | Kein expliziter Leerungsschutz | Externer Feed/Report ohne explizite MIN_* Guard-Variable – Müll-/Leer-Daten könnten unbemerkt akzeptiert werden |
| `dns_blocklist_finder.yml` | Node24 env fehlt | FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 env-Variable fehlt – Node.js Kompatibilitaetsproblem moeglich |
| `netshield_report_generator.yml` | Doppelter Import | Block 0: Doppelte Imports: ((2x) – moeglicherweise Copy-Paste-Artefakt |
| `Production Health` | Feed-Ausfälle | 2 von 98 Feeds ausgefallen: greensnow, urlhaus_ips |
| `Production Health` | active ⊆ conf40 Subset-Invariante (Mini-Drift) | 3 IPs in active fehlen in conf40 (unterhalb CRITICAL-Schwelle). Wahrscheinlich kleiner Cache-Drift im Toleranz-bereich oder Score-Bucket-Wechsel am Tageswechsel. |

## 🏥 Production Health

**Status:** 🔴 2 CRITICAL | 🟡 2 WARN

| Level | Check | Detail |
|---|---|---|
| 🔴 CRITICAL | Whitelist-Leak: combined_threat_blacklist_ipv4.txt | combined_threat_blacklist_ipv4.txt enthält whitelisted IPs: 84.17.59.115, 103.10.125.40, 103.28.54.189, 155.133.226.68, 155.133.226.87… – Filterung wirkungslos! |
| 🔴 CRITICAL | Whitelist-Leak: active_blacklist_ipv4.txt | active_blacklist_ipv4.txt enthält whitelisted IPs: 84.17.59.115, 155.133.226.87, 162.254.196.66 – Filterung wirkungslos! |
| 🟡 WARN | Feed-Ausfälle | 2 von 98 Feeds ausgefallen: greensnow, urlhaus_ips |
| 🟡 WARN | active ⊆ conf40 Subset-Invariante (Mini-Drift) | 3 IPs in active fehlen in conf40 (unterhalb CRITICAL-Schwelle). Wahrscheinlich kleiner Cache-Drift im Toleranz-bereich oder Score-Bucket-Wechsel am Tageswechsel. |

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `auto_feed_discovery.yml` | ⚠️ | 0 | 1 | `37 4 * * 0`, `23 7 * * 0`, `47 11 * * 0` |
| `auto_feed_refresh.yml` | ✅ OK | 0 | 0 | `15 2 * * *` |
| `codeql.yml` | ✅ OK | 0 | 0 | `0 3 * * 0` |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ✅ OK | 0 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | – |
| `dns_blocklist_finder.yml` | ⚠️ | 0 | 2 | – |
| `dns_list_mirror.yml` | ✅ OK | 0 | 0 | `35 1,7,13,19 * * *` |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `feed_ip_finder.yml` | ✅ OK | 0 | 0 | – |
| `feed_overlap_report.yml` | ✅ OK | 0 | 0 | `25 3 * * 0` |
| `force_cancel_stuck_runs.yml` | ✅ OK | 0 | 0 | – |
| `history_fresh_start.yml` | ✅ OK | 0 | 0 | `20 5 1 * *` |
| `honeypot_monitor.yml` | ✅ OK | 0 | 0 | `0 5,11,17,23 * * *` |
| `honigtopf.yml` | ✅ OK | 0 | 0 | `*/20 * * * *`, `5,25,45 * * * *`, `10,30,50 * * * *` |
| `ip_ablauf.yml` | ✅ OK | 0 | 0 | `30 6 * * 1`, `55 */3 * * *` |
| `ledger_diagnose.yml` | ✅ OK | 0 | 0 | – |
| `netshield_report_generator.yml` | ⚠️ | 0 | 1 | `30 * * * *`, `45 * * * *`, `55 * * * *` |
| `repo_size_check.yml` | ✅ OK | 0 | 0 | – |
| `run_tests.yml` | ✅ OK | 0 | 0 | – |
| `runner_image_watch.yml` | ✅ OK | 0 | 0 | `0 2 * * 0` |
| `score_decay_monitor.yml` | ✅ OK | 0 | 0 | `0 7 * * 0` |
| `sniffcat_fetch.yml` | ✅ OK | 0 | 0 | – |
| `tweetfeed_monitor.yml` | ✅ OK | 0 | 0 | `45 2 * * *` |
| `update-blocklist.yml` | ✅ OK | 0 | 0 | `30 1 * * 1`, `30 1 * * 3` |
| `update_bot_detector.yml` | ✅ OK | 0 | 0 | `35 22 * * *` |
| `update_combined_blacklist.yml` | ✅ OK | 0 | 0 | `7 */3 * * *`, `27 */3 * * *`, `47 */3 * * *` |
| `update_confidence_blacklist.yml` | ✅ OK | 0 | 0 | `47 1,4,7,10,13,16,19,22 * * *` |
| `watchdog_combined.yml` | ✅ OK | 0 | 0 | `*/15 * * * *` |
| `watchdog_ip_ablauf.yml` | ✅ OK | 0 | 0 | `*/30 * * * *` |
| `workflow_health_checker.yml` | ✅ OK | 0 | 0 | – |
| `workflow_health_dashboard.yml` | ✅ OK | 0 | 0 | `5 */6 * * *` |

---
*Generiert: 2026-11-01 15:16 CET (Europe/Berlin) | 33 Workflow-Dateien geprüft*