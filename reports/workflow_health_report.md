# Workflow Health Checker – Report
**Aktualisiert:** 2026-11-17 10:10 CET (Europe/Berlin)

**Workflows:** 35 | ✅ 32 OK | ⚠️ 5 Warnung | ❌ 0 Fehler

---
## Regressionstests

⚠️ Commit: `0b939512b7eea7caafe5fc69bd2ab8d490b455ce`

490 Tests; 7 Fehlschlaege, 0 Ausfuehrungsfehler, 0 uebersprungen, 0 unerwartete Testerfolge, 0 fehlende Pflichtpruefungen, 0 Pflichtpruefungen nicht bestanden. Betroffen: test_release_audit_fixes.AuditFixTests.test_honey_http_402_credential_is_quarantined_for_rest_of_run, test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure=429), test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure=503), test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure='timeout'), test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure='json'), test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure='schema'), test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure='schema-items')

Diese Pruefung meldet nur Warnungen. Sie prueft bekannte Fehlerfaelle; sie garantiert keine vollstaendige Fehlerfreiheit.

## ⚠️ Warnungen

| Datei | Check | Detail |
|---|---|---|
| `Regressionstests` | Bekannte Logikfehler / Testsuite | 490 Tests; 7 Fehlschlaege, 0 Ausfuehrungsfehler, 0 uebersprungen, 0 unerwartete Testerfolge, 0 fehlende Pflichtpruefungen, 0 Pflichtpruefungen nicht bestanden. Betroffen: test_release_audit_fixes.AuditFixTests.test_honey_http_402_credential_is_quarantined_for_rest_of_run, test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure=429), test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure=503), test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure='timeout'), test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure='json'), test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure='schema'), test_release_audit_fixes.AuditFixTests.test_honey_partial_failures_preserve_list_and_freshness (endpoint='/bad-hosts/SSH', failure='schema-items') |
| `asn_drop.yml + dns_blocklist_finder.yml` | Cron-Kollision | '15 4 * * *' – beide Workflows laufen gleichzeitig |
| `dns_list_mirror.yml` | continue-on-error aktiv | continue-on-error=true gesetzt – Fehler können still bleiben; Review ob das wirklich beabsichtigt ist |
| `honeypot_monitor.yml` | Doppelter Import | Block 0: Doppelte Imports: re(2x), json(2x) – moeglicherweise Copy-Paste-Artefakt |
| `netshield_report_generator.yml` | continue-on-error aktiv | continue-on-error=true gesetzt – Fehler können still bleiben; Review ob das wirklich beabsichtigt ist |

## 🏥 Production Health

**Status:** 🔴 0 CRITICAL | 🟡 0 WARN

*Alle Production Health Checks bestanden.*

## Übersicht

| Workflow | Status | Fehler | Warnungen | Cron |
|---|---|---|---|---|
| `asn_drop.yml` | ✅ OK | 0 | 0 | `15 4 * * *`, `15 6 * * *` |
| `auto_feed_discovery.yml` | ✅ OK | 0 | 0 | `37 4 * * 0`, `23 7 * * 0`, `47 11 * * 0` |
| `auto_feed_refresh.yml` | ✅ OK | 0 | 0 | `15 2 * * *` |
| `codeql.yml` | ✅ OK | 0 | 0 | `0 3 * * 0` |
| `cve_to_ip_mapper.yml` | ✅ OK | 0 | 0 | `0 4 * * *` |
| `dependabot-auto-merge.yml` | ✅ OK | 0 | 0 | – |
| `dependabot-heal-conflicts.yml` | ✅ OK | 0 | 0 | `17 4 * * *` |
| `dns_blocklist_finder.yml` | ✅ OK | 0 | 0 | `15 4 * * *` |
| `dns_list_mirror.yml` | ⚠️ | 0 | 1 | `35 * * * *` |
| `false_positive_checker.yml` | ✅ OK | 0 | 0 | `0 5 * * *`, `0 13 * * *`, `0 20 * * *` |
| `feed_health_monitor.yml` | ✅ OK | 0 | 0 | `0 1 * * *` |
| `feed_ip_finder.yml` | ✅ OK | 0 | 0 | – |
| `feed_overlap_report.yml` | ✅ OK | 0 | 0 | `25 3 * * 0` |
| `force_cancel_stuck_runs.yml` | ✅ OK | 0 | 0 | – |
| `history_fresh_start.yml` | ✅ OK | 0 | 0 | `20 5 1 * *` |
| `honeypot_monitor.yml` | ⚠️ | 0 | 1 | `0 5,11,17,23 * * *` |
| `honigtopf.yml` | ✅ OK | 0 | 0 | `17 */2 * * *` |
| `ip_ablauf.yml` | ✅ OK | 0 | 0 | `30 6 * * 1`, `55 */3 * * *` |
| `ledger_diagnose.yml` | ✅ OK | 0 | 0 | – |
| `netshield_report_generator.yml` | ⚠️ | 0 | 1 | `30 * * * *`, `45 * * * *`, `55 * * * *` |
| `open_proxies.yml` | ✅ OK | 0 | 0 | `35 */2 * * *` |
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
*Generiert: 2026-11-17 10:10 CET (Europe/Berlin) | 35 Workflow-Dateien geprüft*