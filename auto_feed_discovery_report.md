# Auto Feed Discovery – Report
**Aktualisiert:** 2026-05-24 15:56 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **3050** |
| davon GitHub (Topics+Code) | **3013** |
| davon GitLab | **37** |
| davon Awesome-Lists | **1036** |
| Tools/Libraries vor Eval gefiltert | **372** |
| davon Hard-Reject (awesome-Liste etc.) | **68** |
| EVAL-Kandidaten (nach Stratifizierung) | **200** |
| davon bereits rejected (übersprungen) | **181** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluiert | **27** |
| Neu angenommen | **7** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bekannte Feeds re-fetched | **1** |
| Abgelehnt (dieser Run) | **19** |
| davon GitLab abgelehnt | **1** |
| Feeds gesamt (aktiv) | **30** |
| IPs in seen_db bestätigt | **717422** |
| Neue IPs eingetragen | **0** |
| seen_db gesamt | **4,752,552** |
| HQ-Referenz-IPs (6 Quellen) | **135075** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **17** |
| IP-Datei veraltet (>30d) | **1** |
| Repo zu alt (>30d) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `cbuijs_accomplist_plain_black_ipcidr` | [cbuijs/accomplist](https://github.com/cbuijs/accomplist) | GITHUB | 134,746 | 0.6% | 1.5% | 20 | 🆕 NEU |
| `cbuijs_accomplist_plain_black_ip4cidr` | [cbuijs/accomplist](https://github.com/cbuijs/accomplist) | GITHUB | 134,746 | 0.6% | 1.5% | 20 | 🆕 NEU |
| `turbolabit_zzfirewall_blacklist` | [TurboLabIt/zzfirewall](https://github.com/TurboLabIt/zzfirewall) | GITHUB | 85 | 66.4% | 0.0% | 0 | 🔄 Update |
| `wintergate_ic_wic_resources_permanent_blacklist_v3` | [WinterGate-IC/wic-resources](https://github.com/WinterGate-IC/wic-resources) | GITHUB | 508 | 67.0% | 0.0% | 0 | 🆕 NEU |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist_v2` | [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) | GITHUB | 10,633 | 75.0% | 0.0% | 4721 | 🆕 NEU |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist_v3` | [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) | GITHUB | 10,633 | 75.0% | 0.0% | 4721 | 🆕 NEU |
| `kamalmjt_emerging_attackers_badips_txt` | [kamalmjt/emerging-attackers](https://github.com/kamalmjt/emerging-attackers) | GITHUB | 172,704 | 18.9% | 0.0% | 1 | 🆕 NEU |
| `ziyadnz_threat_intel_ip_feeds_ipv4_blacklist` | [ziyadnz/threat-intel-ip-feeds](https://github.com/ziyadnz/threat-intel-ip-feeds) | GITHUB | 105,024 | 36.7% | 0.0% | 8 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `kevoreilly/CAPEv2` | GITHUB | Keine IP-Datei |
| `foospidy/HoneyPy` | GITHUB | Keine IP-Datei |
| `InQuest/omnibus` | GITHUB | Keine IP-Datei |
| `S03D4-164/Hiryu` | GITHUB | Keine IP-Datei |
| `jheise/threatcrowd_api` | GITHUB | Keine IP-Datei |
| `mandiant/ioc_writer` | GITHUB | Keine IP-Datei |
| `brianwarehime/threatnote` | GITHUB | Keine IP-Datei |
| `armbues/ioc_parser` | GITHUB | Keine IP-Datei |
| `exp0se/bro-intel-generator` | GITHUB | IP-Datei 3821d alt |
| `Netflix/Scumblr` | GITHUB | Keine IP-Datei |
| `EclecticIQ/cabby` | GITHUB | Keine IP-Datei |
| `gitlab:devswanson-create-crypto-token/create-honeypot-token` | GITLAB | Zu alt: 601d |
| `OneUptime/oneuptime` | GITHUB | Keine IP-Datei |
| `koala73/worldmonitor` | GITHUB | Keine IP-Datei |
| `Ian-Lusule/Proxies` | GITHUB | Keine IP-Datei |
| `notfaj/ester` | GITHUB | Keine IP-Datei |
| `ebogdum/terraform-provider-routeros` | GITHUB | Keine IP-Datei |
| `vqmpjayZ/Vadrifts` | GITHUB | Keine IP-Datei |
| `officialputuid/ProxyForEveryone` | GITHUB | Keine IP-Datei |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | GITHUB | 10,633 | 75.0% | 4721 | 2026-05-24 |
| `cbuijs_accomplist` | GITHUB | 96,584 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 134,746 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,503 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 105,024 | 36.7% | 8 | 2026-05-24 |
| `turntuptechnologies_iocs` | GITHUB | 155 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 36,171 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 94,521 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,126 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 93 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 220,433 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 7,789 | 69.0% | 4 | 2026-05-24 |
| `fadouse_clash_threat_intel` | GITHUB | 5,035 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 5,175 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 172,704 | 18.9% | 1 | 2026-05-24 |
| `idleadmin_threatfeed` | GITHUB | 52,726 | 41.9% | 0 | 2026-04-09 |
| `turbolabit_zzfirewall` | GITHUB | 99,303 | 66.4% | 0 | 2026-05-03 |
| `kraloveckey_ipsets_blocklist` | GITHUB | 16,854 | 13.1% | 0 | 2026-05-10 |
| `wintergate_ic_wic_resources_permanent_blacklist` | GITHUB | 508 | 67.0% | 0 | 2026-05-24 |
| `wintergate_ic_wic_resources_permanent_blacklist_v2` | GITHUB | 503 | 67.0% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 38,933 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_iblocklist_ciarmy_malicious` | GITHUB | 11,950 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_et_tor` | GITHUB | 7,560 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,472 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_blocklist_de_ssh` | GITHUB | 5,773 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_blocklist_de_bruteforce` | GITHUB | 2,522 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_snort_ip_blocklist` | GITHUB | 1,386 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_alienvault_reputation` | GITHUB | 609 | 13.1% | 0 | 2026-05-24 |
| `turbolabit_zzfirewall_blacklist` | GITHUB | 85 | 66.4% | 0 | 2026-05-24 |

---
*Generiert: 2026-05-24 15:56 UTC*