# Auto Feed Discovery – Report
**Aktualisiert:** 2026-05-24 15:26 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **3103** |
| davon GitHub (Topics+Code) | **3066** |
| davon GitLab | **37** |
| davon Awesome-Lists | **1037** |
| Tools/Libraries vor Eval gefiltert | **274** |
| EVAL-Kandidaten (nach Stratifizierung) | **200** |
| davon bereits rejected (übersprungen) | **172** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluiert | **36** |
| Neu angenommen | **7** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bekannte Feeds re-fetched | **1** |
| Abgelehnt (dieser Run) | **28** |
| davon GitLab abgelehnt | **2** |
| Feeds gesamt (aktiv) | **30** |
| IPs in seen_db bestätigt | **717019** |
| Neue IPs eingetragen | **403** |
| seen_db gesamt | **4,752,552** |
| HQ-Referenz-IPs (6 Quellen) | **134930** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **23** |
| IP-Datei veraltet (>30d) | **3** |
| Repo zu alt (>30d) | **2** |

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
| `dreddsa5dies/goHackTools` | GITHUB | Keine IP-Datei |
| `0x4d31/sqhunter` | GITHUB | Keine IP-Datei |
| `InQuest/python-iocextract` | GITHUB | Keine IP-Datei |
| `SupportIntelligence/Icewater` | GITHUB | Keine IP-Datei |
| `tripwire/tardis` | GITHUB | Keine IP-Datei |
| `HurricaneLabs/machinae` | GITHUB | Keine IP-Datei |
| `KasperskyLab/klara` | GITHUB | Keine IP-Datei |
| `STIXProject/stix-viz` | GITHUB | Keine IP-Datei |
| `yahoo/PyIOCe` | GITHUB | Keine IP-Datei |
| `PaloAltoNetworks/minemeld` | GITHUB | Keine IP-Datei |
| `CERT-Polska/n6` | GITHUB | IP-Datei 250d alt |
| `Ptr32Void/OSTrICa` | GITHUB | Keine IP-Datei |
| `stratosphereips/Manati` | GITHUB | Keine IP-Datei |
| `mlsecproject/tiq-test` | GITHUB | Keine IP-Datei |
| `davidonzo/Threat-Intel` | GITHUB | IP-Datei 587d alt |
| `CrowdStrike/CrowdFMS` | GITHUB | Keine IP-Datei |
| `gitlab:devswanson-create-crypto-token/how-to-create-crypto-token` | GITLAB | Zu alt: 601d |
| `gitlab:devswanson-create-crypto-token/smart-contract-honeypot` | GITLAB | Zu alt: 601d |
| `TurboLabIt/webstackup` | GITHUB | IP-Datei 1330d alt |
| `NullSecHQ/nullsec-framework` | GITHUB | Keine IP-Datei |
| `iamutaki/dompeng-web` | GITHUB | Keine IP-Datei |
| `froggychips/sre-ai-copilot` | GITHUB | Keine IP-Datei |
| `karimhabush/cyberowl` | GITHUB | Keine IP-Datei |
| `soapbucket/sbproxy` | GITHUB | Keine IP-Datei |
| `maxtattonbrown/sundial` | GITHUB | Keine IP-Datei |
| `Bes-js/public-proxy-list` | GITHUB | Keine IP-Datei |
| `ErcinDedeoglu/proxies` | GITHUB | Keine IP-Datei |
| `mtheuma/epson2paperless` | GITHUB | Keine IP-Datei |

---
## 🦊 Codeberg-Kandidaten (manuelle Kuration)

Diese Repos wurden auf Codeberg per Keyword-Suche gefunden. Codeberg-Integration in die Eval-Pipeline ist noch nicht umgesetzt - die Liste dient als Hinweis fuer manuelles Review.

| Repo | Stars | Updated | Found via |
|---|---|---|---|
| [CloudyyUw/adblock-to-pihole-blocklist](https://codeberg.org/CloudyyUw/adblock-to-pihole-blocklist) | 0 | 2024-12-03 | `blocklist` |
| [ScryptKidd0/adguard-blocklist](https://codeberg.org/ScryptKidd0/adguard-blocklist) | 0 | 2026-01-25 | `blocklist` |
| [celenity/adguard-dns-settings](https://codeberg.org/celenity/adguard-dns-settings) | 5 | 2025-09-01 | `blocklist` |
| [celenity/adguard-home-settings](https://codeberg.org/celenity/adguard-home-settings) | 9 | 2024-12-17 | `blocklist` |
| [josh/AdGuard.blocklists](https://codeberg.org/josh/AdGuard.blocklists) | 0 | 2024-10-05 | `blocklist` |
| [HalfofBilly/AI-Blocklist-for-SearXNG](https://codeberg.org/HalfofBilly/AI-Blocklist-for-SearXNG) | 2 | 2024-12-19 | `blocklist` |
| [fausty/AIBlocklist](https://codeberg.org/fausty/AIBlocklist) | 2 | 2024-12-03 | `blocklist` |
| [111934321/anti-murdoch-blocklist](https://codeberg.org/111934321/anti-murdoch-blocklist) | 1 | 2024-12-03 | `blocklist` |
| [polarhive/arceo](https://codeberg.org/polarhive/arceo) | 1 | 2025-05-29 | `blocklist` |
| [Lanre/Artemis](https://codeberg.org/Lanre/Artemis) | 0 | 2026-05-21 | `blocklist` |
| [syedsharjeel/automated-ip-blocklist-dns-filtering](https://codeberg.org/syedsharjeel/automated-ip-blocklist-dns-filtering) | 0 | 2025-05-01 | `blocklist` |
| [badandugly/badandugly](https://codeberg.org/badandugly/badandugly) | 6 | 2025-08-03 | `blocklist` |
| [celenity/BadBlock](https://codeberg.org/celenity/BadBlock) | 86 | 2026-05-18 | `blocklist` |
| [knyz/based-christian-blocklist](https://codeberg.org/knyz/based-christian-blocklist) | 0 | 2024-12-03 | `blocklist` |
| [nithou/begone-blocklist](https://codeberg.org/nithou/begone-blocklist) | 0 | 2026-02-09 | `blocklist` |
| [blackfoxpl/blackfox_blocklist](https://codeberg.org/blackfoxpl/blackfox_blocklist) | 0 | 2026-05-22 | `blocklist` |
| [gzachariadis/Blacklist](https://codeberg.org/gzachariadis/Blacklist) | 5 | 2024-08-16 | `blocklist` |
| [fabriziosalmi/blacklists](https://codeberg.org/fabriziosalmi/blacklists) | 0 | 2025-03-01 | `blocklist` |
| [spootle/blocklist](https://codeberg.org/spootle/blocklist) | 5 | 2024-12-03 | `blocklist` |
| [rad4day/blocklist](https://codeberg.org/rad4day/blocklist) | 0 | 2024-12-03 | `blocklist` |
| [bbbhltz/16CompaniesFilters](https://codeberg.org/bbbhltz/16CompaniesFilters) | 12 | 2026-04-12 | `blacklist` |
| [parlortricks/blacklist](https://codeberg.org/parlortricks/blacklist) | 0 | 2024-12-03 | `blacklist` |
| [Sergey_Paradox/blacklist](https://codeberg.org/Sergey_Paradox/blacklist) | 0 | 2024-12-03 | `blacklist` |
| [wysnzhang/blacklist](https://codeberg.org/wysnzhang/blacklist) | 0 | 2026-05-24 | `blacklist` |
| [sciss/Blacklist](https://codeberg.org/sciss/Blacklist) | 0 | 2024-07-13 | `blacklist` |
| [amassivus/Blacklist](https://codeberg.org/amassivus/Blacklist) | 0 | 2024-08-02 | `blacklist` |
| [andersaardvark/blacklist-check-unix-linux-utility](https://codeberg.org/andersaardvark/blacklist-check-unix-linux-utility) | 0 | 2025-09-29 | `blacklist` |
| [fabiux/blacklist-user-agents-conf](https://codeberg.org/fabiux/blacklist-user-agents-conf) | 0 | 2026-05-21 | `blacklist` |
| [ig3/blacklistd](https://codeberg.org/ig3/blacklistd) | 0 | 2025-08-11 | `blacklist` |
| [SugusGuard/Blacklists](https://codeberg.org/SugusGuard/Blacklists) | 0 | 2026-05-11 | `blacklist` |

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
*Generiert: 2026-05-24 15:26 UTC*