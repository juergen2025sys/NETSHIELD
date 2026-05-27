# Auto Feed Discovery – Report
**Aktualisiert:** 2026-05-27 05:51 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **6694** |
| davon GitHub (Topics+Code) | **6657** |
| davon GitLab | **37** |
| davon Awesome-Lists | **1023** |
| Tools/Libraries vor Eval gefiltert | **941** |
| davon Hard-Reject (awesome-Liste etc.) | **92** |
| EVAL-Kandidaten (nach Stratifizierung) | **240** |
| davon bereits rejected (übersprungen) | **168** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluiert | **79** |
| Neu angenommen | **5** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bekannte Feeds re-fetched | **25** |
| Abgelehnt (dieser Run) | **72** |
| davon GitLab abgelehnt | **10** |
| Feeds gesamt (aktiv) | **30** |
| IPs in seen_db bestätigt | **692508** |
| Neue IPs eingetragen | **1625** |
| seen_db gesamt | **4,763,945** |
| HQ-Referenz-IPs (6 Quellen) | **137802** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **46** |
| Repo zu alt (>30d) | **22** |
| IP-Datei veraltet (>30d) | **2** |
| Falsche Größe (<100 / >500k IPs) | **2** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `cbuijs_accomplist_adblock_ip` | [cbuijs/accomplist](https://github.com/cbuijs/accomplist) | GITHUB | 126,685 | 0.6% | 1.5% | 20 | 🆕 NEU |
| `cbuijs_accomplist_plain_black_ip4cidr` | [cbuijs/accomplist](https://github.com/cbuijs/accomplist) | GITHUB | 126,685 | 0.6% | 1.5% | 20 | 🆕 NEU |
| `turbolabit_zzfirewall_blacklist` | [TurboLabIt/zzfirewall](https://github.com/TurboLabIt/zzfirewall) | GITHUB | 85 | 66.4% | 0.0% | 0 | 🔄 Update |
| `wintergate_ic_wic_resources_permanent_blacklist` | [WinterGate-IC/wic-resources](https://github.com/WinterGate-IC/wic-resources) | GITHUB | 508 | 67.0% | 0.0% | 0 | 🆕 NEU |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) | GITHUB | 10,623 | 75.0% | 0.0% | 4721 | 🆕 NEU |
| `kamalmjt_emerging_attackers_badips` | [kamalmjt/emerging-attackers](https://github.com/kamalmjt/emerging-attackers) | GITHUB | 162,907 | 18.9% | 0.0% | 1 | 🆕 NEU |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | [ziyadnz/threat-intel-ip-feeds](https://github.com/ziyadnz/threat-intel-ip-feeds) | GITHUB | 100,889 | 36.7% | 0.0% | 8 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2085d |
| `MISP/MISP-maltego` | GITHUB | Zu alt: 703d |
| `MalwareSamples/Malware-Feed` | GITHUB | Zu alt: 1867d |
| `Truvis/Suricata_Threat-Hunting-Rules` | GITHUB | Zu alt: 2082d |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei |
| `vercube/vercube` | GITHUB | Keine IP-Datei |
| `loopbackio/loopback-next` | GITHUB | Keine IP-Datei |
| `InQuest/ThreatIngestor` | GITHUB | Keine IP-Datei |
| `intelowlproject/IntelOwl` | GITHUB | IP-Datei 96d alt |
| `ioc-fang/ioc-fanger` | GITHUB | Keine IP-Datei |
| `modern-python/modern-di` | GITHUB | Keine IP-Datei |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei |
| `farseer-go/fs` | GITHUB | Keine IP-Datei |
| `TAKETODAY/today-infrastructure` | GITHUB | Keine IP-Datei |
| `reactiveui/splat` | GITHUB | Keine IP-Datei |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei |
| `maou-shonen/hono-simple-DI` | GITHUB | Keine IP-Datei |
| `samber/do` | GITHUB | Keine IP-Datei |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei |
| `suites-dev/suites` | GITHUB | Keine IP-Datei |
| `BC-SECURITY/Starkiller` | GITHUB | Keine IP-Datei |
| `c2lang/c2compiler` | GITHUB | Keine IP-Datei |
| `maxDcb/C2TeamServer` | GITHUB | Keine IP-Datei |
| `cfs0x/Cobalt-Strike-Ultimate-Arsenal` | GITHUB | Keine IP-Datei |
| `sharsil/favicorn` | GITHUB | Keine IP-Datei |
| `BlackSnufkin/Cheshire` | GITHUB | Keine IP-Datei |
| `jm33-m0/emp3r0r` | GITHUB | Keine IP-Datei |
| `Xart3mis/AKILT` | GITHUB | Zu alt: 58d |
| `bmshifat/TecSpy` | GITHUB | Zu alt: 103d |
| `0x4meliorate/toxnet` | GITHUB | Zu alt: 108d |
| `CirqueiraDev/OverburstC2` | GITHUB | Zu alt: 129d |
| `illusionsec/DDOS-archive` | GITHUB | Zu alt: 134d |
| `hackerxphantom/hxp_photo_eye` | GITHUB | Zu alt: 201d |
| `zarkones/OnionC2` | GITHUB | Zu alt: 209d |
| `efxtv/L3MON` | GITHUB | Zu alt: 223d |
| `yaklang/yakit` | GITHUB | Keine IP-Datei |
| `google/osv-scanner` | GITHUB | Keine IP-Datei |
| `zmap/zdns` | GITHUB | Keine IP-Datei |
| `ipverse/as-ip-blocks` | GITHUB | Keine IP-Datei |
| `splorp/wordpress-comment-blocklist` | GITHUB | Größe: 0 IPs |
| `popcar2/BadWebsiteBlocklist` | GITHUB | Größe: 0 IPs |
| `malwaredb/malwaredb-rs` | GITHUB | Keine IP-Datei |
| `kawaiipantsu/spamassassin-rules` | GITHUB | Keine IP-Datei |
| `OspreyProject/Osprey` | GITHUB | Keine IP-Datei |
| `0xDanielLopez/phishing_kits` | GITHUB | Keine IP-Datei |
| `jvexcoder/Hacker-Hook` | GITHUB | Keine IP-Datei |
| `michael-yip/ThreatTracker` | GITHUB | Keine IP-Datei |
| `gitlab:urbanware-org/honeypot-wasp` | GITLAB | Zu alt: 684d |
| `gitlab:urbanware-org/honeypot-hornet` | GITLAB | Zu alt: 684d |
| `gitlab:scott-codes-things/ssh-honey-pot-reporter/honey-pot` | GITLAB | Zu alt: 809d |
| `gitlab:ansible-roles3353717/ansible-custom-firewall` | GITLAB | Zu alt: 824d |
| `gitlab:acidvegas/jupiter` | GITLAB | Zu alt: 857d |
| `gitlab:bloodhunterd-labs/tools/pi-hole-blocklists` | GITLAB | Zu alt: 934d |
| `gitlab:knister94/mirai-tracker` | GITLAB | Zu alt: 2386d |
| `gitlab:ProjetoIntegradorNoite/honeypot---comparativo-entre-ferramentas-em-ambiente-real` | GITLAB | Zu alt: 2566d |
| `gitlab:Twoure/p2p-blocklist` | GITLAB | Zu alt: 2773d |
| `gitlab:freetom/SSH-anti-DoS` | GITLAB | Zu alt: 2836d |
| `Irdk1242s/triagectl` | GITHUB | Keine IP-Datei |
| `rishikumarp-sec/soc-home-lab` | GITHUB | Keine IP-Datei |
| `Hack23/euparliamentmonitor` | GITHUB | Keine IP-Datei |
| `vindicara-inc/projectair` | GITHUB | Keine IP-Datei |
| `Velocidex/velociraptor` | GITHUB | IP-Datei 525d alt |
| `SobralCybersec/APIKeyScanner` | GITHUB | Keine IP-Datei |
| `acid5555/pi-hostname` | GITHUB | Keine IP-Datei |
| `mauricegift/free-proxies` | GITHUB | Keine IP-Datei |
| `SATiger9300/solo-saas-field-manual` | GITHUB | Keine IP-Datei |
| `MERUS-J/dictate.sh` | GITHUB | Keine IP-Datei |
| `Hack23/riksdagsmonitor` | GITHUB | Keine IP-Datei |
| `Abhi2109kumar/FaceID` | GITHUB | Keine IP-Datei |
| `Talhaer/cloud-skills-roadmap` | GITHUB | Keine IP-Datei |
| `kakshaykumar/cloud-security-iaas` | GITHUB | Keine IP-Datei |
| `hyu164/Terrminus-CVE-2026-2406` | GITHUB | Keine IP-Datei |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | GITHUB | 10,623 | 75.0% | 4721 | 2026-05-27 |
| `cbuijs_accomplist` | GITHUB | 96,803 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,474 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 126,685 | 0.6% | 20 | 2026-05-27 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 100,889 | 36.7% | 8 | 2026-05-27 |
| `turntuptechnologies_iocs` | GITHUB | 14 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 37,533 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 94,519 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,137 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 94 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 220,659 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 7,822 | 69.0% | 4 | 2026-05-24 |
| `fadouse_clash_threat_intel` | GITHUB | 5,151 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 5,318 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 162,907 | 18.9% | 1 | 2026-05-27 |
| `idleadmin_threatfeed` | GITHUB | 49,503 | 41.9% | 0 | 2026-04-09 |
| `turbolabit_zzfirewall` | GITHUB | 99,291 | 66.4% | 0 | 2026-05-03 |
| `kraloveckey_ipsets_blocklist` | GITHUB | 16,854 | 13.1% | 0 | 2026-05-10 |
| `wintergate_ic_wic_resources_permanent_blacklist_v2` | GITHUB | 503 | 67.0% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 39,209 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_iblocklist_ciarmy_malicious` | GITHUB | 12,692 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_et_tor` | GITHUB | 7,560 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,449 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_blocklist_de_ssh` | GITHUB | 5,071 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_blocklist_de_bruteforce` | GITHUB | 680 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_snort_ip_blocklist` | GITHUB | 1,386 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_alienvault_reputation` | GITHUB | 609 | 13.1% | 0 | 2026-05-24 |
| `turbolabit_zzfirewall_blacklist` | GITHUB | 85 | 66.4% | 0 | 2026-05-27 |
| `wintergate_ic_wic_resources_permanent_blacklist` | GITHUB | 508 | 67.0% | 0 | 2026-05-27 |

---
*Generiert: 2026-05-27 05:51 UTC*