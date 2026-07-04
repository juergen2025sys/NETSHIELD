# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-04 07:05 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7643** |
| davon GitHub (Topics+Code) | **7592** |
| davon GitLab | **51** |
| davon Awesome-Lists | **1017** |
| Tools/Libraries vor Eval gefiltert | **1287** |
| davon Hard-Reject (awesome-Liste etc.) | **142** |
| EVAL-Kandidaten (nach Stratifizierung) | **302** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **302** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **301** |
| Neu angenommene Feed-Dateien | **17** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **95** |
| Abgelehnte Repositories (dieser Run) | **301** |
| davon GitLab abgelehnt | **2** |
| Feeds gesamt (aktiv) | **112** |
| IPs in seen_db bestätigt | **4438656** |
| Neue IPs eingetragen | **981007** |
| seen_db gesamt | **7,648,997** |
| HQ-Referenz-IPs (6 Quellen) | **140920** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Sonstige | **275** |
| Falsche Größe (<100 / >2,000,000 IPs) | **17** |
| IP-Datei veraltet (>30d) | **8** |
| Repo zu alt (>30d) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_myip` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 924 | 65.5% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 887 | 6.0% | 0.0% | 0 | 🆕 NEU |
| `configserverapps_service_blocklists_blacklist_15d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 46,419 | 47.8% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_blocklist` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 46,339 | 40.4% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_telnet_365d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 42,372 | 29.7% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_blocklist_large` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 29,715 | 62.8% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_blocklist_core` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 21,404 | 67.5% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_all_365d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 24,666 | 77.0% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_level2` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 22,287 | 94.9% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_level2_v2` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 18,583 | 62.6% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_all` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 16,154 | 60.8% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_ftp_365d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 15,181 | 35.9% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_forums` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 13,228 | 5.5% | 0.0% | 10 | 🆕 NEU |
| `vpslabcloud_vpslab_free_proxy_list` | [VPSLabCloud/VPSLab-Free-Proxy-List](https://github.com/VPSLabCloud/VPSLab-Free-Proxy-List) | GITHUB | 1,214 | 6.2% | 0.0% | 60 | 🆕 NEU |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | [VPSLabCloud/VPSLab-Free-Proxy-List](https://github.com/VPSLabCloud/VPSLab-Free-Proxy-List) | GITHUB | 777 | 8.6% | 0.0% | 60 | 🆕 NEU |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | [VPSLabCloud/VPSLab-Free-Proxy-List](https://github.com/VPSLabCloud/VPSLab-Free-Proxy-List) | GITHUB | 762 | 8.5% | 0.0% | 60 | 🆕 NEU |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | [VPSLabCloud/VPSLab-Free-Proxy-List](https://github.com/VPSLabCloud/VPSLab-Free-Proxy-List) | GITHUB | 666 | 9.2% | 0.0% | 60 | 🆕 NEU |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | [VPSLabCloud/VPSLab-Free-Proxy-List](https://github.com/VPSLabCloud/VPSLab-Free-Proxy-List) | GITHUB | 436 | 12.8% | 0.0% | 60 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `JasonLovesDoggo/caddy-defender` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `muchdogesec/obstracts` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CriticalPathSecurity/Zeek-Intelligence-Feeds` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rix4uni/medium-writeups` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EndlessFractal/Threat-Intel-Feed` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `christinminor459/OnionClaw` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `KatrielMoses/MailAccess` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Bert-JanP/Open-Source-Threat-Intel-Feeds` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vercube/vercube` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `modern-python/modern-di` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `deepfield/public-research` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GreedyBear-Project/GreedyBear` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `reactiveui/splat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `IOCoin/DIONS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `stanfrbd/cyberbro` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `samber/do` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `midwayjs/midway` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `suites-dev/suites` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `abdullahbutt/deutsch-lernen-goethe-a1-c2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `The-Z-Labs/bof-launcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `chainreactors/malice-network` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nickvourd/SkyFall-Pack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `28Zaaky/khaos-c2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `looCiprian/GC2-sheet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jm33-m0/emp3r0r` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `chainreactors/malefic` | GITHUB | Größe: 0 IPs |
| `r4ulcl/Mythic-OSEP-CheatSheet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `portbuster1337/ArachneC2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wsummerhill/C2_RedTeam_CheatSheets` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BlackSnufkin/Maverick` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cfs0x/Cobalt-Strike-Ultimate-Arsenal` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mwakidenis/mwakidenis` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yankywilson/jdy-botnet-threat-analysis` | GITHUB | Größe: 10 IPs |
| `drcrypterdotru/warworm-stealer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `osociety/network_tools` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hashgraph-online/hol-guard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vdjagilev/nmap-formatter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `horsicq/Detect-It-Easy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `5rahim/seanime` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ostorlab/oxo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `manticore-projects/aurscan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sefinek/UFW-AbuseIPDB-Reporter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `romainmarcoux/malicious-hash` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Stevoisiak/Stevos-AI-Blocklist` | GITHUB | Größe: 0 IPs |
| `ipverse/as-ip-blocks` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cbuijs/oisd` | GITHUB | Größe: 0 IPs |
| `popcar2/BadWebsiteBlocklist` | GITHUB | Größe: 0 IPs |
| `splorp/wordpress-comment-blocklist` | GITHUB | Größe: 0 IPs |
| `Adamm00/IPSet_ASUS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rainbowdashlabs/reputation-bot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dohoangtungduong24/Redline-Vidar-NJRat-Raccoon-C2-Panel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ruzickap/malware-cryptominer-container` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0xDanielLopez/phishing_kits` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mytechnotalent/Reverse-Engineering` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `toborrm9/malicious_extension_sentry` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mandiant/flare-floss` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OspreyProject/Osprey` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `phishingclub/phishingclub` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `andpalmier/makephish` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cybercdh/kitphishr` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sublime-security/sublime-rules` | GITHUB | Größe: 0 IPs |
| `kawaiipantsu/spamassassin-rules` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `x90skysn3k/brutespray` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sensepost/hash-cracker` | GITHUB | IP-Datei 49d alt |
| `chickendrop89/OneShot-Extended` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0xPugal/fuzz4bounty` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vanhauser-thc/thc-hydra` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `samsesh/SocialBox-Termux` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `samuelcaldas/Bruteforce-Bootloader-Unlocker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `duyet/bruteforce-database` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `chaitin/SafeLine` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `X-Stuff/CudaKeeloq` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aryainjas/Microllect` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Rem01Gaming/OneShot-Termux` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `animir/node-rate-limiter-flexible` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zhangjiayang6835-cyber/ai-research` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sjinks/mysql-honeypotd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `andreicscs/HoneyWire` | GITHUB | Größe: 0 IPs |
| `djkurlander/knock-knock` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RiskyMH/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cowrie/cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BlessedRebuS/Krawl` | GITHUB | Größe: 0 IPs |
| `theaog/spirit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Yamato-Security/hayabusa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OISF/suricata` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mthcht/ThreatIntel-Reports` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ninoseki/mihari` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `The-Privacy-Commons-Institute/chrome-mal-ids` | GITHUB | Größe: 0 IPs |
| `utmstack/UTMStack` | GITHUB | Größe: 0 IPs |
| `mentat-is/gulp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JMousqueton/CTI-MSTeams-Bot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `privtools/ransomposts` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RansomLook/RansomLook` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `f6-dfir/Ransomware` | GITHUB | Größe: 2 IPs |
| `badchars/darknet-mcp-server` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PanagiotisDrakatos/JavaRansomware` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LJ9859/Malware-Database` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ThreatLabz/ransomware_notes` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BushidoUK/Ransomware-Tool-Matrix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dmdhrumilmistry/pyhtools` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `iss4cf0ng/OpenPetya` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ThreatLabz/tools` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AOSC-Dev/oma` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `avaje/avaje-inject` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheDuffman85/linux-update-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kdeldycke/meta-package-manager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PatchMon/PatchMon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sous-chefs/apt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rami3l/pacaptr` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aptly-dev/aptly` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `S3N4T0R-0X0/APTs-Adversary-Simulation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wimpysworld/deb-get` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mapbox/mason` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mexirica/aptui` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `neur0map/glazepkg` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lbr38/repomanager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `StopDDoS/packet-captures` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tempesta-tech/tempesta` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aliesbelik/load-testing-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Safe3/uusec-waf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lance0/prefixd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `darkweak/rudy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `goncalopolido/overload` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SystemVll/cloudflare-uam-bypass` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `palahsu/DDoS-Ripper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zer-far/spurt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `duy13/vDDoS-Protection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `c0r0n3r/dheater` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RuiSiang/PoW-Shield` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nccgroup/SteppingStones` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `D7EAD/mkPIVM` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cisagov/ansible-role-cobalt-strike` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `endend2003-cmd/Tactical-Matrix-Console` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nomi-sec/PoC-in-GitHub` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Patrowl/PatrowlHearsData` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yadavnikhil17102004/CVE-Intel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GhostTroops/TOP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FrizzleM/SideInstaller` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Charcoal-SE/SmokeDetector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nonPointer/uBlacklist-Subscription` | GITHUB | Größe: 1 IPs |
| `pwlgrzs/Mikrotik-Blacklist` | GITHUB | Größe: 0 IPs |
| `spatie/laravel-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `katlogic/solana-arbitrage-bot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `adamff-dev/spam-call-blocker-app` | GITHUB | Größe: 0 IPs |
| `Dra-Ganzz/Premium-Call` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CleanTalk/php-antispam` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ypankovych/Telegram-collector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Machou/Cloudflare-Block` | GITHUB | Zu alt: 38d |
| `whoahaow/rjsxrd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Pawdroid/Free-servers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ebrasha/free-v2ray-public-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MahanKenway/Freedom-V2Ray` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Barabama/FreeNodes` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `blatteprince2/Void-Engine-GD` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `KasperskyLab/klara` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aboutsecurity/rastrea2r` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Netflix/Scumblr` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `brianwarehime/threatnote` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kbandla/APTnotes` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `1aN0rmus/TekDefense-Automater` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yahoo/PyIOCe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MISP/misp-workbench` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheHive-Project/Hippocampe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SecurityRiskAdvisors/sra-taxii2-server` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `stephenbrannon/IOCextractor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Yelp/threat_intel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `stratosphereips/Manati` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `silascutler/MalPipe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CrowdStrike/CrowdFMS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `STIXProject/stix-viz` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `abusesa/abusehelper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mlsecproject/tiq-test` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mgeide/poortego` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tripwire/tardis` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `facebook/ThreatExchange` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `johestephan/ibmxforceex.checker.py` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BinaryDefense/goatrider` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ioc-fang/ioc_fanger` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TAXIIProject/libtaxii` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Neo23x0/signature-base` | GITHUB | IP-Datei 60d alt |
| `EclecticIQ/cabby` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dougiep16/actortrackr` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mandiant/ioc_writer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PaloAltoNetworks/minemeld` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mlsecproject/combine` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EclecticIQ/OpenTAXII` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Neo23x0/Loki` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kx499/ostip` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `byt3smith/malstrom` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CylanceSPEAR/CyBot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `byt3smith/Forager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0x4d31/sqhunter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ocmdev/rita` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `QTek/QRadio` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ciscocsirt/gosint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spacepatcher/FireHOL-IP-Aggregator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `paulpc/nyx` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `InQuest/python-iocextract` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `foospidy/HoneyPy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jheise/threatcmd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jpsenior/threataggregator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jheise/threatcrowd_api` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `michael-yip/ThreatTracker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HurricaneLabs/machinae` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheHive-Project/Cortex` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sroberts/cacador` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `abhinavbom/Threat-Intelligence-Hunter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sroberts/jager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `armbues/ioc_parser` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `S03D4-164/Hiryu` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SupportIntelligence/Icewater` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Yara-Rules/rules` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fhightower/onemillion` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `InQuest/omnibus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spacepatcher/softrace` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ptr32Void/OSTrICa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Lookingglass/opentpx` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `exp0se/harbinger` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TAXIIProject/yeti` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `amv42/sshd-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `christophe77/node-ftp-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rshipp/slipm-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hexgolems/pint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yvesago/imap-honey` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mzweilin/ipv6-attack-detector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jadb/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `r0hi7/HoneySMB` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CanadianJeff/honeywrt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `buffer/libemu` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `referefref/honeydet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0x4D31/honeylambda` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `buffer/pylibemu` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `run41/honey_ports` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Plazmaz/MongoDB-HoneyProxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sjhilt/GasPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cymmetria/micros_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `magisterquis/sshhipot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aplura/Tango` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `glaslos/honeyprint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sa7mon/miniprint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ls1911/GenAIPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sreinhardt/Docker-Honeynet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bjeborn/basic-auth-pot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `csirtgadgets/csirtg-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `honeynet/apkinspector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0xBallpoint/trapster-community` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ahoernecke/ensnare` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alexbredo/honeypot-camera` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Mojachieee/go-HoneyPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `magisterquis/vnclowpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `omererdem/honeything` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `antonsatt/ssh-radar` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Masood-M/yalih` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CERT-Polska/hsn2-bundle` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gitlab:niclas-zone/ctr/cowrie` | GITLAB | Keine IP-Datei (Name/Inhalt) |
| `gitlab:kikinovak/deb_setup_fail2ban` | GITLAB | Keine IP-Datei (Name/Inhalt) |
| `buroa/k8s-gitops` | GITHUB | IP-Datei 49d alt |
| `yukariin/cluster` | GITHUB | IP-Datei 59d alt |
| `Correia-jpv/fucking-terminals-are-sexy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `phycoforce/home-ops` | GITHUB | IP-Datei 46d alt |
| `nicolerenee/infra` | GITHUB | Größe: 0 IPs |
| `gerarddiaz01/SOC-Analyst-Cybersecurity-Training` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OpenCTI-Platform/connectors` | GITHUB | IP-Datei 225d alt |
| `IvanAchire/waf-for-gmssh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `acid5555/pi-hostname` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `H-A-R-S-H-V-A-R-D-H-A-N/HOLE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `koala73/worldmonitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SATiger9300/solo-saas-field-manual` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ABODR3325/caesar-cipher-python` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MERUS-J/dictate.sh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `therayyanawaz/TeleUserBot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nezzyomran/ExecEvasion` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dasnija/aegis-omega-ids` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mango-jade/bank-network-in-cisco-packet-tracer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `taraldesai10/Watchdog` | GITHUB | IP-Datei 858d alt |
| `Abhi2109kumar/FaceID` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Shivvvanshh/Command-Line-To-Do-Manager-Python-` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dpangestuw/Free-Proxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Talhaer/cloud-skills-roadmap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Karib0u/rustinel` | GITHUB | Größe: 0 IPs |
| `apache/magpie` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rahulkushwaha1510/domHound` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `richdz12/traffic-guard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zloi-user/hideip.me` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fredperry72/crowdsec-blocklist-import` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LUANNNN1-ops/rouletteboxd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Suwanna45/Scan-port-localhost` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cognis-digital/c2detect` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rodent1/home-ops` | GITHUB | IP-Datei 49d alt |
| `elpepeeeeeeeeeeeeeeeeeeeeeeeee/iot-botnet-simulation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Platon214/Email-Spam-Detection-Project` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nikitastupin/orgs-data` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Hadrysel/WhatsApp-Network-Tracker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cludes/botnet-live-maps` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | GITHUB | 10,635 | 75.0% | 4721 | 2026-05-28 |
| `cbuijs_hagezi` | GITHUB | 46,339 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 24,962 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,067 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 3,349 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,626 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 627 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 16,884 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 143 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 76 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 5,921 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,632 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,408 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,986 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 4,630 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 2,802 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https_anonymous` | GITHUB | 3,374 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 3,759 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,214 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 777 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 762 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 666 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 436 | 12.8% | 60 | 2026-07-04 |
| `cbuijs_accomplist` | GITHUB | 99,805 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,444 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 101,092 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 108,349 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 628 | 36.7% | 8 | 2026-07-03 |
| `configserverapps_service_blocklists` | GITHUB | 3,631,071 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_anonymous` | GITHUB | 2,297,244 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_proxies` | GITHUB | 2,291,787 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,478 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,137 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 175,385 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 137,939 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 92,645 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 86,149 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 93,010 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_30d` | GITHUB | 83,708 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 84,712 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 64,777 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 46,471 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_15d` | GITHUB | 46,419 | 47.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 42,372 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 29,715 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 21,404 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 24,666 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 22,287 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 18,583 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 16,154 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 15,181 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,228 | 5.5% | 10 | 2026-07-04 |
| `turntuptechnologies_iocs` | GITHUB | 29 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 52,112 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 95,106 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,578 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 121 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 221,594 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,894 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,678 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 6,962 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 7,237 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 166,003 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 1,984 | 21.9% | 1 | 2026-07-04 |
| `idleadmin_threatfeed` | GITHUB | 51,321 | 41.9% | 0 | 2026-04-09 |
| `turbolabit_zzfirewall` | GITHUB | 99,140 | 66.4% | 0 | 2026-05-03 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 45,915 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,534 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 111,134 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 517 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,168 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 191,733 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,461 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 112,223 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 111,001 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,235 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 32,107 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 493 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 19,953 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 15,367 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,793 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 7,411 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,488 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cps_abusech` | GITHUB | 7,607 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,693 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,649 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 3,958 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,622 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,120 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,534 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 3,483 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,741 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 3,355 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,313 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 2,004 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,425 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_socks_proxy_7d` | GITHUB | 1,461 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,354 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,263 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,204 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,179 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,116 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 980 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,238 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,214 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 842 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 924 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 887 | 6.0% | 0 | 2026-07-04 |

---
*Generiert: 2026-07-04 07:05 UTC*