# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-25 14:09 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **11499** |
| davon GitHub (Topics+Code) | **11409** |
| davon GitLab | **90** |
| davon Awesome-Lists | **2400** |
| Tools/Libraries vor Eval gefiltert | **1537** |
| davon Hard-Reject (awesome-Liste etc.) | **169** |
| EVAL-Kandidaten (nach Stratifizierung) | **450** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **450** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **449** |
| Neu angenommene Feed-Dateien | **6** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **199** |
| Abgelehnte Repositories (dieser Run) | **449** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **205** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **161513** |
| SQLite-Refresh-Cache-Hits | **185/199** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **246** |
| Repo zu alt (>30d) | **154** |
| IP-Datei veraltet (>30d) | **30** |
| Falsche Größe (<30 / >2,000,000 IPs) | **18** |
| Sonstige | **1** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `gazpitchy92_ip_blocklist_blacklist` | [gazpitchy92/ip-blocklist](https://github.com/gazpitchy92/ip-blocklist) | GITHUB | 266,902 | 25.4% | 0.0% | 6 | 🆕 NEU |
| `brandontroidl_blocklist_all_90d` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 3,782 | 67.1% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_30d_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 3,376 | 69.3% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_7d_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 791 | 64.9% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_24h_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 237 | 44.7% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_standard_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 78 | 56.4% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `Ondulab/Sp3ctra_CIS_electronics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `festlv/thc` | GITHUB | Zu alt: 4590d |
| `Testbild-synth/super-sweet-16` | GITHUB | Zu alt: 551d |
| `Badbird5907/microkey` | GITHUB | Zu alt: 240d |
| `EmilEmilchen/chess-board` | GITHUB | Zu alt: 84d |
| `samienr/kryptonite` | GITHUB | Zu alt: 759d |
| `dialgorithm/tek` | GITHUB | Zu alt: 35d |
| `aviyanp/RubberESP32-S3` | GITHUB | Zu alt: 297d |
| `shashwtd/Open-FlipDisk` | GITHUB | Zu alt: 75d |
| `mmukta/MLIP_Becnhmark` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rishaan2202/The-Surevival` | GITHUB | Zu alt: 189d |
| `kaileh57/Bass` | GITHUB | Zu alt: 174d |
| `rr948/python` | GITHUB | Zu alt: 347d |
| `Kalidomra/SuperClone-5.0` | GITHUB | Zu alt: 1337d |
| `olalid/SmartRoomSensor` | GITHUB | Zu alt: 3150d |
| `xueannafang/hsp_mloc_v2` | GITHUB | Zu alt: 110d |
| `timonsku/Numberwang-Badge` | GITHUB | Zu alt: 2586d |
| `CorleoneSalute/SHADOW-BLOCKER-BLOCKLIST` | GITHUB | IP-Datei 57d alt |
| `eded333/TheFuckingList` | GITHUB | Zu alt: 1588d |
| `TheKingOfDuck/fuzzDicts` | GITHUB | Zu alt: 1047d |
| `andylling/scm-jarvis` | GITHUB | Zu alt: 153d |
| `DauphinDM/snobble-Discord-Server-Bot` | GITHUB | IP-Datei 48d alt |
| `redhat-best-practices-for-k8s/telco-bot` | GITHUB | IP-Datei 252d alt |
| `kicka5h/tf-modules` | GITHUB | Zu alt: 184d |
| `0verseas/official-site-WP` | GITHUB | Zu alt: 48d |
| `elkhetadotcom/elkheta-wordpress` | GITHUB | Zu alt: 1881d |
| `UninvitedActivity/UninvitedActivity` | GITHUB | Zu alt: 73d |
| `tborychowski/self-hosted-cookbook` | GITHUB | Zu alt: 38d |
| `zebpalmer/dns_blocklists` | GITHUB | Zu alt: 414d |
| `alexinfopruna/qubbawp23` | GITHUB | Zu alt: 1181d |
| `melwong/chnfls` | GITHUB | Zu alt: 1697d |
| `nishanThapaMagar/SeedsForTheFuture` | GITHUB | Zu alt: 925d |
| `andreburiche/transparencia` | GITHUB | Zu alt: 456d |
| `Felipe771314/antonio-lorenzo` | GITHUB | Zu alt: 644d |
| `habibjutt/cloudmom_easywp` | GITHUB | Zu alt: 66d |
| `islippers/claudeguard` | GITHUB | Zu alt: 182d |
| `Soben/bethchernes.com` | GITHUB | Zu alt: 746d |
| `sh1vmani/wp-reaper` | GITHUB | Zu alt: 138d |
| `adon90/pentest_compilation` | GITHUB | Zu alt: 1373d |
| `pharemedia-alex/commercegranby` | GITHUB | Zu alt: 1835d |
| `pharemedia-alex/versilis` | GITHUB | Zu alt: 1785d |
| `opanbobo/meruhotels` | GITHUB | Zu alt: 747d |
| `Aetherinox/csf-firewall` | GITHUB | IP-Datei 357d alt |
| `iam-py-test/my_filters_001` | GITHUB | IP-Datei 646d alt |
| `fieldingtron/casaverdepucon` | GITHUB | Zu alt: 118d |
| `RegimA-Zone/regimazone` | GITHUB | Zu alt: 184d |
| `tennc/fuzzdb` | GITHUB | Zu alt: 1937d |
| `byerlikaya/claude-starter-kit` | GITHUB | Größe: 0 IPs |
| `engakhattab/Pholex` | GITHUB | Zu alt: 813d |
| `evilc0deooo/PentesterSpecialDict` | GITHUB | Zu alt: 465d |
| `stellar-patrickpelayo/New-Melones-Lake-Marina` | GITHUB | Zu alt: 254d |
| `basharovV/StumbleUponAwesome` | GITHUB | Zu alt: 867d |
| `soy-rafa/claude-mcp-sentinel` | GITHUB | Zu alt: 74d |
| `ojasiam/cautious-guide` | GITHUB | Zu alt: 113d |
| `namnhat239/plugin_scan` | GITHUB | Zu alt: 1567d |
| `six2dez/OneListForAll` | GITHUB | IP-Datei 198d alt |
| `microsoft/CSS-Exchange` | GITHUB | IP-Datei 1388d alt |
| `WordpressPluginDirectory/sucuri-scanner` | GITHUB | Zu alt: 155d |
| `vmware-labs/attack-surface-framework` | GITHUB | Zu alt: 857d |
| `HammadNawaz519/e-commerce` | GITHUB | Zu alt: 128d |
| `Chocapikk/wpprobe` | GITHUB | Zu alt: 31d |
| `wwl012345/PasswordDic` | GITHUB | Zu alt: 1226d |
| `javierDAW/detection-diary` | GITHUB | Zu alt: 39d |
| `shounak-de/misc-scripts` | GITHUB | Zu alt: 3259d |
| `KomaVR/CYBER-FORGE` | GITHUB | Zu alt: 514d |
| `iustin24/chameleon` | GITHUB | Zu alt: 1227d |
| `maus-me/minecraft_scanners` | GITHUB | Zu alt: 725d |
| `wp-blocks/cf7-antispam` | GITHUB | Zu alt: 89d |
| `FaFre/WebLibre` | GITHUB | IP-Datei 699d alt |
| `7h3rAm/writeups` | GITHUB | Zu alt: 1507d |
| `milo2012/pathbrute` | GITHUB | Zu alt: 2305d |
| `shounak-de/iblocklist-loader` | GITHUB | Zu alt: 3397d |
| `boy-hack/wooyun-payload` | GITHUB | Zu alt: 1561d |
| `hypexdigital/hypex-malware-neutralizer` | GITHUB | Zu alt: 56d |
| `loucmane/gas-city-operations` | GITHUB | IP-Datei 140d alt |
| `Potato-py/Potato` | GITHUB | Zu alt: 1738d |
| `s4yashh/PortShield` | GITHUB | Zu alt: 340d |
| `cbuijs/hagezi` | GITHUB | Identischer Inhalt wie configserverapps_service_blocklists_blocklist |
| `depalmar/ai_for_the_win` | GITHUB | IP-Datei 279d alt |
| `CroodSolutions/BeaconatorC2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drcrypterdotru/warworm-stealer` | GITHUB | Zu alt: 109d |
| `chayleaf/notnft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AmgdGocha/DriveFS-Sleuth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `R3DRUN3/vermilion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `therealdreg/okhi` | GITHUB | IP-Datei 47d alt |
| `armourinfosec/Offensive-File-Transfer-Techniques` | GITHUB | Zu alt: 37d |
| `jaschadub/VectorSmuggle` | GITHUB | Zu alt: 129d |
| `mazen160/xless` | GITHUB | Zu alt: 181d |
| `fulldecent/system-bus-radio` | GITHUB | Zu alt: 191d |
| `t0thkr1s/gtfobins-cli` | GITHUB | Zu alt: 233d |
| `r1vs3c/searchbins` | GITHUB | Zu alt: 799d |
| `ekiojp/dfex` | GITHUB | Zu alt: 896d |
| `jaceddd/text_watermark` | GITHUB | Zu alt: 961d |
| `anfractuosity/musicplayer` | GITHUB | Zu alt: 1116d |
| `DamonMohammadbagher/NativePayload_BSSID` | GITHUB | Zu alt: 1208d |
| `ekiojp/circo` | GITHUB | Zu alt: 1221d |
| `Skiller9090/Lucifer` | GITHUB | Zu alt: 1417d |
| `anfractuosity/ultrasonicnetworking` | GITHUB | Zu alt: 1552d |
| `drivebadger/drivebadger` | GITHUB | Zu alt: 1617d |
| `tokyoneon/CredPhish` | GITHUB | Zu alt: 1886d |
| `leonjza/qrxfer` | GITHUB | Zu alt: 1924d |
| `OlivierLaflamme/DNSWho` | GITHUB | Zu alt: 2075d |
| `christophetd/IPv6teal` | GITHUB | Zu alt: 2618d |
| `leonjza/dnsfilexfer` | GITHUB | Zu alt: 3414d |
| `tempesta-tech/tempesta` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wallarm/gotestwaf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corazawaf/coraza` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uwaserver/uwas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FWGS/xash3d-fwgs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbe2277/waf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coreruleset/coreruleset` | GITHUB | IP-Datei 39d alt |
| `chen2he/orange-cloud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corazawaf/libcoraza` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `roxy-wi/roxy-wi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jx-sec/jxwaf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microlinkhq/is-antibot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kejilion/sh` | GITHUB | IP-Datei 817d alt |
| `owasp-modsecurity/ModSecurity` | GITHUB | IP-Datei 692d alt |
| `fuomag9/caddy-proxy-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `imperva/terraform-provider-incapsula` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maxlerebourg/crowdsec-bouncer-traefik-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corazawaf/coraza-caddy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Esri/geoportal-server-harvester` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zentinelproxy/zentinel` | GITHUB | IP-Datei 220d alt |
| `coreruleset/go-ftw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ADD-SP/ngx_waf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Safe3/uusec-waf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `owasp-modsecurity/ModSecurity-nginx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `1rhino2/RhinoWAF` | GITHUB | Größe: 0 IPs |
| `RuiSiang/PoW-Shield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OTT-Cybersecurity-LLC/lyrie-ai` | GITHUB | IP-Datei 151d alt |
| `416rehman/DeepZero` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rxerium/rxerium-templates` | GITHUB | Zu alt: 67d |
| `JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201` | GITHUB | Zu alt: 143d |
| `rxerium/CVE-2025-61882-CVE-2025-61884` | GITHUB | Zu alt: 346d |
| `onlytoxi/CVE-2025-8088-Winrar-Tool` | GITHUB | Zu alt: 403d |
| `CloudDefenseAI/falco_extended_rules` | GITHUB | Zu alt: 932d |
| `AgainstTheWest/NginxDay` | GITHUB | Zu alt: 1627d |
| `TinToSer/ios-RCE-Vulnerability` | GITHUB | Zu alt: 2614d |
| `JarryShaw/PyPCAPKit` | GITHUB | IP-Datei 1241d alt |
| `netalertx/NetAlertX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `batfish/batfish` | GITHUB | IP-Datei 108d alt |
| `lord-alfred/ipranges` | GITHUB | Overlap zu gering: 0.0% |
| `donislawdev/BeanNetworkTester` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kubeshark/kubeshark` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `D4-project/passive-ssh` | GITHUB | Zu alt: 137d |
| `edoardottt/pphack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jaeles-project/jaeles` | GITHUB | Zu alt: 97d |
| `pentagridsec/PentagridScanController` | GITHUB | Zu alt: 478d |
| `marcolivierbouch/dirbpy` | GITHUB | Zu alt: 1550d |
| `yangr0/RVuln` | GITHUB | Zu alt: 2266d |
| `k0r0pt/Project-Tauro` | GITHUB | Zu alt: 2884d |
| `3022-2/raccoon_clipper` | GITHUB | Zu alt: 352d |
| `xd4rker/MinerBlock` | GITHUB | Zu alt: 563d |
| `KillaStryder/cryptojack` | GITHUB | Zu alt: 1835d |
| `coolacid/docker-misp` | GITHUB | Zu alt: 987d |
| `adulau/misp-osint-collection` | GITHUB | Zu alt: 1092d |
| `harvard-itsecurity/docker-misp` | GITHUB | Zu alt: 2012d |
| `sapphirex00/Threat-Hunting` | GITHUB | Zu alt: 2787d |
| `NexSideloading/certificates` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `github/codeql-coding-standards` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `certd/certd` | GITHUB | IP-Datei 42d alt |
| `rovellipaolo/NinjaDroid` | GITHUB | Zu alt: 140d |
| `yaroslaff/showcert` | GITHUB | Zu alt: 220d |
| `naivesystems/analyze` | GITHUB | Zu alt: 270d |
| `lmolas/kubectl-view-cert` | GITHUB | Zu alt: 882d |
| `tozny/rancher-lets-encrypt` | GITHUB | Zu alt: 1222d |
| `Node-Study-Guide/openjs-nodejs-application-developer-study-guide` | GITHUB | Zu alt: 1628d |
| `yangfuhe/node-wxpay` | GITHUB | Zu alt: 1674d |
| `Heziode/Simple-TLS-Client-Server-with-Node.js` | GITHUB | Zu alt: 1789d |
| `xds0112/5G_based_System_level_Integrated_Sensing_and_Communication_Simulator` | GITHUB | Zu alt: 707d |
| `xds0112/5G_based_Link_level_Integrated_Sensing_and_Communication_Simulator` | GITHUB | Zu alt: 707d |
| `corazawaf/coraza-spoa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wallarm/docker-wallarm-node` | GITHUB | Zu alt: 46d |
| `Janusec/janusec-admin` | GITHUB | Zu alt: 69d |
| `Janusec/janusec` | GITHUB | Zu alt: 69d |
| `TinyActive/nginx-love` | GITHUB | Zu alt: 77d |
| `riverside/php-waf` | GITHUB | Zu alt: 148d |
| `BiuboWAF/Biubo` | GITHUB | Zu alt: 168d |
| `wallarm/api-firewall` | GITHUB | Zu alt: 175d |
| `f5devcentral/f5-agility-labs-waf` | GITHUB | Zu alt: 211d |
| `labring/RuiQi` | GITHUB | Zu alt: 226d |
| `timokoessler/easy-waf` | GITHUB | Zu alt: 399d |
| `Piyush-2975/Advanced-WAF-WAFinity` | GITHUB | Zu alt: 511d |
| `Ekultek/WhatWaf` | GITHUB | Zu alt: 775d |
| `leohearts/awd-watchbird` | GITHUB | Zu alt: 810d |
| `AvalZ/WAF-A-MoLE` | GITHUB | Zu alt: 933d |
| `vladan-stojnic/ML-based-WAF` | GITHUB | Zu alt: 966d |
| `paulveillard/cybersecurity-ethical-hacking` | GITHUB | Zu alt: 1309d |
| `titansec/OpenWAF` | GITHUB | Zu alt: 2005d |
| `UFund-Me/UFund-miniprogram` | GITHUB | Zu alt: 579d |
| `sp00fing/ddos` | GITHUB | Zu alt: 982d |
| `JSv4/Docxodus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dealfluence/adeu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JSv4/Python-Redlines` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evolsb/legal-redline-tools` | GITHUB | Zu alt: 64d |
| `titchmixgrange/Redline-LummaC2-Vidar-NJRat-DCrat-Raccon-Panel` | GITHUB | Zu alt: 191d |
| `srm985/axure-redline-tool` | GITHUB | Zu alt: 1339d |
| `rootpencariilmu/Redlinestealer2020` | GITHUB | Zu alt: 2087d |
| `kizubenda/NjRAT-ShadowEdge-Controller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xPh0enix/njCrypter` | GITHUB | Zu alt: 2390d |
| `Wonderfall/dockerfiles` | GITHUB | Zu alt: 1773d |
| `jim-schwoebel/allie` | GITHUB | Zu alt: 541d |
| `AutoViML/Auto_ViML` | GITHUB | Zu alt: 603d |
| `AutoViML/Auto_TS` | GITHUB | Zu alt: 766d |
| `AutoViML/AutoViz` | GITHUB | Zu alt: 837d |
| `AutoViML/deep_autoviml` | GITHUB | Zu alt: 869d |
| `Yi-Chen-Lin2019/Predictive-maintenance-with-machine-learning` | GITHUB | Zu alt: 1457d |
| `chriotte/wearable_stress_classification` | GITHUB | Zu alt: 2695d |
| `ritabratamaiti/RapidML` | GITHUB | Zu alt: 2985d |
| `NeuroTechX/neurodoro` | GITHUB | Zu alt: 3143d |
| `haridas/IP-monitoring` | GITHUB | Zu alt: 4808d |
| `wolfSSL/documentation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PowerDNS/weakforced` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafael-santiago/pig` | GITHUB | Zu alt: 2153d |
| `limithit/RedisPushIptables` | GITHUB | Zu alt: 2709d |
| `HybridNetworks/whatsapp-cidr` | GITHUB | Zu alt: 244d |
| `ipinfo/sample-database` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NetworkCats/OpenProxyDB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `itbdw/ip-database` | GITHUB | Zu alt: 1029d |
| `drag0n141/home-ops` | GITHUB | IP-Datei 793d alt |
| `ishioni/homelab-ops` | GITHUB | IP-Datei 1017d alt |
| `cozystack/cozystack` | GITHUB | Größe: 0 IPs |
| `joryirving/home-ops` | GITHUB | Größe: 0 IPs |
| `devantler-tech/ksail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `auricom/home-ops` | GITHUB | Größe: 0 IPs |
| `siderolabs/omni-infra-provider-bare-metal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JJGadgets/Biohazard` | GITHUB | IP-Datei 786d alt |
| `axeII/home-ops` | GITHUB | Größe: 0 IPs |
| `postfinance/topf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tyriis/home-ops` | GITHUB | Größe: 0 IPs |
| `larivierec/home-cluster` | GITHUB | IP-Datei 758d alt |
| `buroa/home-ops` | GITHUB | IP-Datei 132d alt |
| `hcloud-talos/terraform-hcloud-talos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `onedr0p/home-ops` | GITHUB | IP-Datei 132d alt |
| `szinn/k8s-homelab` | GITHUB | IP-Datei 35d alt |
| `home-operations/tuppr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thewhiteh4t/nexfil` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/instagram_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yamato-Security/hayabusa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alphasoc/flightsim` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `guardsight/gsvsoc_cirt-playbook-battle-cards` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JPCERTCC/MalConfScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cyb3rfox/Aurora-Incident-Response` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TonyPhipps/Meerkat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tclahr/uac` | GITHUB | IP-Datei 32d alt |
| `DFIRKuiper/Kuiper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DFIR-ORC/dfir-orc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PagerDuty/incident-response-docs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mgreen27/Invoke-LiveResponse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Security-Onion-Solutions/security-onion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dfirtrack/dfirtrack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sandialabs/scot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `counteractive/incident-response-plan-template` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityBrewery/catalyst` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dfir-iris/iris-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splunk/botsv1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corelight/zeek2es` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MHaggis/hunt-detect-prevent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mdsecactivebreach/SharpShooter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `palantir/osquery-configuration` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MHaggis/sysmon-dfir` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mvelazc0/Oriana` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salesforce/GQUIC_Protocol_Analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splunk/botsv3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Foundstone/ExpertInvestigationGuides` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/eql` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sbousseaden/PCAP-ATTACK` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Netflix/dispatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/fatt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `slackhq/go-audit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brimsec/brim` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FoxIO-LLC/LogSlash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `A3sal0n/CyberThreatHunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sysinternals/SysmonForLinux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GoogleCloudPlatform/security-analytics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sooshie/secrepo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zeek/zeek-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splunk/salo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/varna` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERT-Polska/hfinger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `op7ic/BlueTeam.Lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salesforce/ja3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sysinternals/ProcMon-for-Linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kolide/fleet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tenzir/threatbus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beahunt3r/Windows-Hunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThreatHuntingProject/ThreatHunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Shuffle/Shuffle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hasherezade/hollows_hunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jandre/brosquery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `guardicore/monkey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `clong/DetectionLab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `virustotal/yara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ocsf/ocsf-schema` | GITHUB | IP-Datei 53d alt |
| `yahoo/rdfp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sans-blue-team/DeepBlueCLI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `osquery/osquery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `unfetter-analytic/unfetter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arkime/arkime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salesforce/hassh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/auditd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `center-for-threat-informed-defense/adversary_emulation_library` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mdsecactivebreach/CACTUSTORCH` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cyb3rWard0g/mordor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/deception-as-detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ssllabs/sslhaf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BlueTeamLabs/sentinel-attack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmpireProject/Empire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bro/bro-osquery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trustedsec/ptf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marshyski/sshwatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evilsocket/opensnitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `StackExchange/blackbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rfunix/Pompem` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `504ensicsLabs/LiME.git` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deepfence/SecretScanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iBotPeaches/Apktool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dtag-dev-sec/t-pot-autoinstall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ptswarm/reFlutter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lanmaster53/recon-ng` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `undeadlist/trust-scan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `baalmor/cve-ape` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenSOC/opensoc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rusty-ferris-club/shellclear` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jtpereyda/boofuzz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `owasp/nodegoat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marcinguy/scanmycode-ce` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zeroq/amun` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zaproxy/zap-api-nodejs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Checkmarx/kics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cloudsecurelab/security-acronyms` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/rekall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uptimejp/sql_firewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mozilla/sops` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OWASP/owasp-mstg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `retracedhq/retraced` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SpectralOps/keyscope` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fingerprintjs/fingerprintjs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ir193/AMExtractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RustScan/RustScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zaproxy/zaproxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nil0x42/phpsploit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `karimhabush/cyberowl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `baidu/openrasp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kai5263499/container-security-awesome` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jnv/lists` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `99designs/aws-vault` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tijme/angularjs-csti-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lirantal/is-website-vulnerable` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pompelmi/pompelmi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `apache/incubator-spot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frida/frida` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `selefra/selefra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rozgo/anevicon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `starkandwayne/safe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dogoncouch/LogESP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmotiveAutomaton/ghost-scale-sim` | GITHUB | Größe: 0 IPs |
| `JackelineBDM/ics-risk-hub-fullstack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shettyprasad-git/smart-sales-forecasting-system` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ph4n70mr1ddl3r/erpplans_ebs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `YoctoPhoenixMoon/Heroes-Vow-Three-Kingdoms-Trainer-Collection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `praveenkumar1819/Lab-demo-1-Dhruv-god` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shubhamsahu7348/SafeCity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wiothemilo-lang/Autoreply-and-anti-nuke-raid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dphov/omarchy-moergo-companion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `michalstankiewicz4-cell/Space` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vcv-code/SubvDGDA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blocknine0/geomacro` | GITHUB | Größe: 0 IPs |
| `Saranya22-git/DSA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dung122m/netflix1.1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Navjot0/sms-DLR-reciever` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magda-uk/soc-analyst-showcase` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaushikbuilds-cloud/hackathon-management-system` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `martex-dev/aurelis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `etelford32/AI_Safety_Explorer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ittrail/sitebin.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arvind-dhariwal/aeon-credit-gcp-workshop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ulcnzey/cybersecurity-notes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TSVMV/agentscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Brandon-m-Smith4439/3D-Printing-Website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vaishnavipoojary2202/malicious-url-detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sadvik-asus/Self-Evolving-AI-HoneyPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Don-Works/brw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `miquelrosell99/sonarly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `philippstorl/philipp.fyi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vecchioni-lab/NASolve` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `la2278647-arch/ctxpack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `smit061205/SIH_26006` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lerry20/foler-growth-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RJain12/code-switcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `erikenz/dotfiles` | GITHUB | IP-Datei 75d alt |
| `panzhifu/trove` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `felpower/PaniVR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `agamafinance/agama-xlayer` | GITHUB | Größe: 0 IPs |
| `vinit-churi/tracesarkar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mvua-Protocol/mvua-contract` | GITHUB | Größe: 0 IPs |
| `factorysemantics/factorysemantics-mes` | GITHUB | Größe: 0 IPs |
| `rudras777/rivexis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `synthaea-lab/edr-new` | GITHUB | Größe: 0 IPs |
| `RealmsNetwork/Bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ajeytiwary/bonsai_local` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SchwarzRene/bqe-frontend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hasamba/DFIR-Companion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jasonroberts-tw/asdlc-openspec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anuj00018/Kairos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `emustwe/We_Must_E` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dj0rdj3987/AD-Lab-Project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khoinguyen88kt/chrome-macpro-gpu-patch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PixelAlien0/TERMINAL` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `panagiotagrosdouli/pc-fmcw-robotics-planning` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anizum1/GitLine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mudilisabetta47/monvexu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `M-Stoufa/Clients-Contracts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jfautowear/AutopostTg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cosylanguages/COSYgames` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PromptMintLabs/prompt-mint` | GITHUB | Größe: 0 IPs |
| `Odijas/facilit-desafio-kanban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `simoneggert16-png/gods-eye-view` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `huangtianfrance/market-watch-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MRX-72/MRX-72` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `itsmyfinance77-dev/BeauClick` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ER723/soc-log-analyser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DevEslam1/pulsr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BhagyaSalgado/cinevault-ebeyonds-test` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mikeparcewski/wicked-crew` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kirthan-Choudhary-A/Mirraura` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lelik112/parrot669` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mokuyoaxis/medical-privacy-guard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keyboord01/tap-arc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafaqat/projecta` | GITHUB | Größe: 0 IPs |
| `pradun-oops/data_security_manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RatarInvo/Mjukvaruutvecklingsprocessen-DevOps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dmitry-milyutin/Port-Scanner-on-Django` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ADRN-9/wedecent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lazynext-Platform/accessibility-checker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Agence-de-la-Transition-Ecologique/dashlord-ruche` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `murdok1982/murdok-inference-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chrisashley-jnr/rebeltattoo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `scriptzteam/GitHub-Trending` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kavyakunuku/Open_Code_SELLING_AVWAP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inn-media/truyn` | GITHUB | Größe: 0 IPs |
| `Aurtechmx/openlidarviewer` | GITHUB | IP-Datei 38d alt |
| `KKloudTarus/synapse-ce` | GITHUB | Größe: 0 IPs |
| `chungminhtu/brother-t220-wifi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drsharma994-rgb/hardgate-main` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexmarceauprevost812-source/apk-terminal-kali-linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yosi33450/fraud-systems` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ameriqbalqureshi/mikroduinostudio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nuanu-ai/agentify` | GITHUB | Größe: 0 IPs |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 31,351 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,935 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,549 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 11,566 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,844 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,786 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,755 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 3,039 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,951 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,017 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,504 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,416 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,015 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 716 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 658 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 622 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 426 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,171 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,689 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 18,115 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 10,186 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,731 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,612 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 4,076 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 212,794 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,586 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 4,720 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,638 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 2,086 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,713 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 5,024 | 64.3% | 938 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 53,330 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,480 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,717 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 117,069 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 91,506 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,867 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,287 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 106,265 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,718 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 123,658 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,579 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 125,216 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 679 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 475,351 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,449 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 172,463 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 167,416 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 137,794 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 153,958 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 96,625 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 113,157 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 95,771 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 234,426 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 53,161 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 178,003 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 27,631 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 21,723 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 25,251 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 24,219 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 15,345 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 177,775 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,572 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 11,681 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 6,879 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 21,253 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 13,707 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,512 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 11,255 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 7,252 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,816 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,829 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,928 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,878 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 4,808 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,420 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 3,301 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,737 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,839 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 103,327 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,792 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,263 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 61,038 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,670 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 3,395 | 79.4% | 10 | 2026-09-24 |
| `ian_lusule_proxies` | GITHUB | 3,580 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,728 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,385 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 272,879 | 22.0% | 6 | 2026-07-08 |
| `gazpitchy92_ip_blocklist_blacklist` | GITHUB | 266,902 | 25.4% | 6 | 2026-09-25 |
| `officialputuid_proxyforeveryone` | GITHUB | 7,922 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 6,787 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 7,396 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,498 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 77 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 95,766 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 95,845 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,564 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 99 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 96,214 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,862 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,708 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 151 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 17,491 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 17,260 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 21,331 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,360 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 61,318 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 62,699 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,753 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 129,408 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 353 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 195,409 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,533 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 130,055 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 203,021 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,237 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 36,253 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 496 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 17,570 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 19,549 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,728 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 9,969 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,223 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,638 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 5,268 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,555 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,116 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,526 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 4,859 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,789 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 5,974 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 3,888 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,215 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,380 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,375 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,313 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,324 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,120 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,218 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,846 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,134 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,446 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 688 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,963 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,687 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 983 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 11,951 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,412 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 91,613 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 87,825 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 94,984 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 93,286 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 91,850 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 89,744 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,087 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 51,391 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 11,762 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,842 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,800 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,000 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,800 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 42,119 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 20,240 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 11,990 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 6,182 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 41 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 28,739 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 153,961 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 24,179 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 2,881 | 5.1% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,148 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,366 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 3,780 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,381 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 798 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 249 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 82 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 5,916 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 98,889 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 91,188 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 92,459 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 93,463 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 90,356 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 26,397 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 844 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 835 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_20` | GITHUB | 183 | 92.3% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 183 | 76.9% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_24` | GITHUB | 157 | 90.4% | 0 | 2026-09-25 |
| `brandontroidl_blocklist_all_90d` | GITHUB | 3,782 | 67.1% | 0 | 2026-09-25 |
| `brandontroidl_blocklist_all_30d_v2` | GITHUB | 3,376 | 69.3% | 0 | 2026-09-25 |
| `brandontroidl_blocklist_all_7d_v2` | GITHUB | 791 | 64.9% | 0 | 2026-09-25 |
| `brandontroidl_blocklist_all_24h_v2` | GITHUB | 237 | 44.7% | 0 | 2026-09-25 |
| `brandontroidl_blocklist_standard_v2` | GITHUB | 78 | 56.4% | 0 | 2026-09-25 |

---
*Generiert: 2026-09-25 14:09 CEST (Europe/Berlin)*