# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-14 15:19 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7674** |
| davon GitHub (Topics+Code) | **7623** |
| davon GitLab | **51** |
| davon Awesome-Lists | **1026** |
| Tools/Libraries vor Eval gefiltert | **1254** |
| davon Hard-Reject (awesome-Liste etc.) | **134** |
| EVAL-Kandidaten (nach Stratifizierung) | **200** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **200** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **198** |
| Neu angenommene Feed-Dateien | **2** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **154** |
| Abgelehnte Repositories (dieser Run) | **198** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **156** |
| IPs in seen_db bestätigt | **2541492** |
| Neue IPs eingetragen | **373296** |
| seen_db gesamt | **11,147,244** |
| HQ-Referenz-IPs (6 Quellen) | **130696** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Sonstige | **156** |
| IP-Datei veraltet (>30d) | **22** |
| Repo zu alt (>30d) | **11** |
| Falsche Größe (<100 / >2,000,000 IPs) | **8** |
| False-Positive-Rate zu hoch (>5%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `makarson_daily_phishing_feed` | [makarson/Daily-Phishing-Feed](https://github.com/makarson/Daily-Phishing-Feed) | GITHUB | 17,167 | 4.2% | 0.0% | 1 | 🆕 NEU |
| `toxyl_ossh_swarm_wordlists` | [toxyl/ossh-swarm-wordlists](https://github.com/toxyl/ossh-swarm-wordlists) | GITHUB | 17,864 | 68.4% | 0.0% | 1 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `mrwadams/attackgen` | GITHUB | Größe: 4 IPs |
| `D4-project/d4-core` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cifertech/ESP32-DIV` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Dancas93/SSRF-Scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mypdns/matrix` | GITHUB | IP-Datei 475d alt |
| `malwaredb/malwaredb-rs` | GITHUB | Größe: 0 IPs |
| `MISP/misp-taxonomies` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MISP/misp-galaxy` | GITHUB | Größe: 0 IPs |
| `thalesgroup-cert/Watcher` | GITHUB | IP-Datei 78d alt |
| `mentat-is/gulp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Security-Onion-Solutions/securityonion` | GITHUB | IP-Datei 1092d alt |
| `SIA-IOTechnology/Kittysploit-framework` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pcaversaccio/malleable-signatures` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GhostTroops/TOP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FrizzleM/SideInstaller` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NiREvil/vless` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `2dust/v2rayN` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wazuh/wazuh-documentation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vscodev/XArchiver` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vigolium/vigolium` | GITHUB | IP-Datei 52d alt |
| `filipi86/drogonsec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sec0ps/va-pt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Quang-Minh-Phung/DienTu_TKVM_Documents` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0dayInc/pwn` | GITHUB | IP-Datei 819d alt |
| `pzaino/thecrowler` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aziontech/azion-console-kit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FWGS/xash3d-fwgs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vulnerability-lookup/vulnerability-lookup` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `guacsec/trustify` | GITHUB | IP-Datei 210d alt |
| `Galeax/CVE2CAPEC` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JMousqueton/github-cve-monitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `olbat/nvdcve` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lord-alfred/ipranges` | GITHUB | FP-Rate: 97.0% |
| `dedsec1121fk/DedSec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HolmesGPT/holmesgpt` | GITHUB | IP-Datei 229d alt |
| `ongridio/ongrid` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dfroberg/cluster` | GITHUB | IP-Datei 1765d alt |
| `righettod/website-passive-reconnaissance` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RavinduRathnayaka/LiveThreatMap-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `truelockmc/Discord-RAT` | GITHUB | Zu alt: 56d |
| `microlinkhq/is-antibot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kinomakino/ransomware_file_extensions` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wallarm/product-documentation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vmayoral/ExploitFlow` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `H3llKa1ser/SOC-Assistant-Guide` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `oscaromeu/home-ops` | GITHUB | IP-Datei 92d alt |
| `laitoxx/Laitoxx-Multi-Tool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `skka3134/Free-servers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nsasoft/nsauditor-ai` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ArtemioPadilla/watchboard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tholinka/home-ops` | GITHUB | IP-Datei 192d alt |
| `BC100Dev/OsintgramCXX` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BragatteMAS/os-postinstall-scripts` | GITHUB | IP-Datei 68d alt |
| `quodeq/quodeq` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AthenaNetworks/mymate` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shlin168/go-nvd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `muchdogesec/cve2stix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yuceltoluyag/GoodProxy` | GITHUB | IP-Datei 806d alt |
| `kidrek/VigilIntel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eye-wave/spotify-ai-blocklist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SobralCybersec/APIKeyScanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `myeongjae-kim/inversify-typesafe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CoolCat467/Scanner-Server` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `muchdogesec/vulmatch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `k37y/gvs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SilentProgrammer-max/Ayesha-osint-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `muchdogesec/txt2detection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SecurityRonin/issen` | GITHUB | Größe: 0 IPs |
| `aquace/CVE-2026-41940-PoC` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `turulomio/devicesinlan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `oneclickvirt/webvirtcloud` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Jonaskouame/Phone-Number-Tracker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mmontes11/k8s-tooling` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `triconinfotech/shai-hulud-malicious-packages` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jeonghanlee/epics-ioc-runner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jacubes/CVE-2026-24061` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `taynotfound/Node-Mail-Spammer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NITISHMG/talos-hetzner-k8s` | GITHUB | Zu alt: 57d |
| `speatzle/nfsense` | GITHUB | IP-Datei 45d alt |
| `lopes/lantana` | GITHUB | IP-Datei 46d alt |
| `sjinks/node-modsecurity` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dadevel/http-spray` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JY-666-YINZI/Strix-Kali-AI-PoweredPentestFramework` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `duriantaco/ca9` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `stevewm/homelab` | GITHUB | IP-Datei 51d alt |
| `jwidess/OPNsense-node-exporter-smartctl-collect` | GITHUB | Zu alt: 58d |
| `i-am-unbekannt/BLITZPROXY` | GITHUB | IP-Datei 358d alt |
| `TITAN-Softwork-Solutions/Vigil` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dev0root6/zuzumako` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Filearsip/wapp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kylefoxaustin/qemu-imx95` | GITHUB | IP-Datei 70d alt |
| `MEET-UC/seithar-research` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sanks205/getobserver` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `incogbyte/wp-cve-exploits` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `leconio/knockport` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `muchdogesec/arango_cve_processor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jdwlabs/infrastructure` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vaughnw128/immanent-grove` | GITHUB | IP-Datei 107d alt |
| `spidermila/mikrotik_update` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yb85/aglaia` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SuperMarioYL/agentguard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `R3LI4NT/http-tester` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `STBobcat/Bobcat-Proxy-xray` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `winchsortir92/crypto-wallet-bruteforce` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Glyndor/helmly` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SOsintOps/Wukong` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `andyydz/TryHackMe-Writeups` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ryanshrier/blueteam` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AdityaBhatt3010/SOC-Workbooks-and-Lookups` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Joowonoil/LumiMax` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pedrodeivid/osint-resources` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `davidharrigan/home-ops` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `davydehaas98/homelab` | GITHUB | IP-Datei 181d alt |
| `tylerrosnett/homelab` | GITHUB | IP-Datei 57d alt |
| `NavySigma/parkir-digital` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Aqmar777/openclaw-competitive-intel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `canterbury-air-patrol/flight-safety-system` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mar0ls/censys_go` | GITHUB | Zu alt: 145d |
| `OmarRao/secure-scope` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SreejaPuthan/ICEBERG-Threat-Intel-updator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `matteobaccan/FolderCtl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bryopsida/the-watcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `particlelevel/uBlacklist-fake-shops-german` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DereC4/CoreProtect-Blacklist-Settings` | GITHUB | Größe: 0 IPs |
| `SyrusKyury/Yu-Gi-Oh-Tag-Force-Banlist-Maker` | GITHUB | Zu alt: 518d |
| `zentinelproxy/zentinel-agent-denylist` | GITHUB | Zu alt: 93d |
| `alexar76/aimarket-plugins` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Rumblingb/agent-passport-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nohypelabs/AILisency` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HMAKT99/Erabi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `azeth-protocol/cli` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `andysalvo/agentrank` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ASMRoyal/Vouch.` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `unidel2035/gift-onto` | GITHUB | Zu alt: 36d |
| `ArisRhiannon/goodfaith` | GITHUB | Zu alt: 44d |
| `RunTimeAdmin/Countersig-Public` | GITHUB | Zu alt: 49d |
| `Silakos1/Codex-Windows` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `myguard-labs/mailstrix` | GITHUB | Größe: 0 IPs |
| `racckzygot/CraxsRAT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `muchdogesec/ransomware2stix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `abdelrahman835/PhishShield` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cw-l/email-corpus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PWNSTXR69/PhishLens` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cev-api/pycrypt-cracker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `codelassey/scripts-and-tools` | GITHUB | IP-Datei 396d alt |
| `cybercode-dev/HawkEye-Cyber-Log-Analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bugfishtm/windows-hash-cracker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `iamx-ariful-islam/PathQ` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TEX479/calculate-it-solver` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HiennNek/faac-slh-seed-recovery` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Mqtth3w/electrum-brute-force` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `emirberasoguk/Pi-Cracker` | GITHUB | Zu alt: 34d |
| `robotomize/t2r` | GITHUB | Zu alt: 882d |
| `aettern/canary` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Novasky-Guy/GhostTTY` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GODofExploit/exploit-arsenal` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `optimesh-ai/rulehawk-demo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Peanutbutterwatersnake580/baddies-windows-script-hub` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `notedirequiensoyk-source/STACK-2026` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `diogotrodrigues/CivicEcho` | GITHUB | Größe: 0 IPs |
| `ciaomah/cyber_studies` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `therayyanawaz/TeleUserBot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `coredev-uk/home-ops` | GITHUB | Größe: 0 IPs |
| `TheSawkit/ReelMark` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `charlesbulabula/threat-intelligence-engine` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lxk36/xgc2-lichtblick-packaging` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `edygert/js_unshroud` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Yangtoinette/LAB-OSINT-Writeups` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gerezk/find-my-forensics` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `punkkid0/ramseverywhere_snipe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `taadithiya/phishing-email-investigation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `janpuc/home-ops` | GITHUB | IP-Datei 45d alt |
| `momo840505/cyber-risk-intelligence-lakehouse` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tony11301130/shigure-edr` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FAlhumaid/DFIR_Radar_RSS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cplieger/docker-caddy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ThinkEx-OSS/tracer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sulthonzh/portscan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `soenneker/soenneker.cloudflare.origincerts.fetcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ezphongdo-cmyk/guardvibe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sodaashdaylightsavingtime830/zyphor_os` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thrifty-consonance737/ninjaXRF` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bayvapourisable154/Stratum` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `andyssm/Volans-Map` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Dhruv00098/sherlock` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fried-headlock977/WraithRun` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `epsi12-lab/gns3-infra-securisee` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Bettot2829/fix-camera-apps-script-barcode-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `isandr2865/infram` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `garboiluniversity170/nessus-to-excel-nte` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Gerberayale521/pwnkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `unbraced-poultry941/HomeLab-VLAN-Refactor-Community` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alessandratriennial716/blog_hacking` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `uneven-freightage871/mod_doscontrol` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bored-patentapplication930/StarStrings` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `cbuijs_hagezi` | GITHUB | 51,845 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 22,954 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 16,529 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 2,974 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 5,060 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 665 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 18,364 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 464 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 253 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,628 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,811 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,679 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 2,207 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 5,829 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 5,305 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https_anonymous` | GITHUB | 5,302 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 5,048 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,555 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 1,003 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 968 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 830 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 439 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 24,831 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 5,206 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 3,508 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,449 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 7,007 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 5,155 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,460 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 197,730 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 3,817 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,130 | 2.6% | 116 | 2026-07-05 |
| `mohammedcha_proxripper` | GITHUB | 54,926 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,746 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 118,433 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,162 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 82,151 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,368 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 80,740 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 100,536 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,437 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 111,029 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 114,390 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 666 | 36.7% | 8 | 2026-07-03 |
| `darzanebor_mikroblack` | GITHUB | 42,108 | 26.6% | 13 | 2026-07-05 |
| `eshlomo1_cloudsec` | GITHUB | 4,331 | 10.5% | 10 | 2026-07-11 |
| `ankaboot_source_email_open_data` | GITHUB | 498,393 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,504 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,152 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 171,023 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 137,675 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 103,971 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 80,966 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 91,691 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_30d` | GITHUB | 84,272 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 78,567 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 74,975 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 44,442 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_15d` | GITHUB | 52,425 | 47.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 48,954 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 29,102 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 20,575 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 28,483 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,954 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 17,151 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 14,749 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 23,470 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 14,122 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 12,624 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 10,579 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 10,616 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 12,722 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 6,853 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,320 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 5,874 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 4,629 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,531 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 5,103 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 4,578 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,893 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 1,393 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,939 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 50,097 | 39.0% | 10 | 2026-07-12 |
| `ian_lusule_proxies` | GITHUB | 4,097 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,730 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 673 | 17.2% | 9 | 2026-07-08 |
| `celestialbrain_worldpool` | GITHUB | 81,693 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 336,307 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 5,923 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,052 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 4,680 | 2.6% | 7 | 2026-07-04 |
| `realizelol_torblocklist` | GITHUB | 1,523 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 36 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 55,666 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 65,783 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,805 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 95 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 195,729 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,515 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,673 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 7,401 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 7,695 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 166,669 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,056 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 17,167 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 17,864 | 68.4% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 49,534 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 47,213 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,394 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 104,662 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 458 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,167 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 191,782 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,478 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 104,748 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 125,264 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,239 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 32,624 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 21,061 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 16,603 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,789 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 7,831 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 8,036 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cps_abusech` | GITHUB | 7,607 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,689 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,288 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,212 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,941 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,117 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,525 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 3,224 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,841 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 1,543 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,959 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,949 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,958 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_socks_proxy_7d` | GITHUB | 1,535 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,389 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,315 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,236 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,224 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,058 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 980 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 998 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 979 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 856 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 934 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 886 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 773 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 737 | 40.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 729 | 41.2% | 0 | 2026-07-05 |

---
*Generiert: 2026-07-14 15:19 UTC*