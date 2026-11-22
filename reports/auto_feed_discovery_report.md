# Auto Feed Discovery – Report
**Aktualisiert:** 2026-11-22 13:50 CET (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 4 |
| Kandidaten gesamt | **11667** |
| davon GitHub (Topics+Code) | **11583** |
| davon GitLab | **84** |
| davon Awesome-Lists | **2406** |
| Tools/Libraries vor Eval gefiltert | **1705** |
| davon Hard-Reject (awesome-Liste etc.) | **183** |
| EVAL-Kandidaten (nach Stratifizierung) | **462** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **462** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **460** |
| Neu angenommene Feed-Dateien | **6** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **184** |
| Abgelehnte Repositories (dieser Run) | **460** |
| davon GitLab abgelehnt | **2** |
| Feeds gesamt (aktiv) | **190** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **19017** |
| SQLite-Refresh-Cache-Hits | **0/187** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **387** |
| Falsche Größe (<30 / >2,000,000 IPs) | **25** |
| Repo zu alt (>30d) | **24** |
| IP-Datei veraltet (>30d) | **19** |
| Overlap mit HQ-Feeds zu gering (<20%) | **4** |
| False-Positive-Rate zu hoch (>5%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist_emerging_threats` | [alsyundawy/mikrotik-blacklist](https://github.com/alsyundawy/mikrotik-blacklist) | GITHUB | 584 | 19.0% | 0.0% | 49 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 185,023 | 1.6% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 14,767 | 19.8% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_bruteforceblocker` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 586 | 32.4% | 0.0% | 0 | 🆕 NEU |
| `stamparm_maltrail` | [stamparm/maltrail](https://github.com/stamparm/maltrail) | GITHUB | 16,845 | 2.4% | 0.0% | 8661 | 🆕 NEU |
| `criticalpathsecurity_zeek_intelligence_feeds` | [CriticalPathSecurity/Zeek-Intelligence-Feeds](https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds) | GITHUB | 886 | 42.0% | 0.0% | 407 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `firehol/iprange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `offseq/threat-finder` | GITHUB | Größe: 0 IPs |
| `davidonzo/Threat-Intel` | GITHUB | Zu alt: 765d |
| `rix4uni/medium-writeups` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThreatDefence/agentic-attack-detections` | GITHUB | Overlap zu gering: 0.0% |
| `kaifcodec/user-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rix4uni/cvemapping` | GITHUB | IP-Datei 560d alt |
| `1276486/ZERO-X-Bypass-Jailbreak` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nukeratframework/nukerat` | GITHUB | Größe: 0 IPs |
| `kamalx06/TornadoC2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgamec2framework/endgame` | GITHUB | Zu alt: 47d |
| `mwakidenis/mwakidenis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aiperceivable/apexe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kyle-parkeng05b3/subnautica-2-ue5-console-bridge-biome-portable-x64` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `k8gege/K8tools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frontendnetwork/veganify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `5rahim/seanime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `87owo/PYAS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `justcallmekoko/ESP32Marauder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nyxgeek/ntlmscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yogeshojha/rengine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafafunt/FalconSDR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chuot/rdio-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SUBIR33/sbft-bip39-brute-force-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maxgfr/brutifi` | GITHUB | Zu alt: 52d |
| `dandye/adk_runbooks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SackOfHacks/ICS-PCAP-Challenges` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `okanyildiz/WindowsSecurityAudit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `H3llKa1ser/SOC-Assistant-Guide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OISF/suricata` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cyb3rmik3/KQL-threat-hunting-queries` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `awalsh128/cache-apt-pkgs-action` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typedb/bazel-distribution` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neur0map/glazepkg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zbrateam/Zebra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jdnei/JiChangTuiJian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maximecs-web/enjoy-kids-sms-service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kirillskultan-art/Zemana-Threat-Defense-Suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xmwengxing/CFPilot` | GITHUB | Größe: 0 IPs |
| `Mr-Meshky/vify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `limbopro/JichangTuijian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bannedbook/fanqiang` | GITHUB | IP-Datei 2396d alt |
| `LoneKingCode/free-proxy-db` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Q7DF1/XrayFA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `youshandefeiyang/sub-web-modify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kenzok8/trojan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `praetorian-inc/brutus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GhostTroops/scan4all` | GITHUB | IP-Datei 1163d alt |
| `0xdea/tactical-exploitation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AsjadOooO/Zero-attacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SubleXBle/Fail2Ban-Report` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jasonish/docker-suricata` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jasonish/evebox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OISF/suricata-intel-index` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OISF/suricata-update` | GITHUB | IP-Datei 3307d alt |
| `mwakidenis/miktrotik-hotspot-billing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mwakidenis/Mpesa-Based_Wi-Fi-Hotspot_Billing_System` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AliKarami/MikroMCP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AthenaNetworks/mymate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tikoci/routeros-skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wiresage/mikrotik-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kzeedev/MTWireGuard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Csontikka/ha-mikrotik-extended` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mark99i/WinboxPatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amd989/unifi-gateway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `levi-xy/vantage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jaymzh/iptstate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zywe03/realm-xwPF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexhaydock/pinewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `network-evolution/ansible_masterclass` | GITHUB | Zu alt: 227d |
| `nathanaeleyd/monero-miner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Katastrofa0/GOD-OF-RAT` | GITHUB | Zu alt: 138d |
| `fyvri/fresh-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rix4uni/fresh-proxy-list` | GITHUB | Overlap zu gering: 0.0% |
| `Surfboardv2ray/TGParse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yourworstnightmare1/proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `por-cli/por-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maximilianfeix/proxy-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Flatdatrellis/clion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SailorMo0nEpic/soc-automation-update-channel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `retroSoC/retroSoC` | GITHUB | IP-Datei 113d alt |
| `mahialjaber/SOC-Log-Analysis-Datasets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splinedrive/kianRiscV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rix4uni/scope` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pzaino/thecrowler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NYBaywatch/AgrusScanner` | GITHUB | IP-Datei 65d alt |
| `praetorian-inc/nerva` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `praetorian-inc/julius` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s41r4j/phomber` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `letox4/OsintHunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KatrielMoses/MailAccess` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Doble-2/osint-d2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `S3N4T0R-0X0/BEAR-C2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbe2277/waf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `imperva/terraform-provider-incapsula` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ADD-SP/ngx_waf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microlinkhq/is-antibot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jx-sec/jxwaf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nillerusr/source-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rwx-G/Lorica` | GITHUB | IP-Datei 39d alt |
| `fabriziosalmi/secure-proxy-manager` | GITHUB | IP-Datei 112d alt |
| `github/github-well-architected` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fabriziosalmi/patterns` | GITHUB | IP-Datei 35d alt |
| `Ringmast4r/OUI-Master-Database` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UserJoo9/QuotaManager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aabyss-Team/Threat-Broadcast-Plus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kookiejarz/Auto_XDP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `donislawdev/BeanNetworkTester` | GITHUB | Größe: 0 IPs |
| `kalachbeg/Hearthscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `secdev/scapy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gojue/ecapture` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NexSideloading/certificates` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `github/codeql-coding-standards` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bdg9412/artex-ko-plus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EMS-TU-Ilmenau/isac-uav-dataset` | GITHUB | Zu alt: 809d |
| `EnableSecurity/wafw00f` | GITHUB | Zu alt: 217d |
| `teler-sh/teler-proxy` | GITHUB | Zu alt: 636d |
| `USBBios/Joker-Mirai-Botnet-Source-V1` | GITHUB | Zu alt: 1346d |
| `lion001am/Condi-Mirai` | GITHUB | Zu alt: 1564d |
| `weird1337/Stanley` | GITHUB | Zu alt: 1694d |
| `dealfluence/adeu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JSv4/Docxodus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kklimuk/docx-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rjmahesh/ui-redline-walkthrough` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JSv4/Python-Redlines` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kizubenda/NjRAT-ShadowEdge-Controller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ariafatah0711/HPone` | GITHUB | Zu alt: 236d |
| `PowerDNS/weakforced` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wolfSSL/documentation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `libellux/Libellux-Up-and-Running` | GITHUB | Zu alt: 331d |
| `DOWRIGHTTV/dnxfirewall` | GITHUB | Zu alt: 371d |
| `ipinfo/sample-database` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NetworkCats/OpenProxyDB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ecstatic-nobel/OSweep` | GITHUB | Zu alt: 2126d |
| `kashalls/infrastructure` | GITHUB | IP-Datei 174d alt |
| `devantler-tech/ksail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zimmertr/TJs-Kubernetes-Service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `siderolabs/extensions` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `home-operations/tuppr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `toboshii/home-ops` | GITHUB | IP-Datei 1583d alt |
| `frecklelabs/k8s` | GITHUB | Größe: 0 IPs |
| `prateekjaindev/homelab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kubehenge/kubehenge` | GITHUB | IP-Datei 32d alt |
| `hcloud-k8s/terraform-hcloud-kubernetes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hcloud-talos/terraform-hcloud-talos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `siderolabs/discovery-service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MacroPower/homelab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Terra-Online/Atlos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carpenike/k8s-gitops` | GITHUB | IP-Datei 727d alt |
| `rgl/terraform-proxmox-talos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rgl/terraform-libvirt-talos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BootedUp420/TCPDOMINATE2024` | GITHUB | Zu alt: 676d |
| `Ghost-crypto-exe/2018-Malware-Repository` | GITHUB | Zu alt: 1034d |
| `unkn0wnh4ckr/hackers-tool-kit` | GITHUB | Zu alt: 1974d |
| `lulzddos/Lulzddos` | GITHUB | Zu alt: 152d |
| `akashblackhat/DDos_Attack.py` | GITHUB | Zu alt: 526d |
| `HC133/Pummel` | GITHUB | Zu alt: 547d |
| `isPique/Net-Strike` | GITHUB | Zu alt: 547d |
| `nayumiDEV/cc-ddos` | GITHUB | Zu alt: 580d |
| `Leeon123/CC-attack` | GITHUB | Zu alt: 1134d |
| `Neo23x0/yarGen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atiilla/OsintEye` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `megadose/toutatis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nox-project/nox-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaifcodec/user-scanner.git` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `l4rm4nd/LinkedInDumper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zenkdom/parse-everything-global` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NPCmillionaire/govint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khast3x/h8mail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thewhiteh4t/nexfil` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spmedia/Telegram-Channel-Joiner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qeeqbox/social-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JMarchiori13/osint-recon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/instagram_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/spotify_profile_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `megadose/holehe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XD-MHLOO/facebook-gql-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `david3107/squatm3gator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yt-dlp/yt-dlp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amnottdevv/atdork` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `renkagod/tg-chat-dump` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/lol_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atiilla/geospy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NPCmillionaire/capitol-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s0md3v/Orbit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XD-MHLOO/Osintgraph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/BuscaPaginasBlancas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `finos/perspective` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/spotify_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3nock/SpiderSuite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tsale/TeleTracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tg12/phantomtide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Datalux/Osintgram` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `obitouka/InstagramPrivSniffer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mxrch/GHunt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s0md3v/Photon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tejado/telegram-nearby-map` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ElevenPaths/FOCA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kpcyrd/sn0int` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shadawck/glit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KatrielMoses/voidaccess` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `etsy/morgue` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rizinorg/rizin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mbevilacqua/appcompatprocessor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `halpomeranz/lmg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `guardsight/gsvsoc_cirt-playbook-battle-cards` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `viper-framework/viper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ridgelinecyberdefence/vanguard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PagerDuty/incident-response-docs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cyb3rfox/Aurora-Incident-Response` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TonyPhipps/Meerkat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/stenographer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/Raccine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aws-samples/aws-incident-response-runbooks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yamato-Security/WELA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microsoft/avml` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diogo-fernan/domfind` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `muteb/Hoarder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `certsocietegenerale/IRM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PowerShellMafia/CimSweep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ForensicArtifacts/artifacts-kb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DFIR-ORC/dfir-orc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `volatilityfoundation/volatility3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sandialabs/scot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `504ensicsLabs/LiME` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fox-it/acquire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ForensicArtifacts/artifacts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jymcheong/AutoTTP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alphasoc/flightsim` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `biggiesmallsAG/nightHawkResponse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SekoiaLab/Fastir_Collector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JPCERTCC/MalConfScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `forensicanalysis/artifactcollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rough007/CDQR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AJMartel/IRTriage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MagnetForensics/dumpit-linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `defpoint/threat_note` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `counteractive/incident-response-plan-template` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/timesketch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JPCERTCC/LogonTracer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `log2timeline/dftimewolf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MutableSecurity/mutablesecurity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swisscom/PowerGRR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rizinorg/cutter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SekoiaLab/Fastir_Collector_Linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uber-common/metta` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `davehull/Kansa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nogoodconfig/pyarascanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TryCatchHCF/DumpsterFire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mwielgoszewski/doorman` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/CIRTKit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `obsidianforensics/hindsight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/munin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NextronSystems/APTSimulator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DFIRKuiper/Kuiper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zdhenard42/SOC-Multitool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keydet89/RegRipper3.0` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rough007/CCF-VM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlmCo/Panorama` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ralphje/imagemounter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ufrisk/MemProcFS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mkorman90/VolatilityBot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swisscom/PowerSponse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alpine-sec/SPECTR3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Security-Onion-Solutions/security-onion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frikky/Shuffle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre/caldera` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jipegit/OSXAuditor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wagga40/Zircolite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Invoke-IR/PowerForensics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityBrewery/catalyst` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gfoss/PSRecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yelp/osxcollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `orlikoski/CyLR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CIRCL/traceroute-circl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `redhuntlabs/RedHunt-OS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/RTA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThreatResponse/margaritashotgun` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sbousseaden/EVTX-ATTACK-SAMPLES` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mgreen27/Invoke-LiveResponse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:alexs77/nieuwe-winkel.nl` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:Roxanne_Ardary/contextkernel` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `silvanalig95-cmd/Rimworld-Helper` | GITHUB | Größe: 0 IPs |
| `takenthatusernameis-collab/Quantitative-Breakout-Trading-Strategy-Research-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Eclipse-Intelligence/orbit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yunusarda-sudo/mcp-benchmark` | GITHUB | Größe: 0 IPs |
| `bahadirdogru/bdhtml2pdf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zerwiz/ymir` | GITHUB | Größe: 0 IPs |
| `cryptobones-1337/deR4Tizer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `belal2274/onyx-protection-system` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `conmeophat/Tao_trang_web_bang_cach_keo_tha` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kanaiya-rgb/Dhvani-Music` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fkalfopoulos/attack-surface-mapper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ranggalazuardy-source/aura-autopilot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `async-digital-ltd/seen-to-fail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kyamixdd/Black-Market-AI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiyasitomato/vaultstream` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `scobru/radica` | GITHUB | Größe: 0 IPs |
| `AlejoMalia/Totemheart` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iamtanzir/iamtanzir` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maizshaikh21/MailMind-AI-Extension` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `garashov/k8s-ckad-exam-prep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SvejeDobro/bulkbird-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eamax-code/provenance` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JohnPerez012/Digital-Undergraduate-Theses-Repository-with-RAG-Search-at-Cebu-Technological-University-Library` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sabersmash1412/singapore-internship-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zees-games/game-hungario` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zyvorai/zyvor-kubeflight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mariamaher86-svg/soty` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ShreyasLohiaFR/Fintrack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IAM-GROOT1/ctrlz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Praveen1223456/sahaya-setu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mvp2o-ai/cuttingfloor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nomoreroses/DigSpill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Psalmuel01/contract-zero` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `utkarshsingh23-byte/iot-anomaly-detection-rag` | GITHUB | Größe: 0 IPs |
| `JSXiaoJun/new-api-usdt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `plagor44-ux/pi-session-mcp` | GITHUB | IP-Datei 36d alt |
| `capsulebin/capsulebin` | GITHUB | Größe: 0 IPs |
| `hospitalpro26/slashpromo-site` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `balaji87-z/kortex-shield` | GITHUB | Größe: 0 IPs |
| `benjamin-gaultier/rue-par-rue` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Remi-Petit/easybook` | GITHUB | Größe: 0 IPs |
| `kirisaki/phase-vector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Trillion-X/trillion-workshop` | GITHUB | Größe: 0 IPs |
| `zyvorai/zyvor-duvora` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ora/ax` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `duckietm/All-in-1-Manager` | GITHUB | Größe: 0 IPs |
| `getgroupmy/iakauntan` | GITHUB | IP-Datei 96d alt |
| `piyushmakhija28/ai-link-analysis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AFG-design/FPL-Lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `What-if-Ajeeb/Orbit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xp-provider-factory/crossplane-update-tester` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Anexseus/WalkMap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JebetrexxMC/wagu` | GITHUB | Größe: 0 IPs |
| `gigabytegrove/spamgate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0peng/yaqiz-releases` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sreenandhan-17/Agent-project-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jordanlegare/uefi-browser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jamillaaninang57-sys/cafeteria-preorder.` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `punithkumarab/CropShield-AI_2_` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `techeethan46-dev/Discord-event-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rathanhimakarvanguri/india-day-trader-skill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rjdunlap/neo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ImGhost7/portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neo-wabow/security-blocklist` | GITHUB | Overlap zu gering: 0.7% |
| `dailizer33-cloud/TAYJAY` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MEZTKING/Minecraft-Server-Master` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KazuhaHub/rackbook` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Maik-Huebner/intrusion-detection-mlops` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nredd/pi-harness` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lonion-1/WhaleGuard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `empresacontalo/ecommerce_demo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aimen-ansari/tactical-ecomerce-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jiangxianyan/tafeiyu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mryandexxx-spec/lifesim-prototype` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ftymoshchuk/sotnia` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AleonSC/Top-down-arena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benscha/ClickFixObserver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VivekS51/NyayaSetu-India` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ehammer1/Mandate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `prakash200627/BugHawk-AI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `espolo/cyber-info` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oldhawk007xd/oldhawk-line` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GoDxVictoryRR/HGA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Choffolo/spikes402` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SaiKaligotla/Cyberpulse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Galaxys22702/streetwise-connection-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enadot/mosheedri` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bytecoinBCN-community/bcn-stats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `forke-org/forke-mail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `despresnicolas/limier` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nathan-NLB/vie-watcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ersinkoc/Agora` | GITHUB | Größe: 0 IPs |
| `Mezfinance/Tradingbot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AldrinCleetus/jason` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kk161205/Rosterly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ferroxdev/ferrox` | GITHUB | Größe: 0 IPs |
| `norik-jusufi/Prism` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jaso69/obd2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arc-depth/arc-depth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `damoateng1989-star/hub-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nimsek90-ops/jayesh-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kingdaniel4747/openote` | GITHUB | IP-Datei 35d alt |
| `vecfonds/ai-engineering-from-scratch` | GITHUB | IP-Datei 44d alt |
| `marketscanner247/crypto-grabber` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thedestoroyah/NeuroDiagnosisAI_Sangtaotre` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kotivahdit/kotivahdit.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lumieregiurare-ops/newsites` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlonsoLP/HUDnopy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jack-Hwang/beyondthesecurity-sbom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bert1041/World-Emotion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `B23DCAT011/reconkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tekelioglu-a/tim` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Adityaakr/proteus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tanguille/cluster` | GITHUB | Größe: 0 IPs |
| `SaadAzil3/IntelScope` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sykt-org/threat-ip-list` | GITHUB | Overlap zu gering: 0.0% |
| `platanus-hack/platanus-hack-26-cl-team-20` | GITHUB | Größe: 0 IPs |
| `andy489/online-bookstore-service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vile-sudo/deep-microcap-screener` | GITHUB | IP-Datei 57d alt |
| `kimmj1234/plugin-hub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sothis/fenestal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `openbashok/attack-vectors` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khzaw/rangoonpulse` | GITHUB | IP-Datei 66d alt |
| `sendotjiam/zest` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `scottnarmstrong/QED-dev` | GITHUB | Größe: 0 IPs |
| `AgwambaFavour/CheckMe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `binyamindavid/inyovis-safe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kenono2000/enterprise-rag-pgvector-rbac` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `purinisowmya-cell/ZK-Trust` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `getgroupmy/get.suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ulasislak/corivometals` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `studyfranco/simply_fw_rules_manager` | GITHUB | FP-Rate: 13.3% |
| `hollingswood/nfl-win-probability` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VoHoang07/tool_scan_video_tiktok` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `go-fleettools/fleettools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XidT01/Solana-Trading-Agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rudycelekli/rudycelekli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JanuszPelc/my-feeds` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `phycoforce/home-ops` | GITHUB | Größe: 0 IPs |
| `q7xk/q7-chat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `droplinxuser/ubuntu-setup-script` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ganyanentsiyeni-rgb/RYANAI-Automous-Reasioning-Plat-main` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Agentboxx-dev/Agentboxx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kiro457/nyxarisHubAuth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ainunizhar/Ransomware-Claim-Triage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Boym323/Meteo_audit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tiaratatyanadewi/cyber-security-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vimalkumarbatchu09/CSP-CYBER-SURAKSHA-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `282610325/jobpilot-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `masanori-satake/Signboard-Duo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaomei/stickman-video-director` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mv89-heb/eli-cohen-business-mvp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jhz1053962051-sketch/billiards-ai-coach` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Pixelated2/Lucy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `klyrostack/browse-clean` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yoman12357/Software_Engineering_Project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sattle-tech/sattle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aliou27/soc-homelab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `denniskeefe/papertiger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `V7-Awad/Moros-Ai-Agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `damianospap/winharden` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fnoufnou/qorewitness` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Coastrnaut/VisualCore` | GITHUB | Größe: 0 IPs |
| `techgenius1/tvOS-Launcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `harifaka/kodo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `17yyamada-tech/dealwire_dailyupdate` | GITHUB | Größe: 0 IPs |
| `Degas01/tensorphysics-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-emulators` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bazsi-2006/vm-panel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hrabanazviking/RuneForgeAI-Samverk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gtzapper/jarvis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DeveloperPuneet/Crowdwide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aqr325/BaiZe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `infinityabundance/openssl-rs` | GITHUB | Größe: 0 IPs |
| `znlgis/dsh-video-studio-skill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Trisha-SWE/QA-AI-Testing-Skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `akoffice933-maker/pto-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `richardstartin/instructive` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 22,569 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,078 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 8,506 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 5,077 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,813 | 0.2% | 120 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,970 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 4,485 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 627 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,184 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 621 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 576 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 475 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 311 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,974 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,974 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 20,600 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 14,321 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 7,063 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 5,430 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 7,415 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 217,405 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 5,455 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 7,678 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,634 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 5,010 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 32,722 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 4,650 | 64.3% | 938 | 2026-09-04 |
| `cbuijs_hagezi` | GITHUB | 30,660 | 37.9% | 129 | 2026-11-08 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 584 | 19.0% | 49 | 2026-11-22 |
| `stamparm_maltrail` | GITHUB | 16,845 | 2.4% | 8661 | 2026-11-22 |
| `criticalpathsecurity_zeek_intelligence_feeds` | GITHUB | 886 | 42.0% | 407 | 2026-11-22 |
| `mohammedcha_proxripper` | GITHUB | 54,608 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,314 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 118,844 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 119,307 | 0.2% | 36 | 2026-07-05 |
| `telekom_security_listbot` | GITHUB | 533 | 10.4% | 22 | 2026-10-18 |
| `dinoz0rg_proxy_list` | GITHUB | 91,819 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,890 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 94,877 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 110,501 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 8,489 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 133,770 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 16,565 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 97,430 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 596 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 498,557 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 220,071 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 174,815 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 77,559 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 173,874 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 184,999 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 85,777 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 90,722 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 318,366 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 69,923 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 234,201 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 27,324 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 14,851 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 13,653 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 276,684 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,282 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,070 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,075 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 28,973 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 16,735 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 14,203 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 29,178 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 1,440 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,040 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,869 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,978 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 850 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 5,280 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 5,360 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,674 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,483 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 143,389 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 595 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 30,714 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 2,604 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 5,006 | 79.4% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 6,376 | 64.3% | 10 | 2026-10-11 |
| `ian_lusule_proxies` | GITHUB | 3,734 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,923 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,365 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 397,688 | 22.0% | 6 | 2026-07-08 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,408 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 30 | 97.4% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 107,085 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 23,385 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 75 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 105,959 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 4,437 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,746 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 75 | 28.1% | 2 | 2026-08-02 |
| `runtechx_dns_runtech_ao` | GITHUB | 20,774 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 31,547 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,429 | 31.1% | 1 | 2026-07-14 |
| `klonet_it_ip_threat_lists` | GITHUB | 140,599 | 51.5% | 1 | 2026-10-11 |
| `klonet_it_ip_threat_lists_blocklist_apache` | GITHUB | 9,099 | 9.7% | 1 | 2026-10-11 |
| `idleadmin_threatfeed` | GITHUB | 52,463 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 77,063 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,116 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 139,501 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,170 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 198,010 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 135,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 234,518 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 37,645 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 16,380 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 17,608 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,690 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 8,073 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,291 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,614 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 3,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,582 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,131 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,802 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,470 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 465 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 8,709 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,019 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,306 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 992 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 904 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 992 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,162 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 743 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,099 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,007 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,346 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 623 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,453 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,473 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,210 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 28,073 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,635 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 89,812 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 91,355 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 96,155 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 90,261 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 93,338 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 110,676 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,297 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 38,944 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,772 | 2.7% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 16,000 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 36,265 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 17,658 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 11,009 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 3,141 | 71.1% | 0 | 2026-08-12 |
| `zgzyh_malicious_website_detection` | GITHUB | 33,747 | 3.1% | 0 | 2026-08-15 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 7,129 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 18,279 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 6,365 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,579 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 1,318 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 489 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 227 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 16,813 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 95,012 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 95,215 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 94,609 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 91,990 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 97,063 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 36,746 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 6,009 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 5,944 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 1,985 | 76.9% | 0 | 2026-09-25 |
| `brandontroidl_blocklist_all_90d` | GITHUB | 6,583 | 61.9% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_aggressive` | GITHUB | 68 | 80.9% | 0 | 2026-10-11 |
| `helio4k_bad_ip` | GITHUB | 1,072 | 43.3% | 0 | 2026-10-25 |
| `verkombr_block_list_firewalls` | GITHUB | 948 | 46.9% | 0 | 2026-10-25 |
| `blawoblowa_blackened` | GITHUB | 1,501 | 56.0% | 0 | 2026-11-01 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 7,129 | 13.1% | 0 | 2026-11-08 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,220 | 69.7% | 0 | 2026-11-08 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 185,023 | 1.6% | 0 | 2026-11-22 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 14,767 | 19.8% | 0 | 2026-11-22 |
| `claudiusdecimius_ioc_ipsets_bruteforceblocker` | GITHUB | 586 | 32.4% | 0 | 2026-11-22 |

---
*Generiert: 2026-11-22 13:50 CET (Europe/Berlin)*