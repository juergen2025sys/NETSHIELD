# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-04 04:25 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7659** |
| davon GitHub (Topics+Code) | **7608** |
| davon GitLab | **51** |
| davon Awesome-Lists | **1016** |
| Tools/Libraries vor Eval gefiltert | **1293** |
| davon Hard-Reject (awesome-Liste etc.) | **141** |
| EVAL-Kandidaten (nach Stratifizierung) | **300** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluiert | **308** |
| Neu angenommen | **10** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feeds aktualisiert | **56** |
| Abgelehnt (dieser Run) | **298** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **66** |
| IPs in seen_db bestätigt | **1216628** |
| Neue IPs eingetragen | **43295** |
| seen_db gesamt | **5,755,927** |
| HQ-Referenz-IPs (6 Quellen) | **140920** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **227** |
| Repo zu alt (>30d) | **35** |
| IP-Datei veraltet (>30d) | **29** |
| Falsche Größe (<100 / >500k IPs) | **7** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_sblam` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,109 | 13.1% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 993 | 13.1% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 998 | 13.1% | 0.0% | 0 | 🆕 NEU |
| `cbuijs_hagezi` | [cbuijs/hagezi](https://github.com/cbuijs/hagezi) | GITHUB | 46,339 | 40.4% | 0.0% | 105 | 🆕 NEU |
| `alsyundawy_mikrotik_blacklist` | [alsyundawy/mikrotik-blacklist](https://github.com/alsyundawy/mikrotik-blacklist) | GITHUB | 48,653 | 1.8% | 0.0% | 49 | 🆕 NEU |
| `alsyundawy_mikrotik_blacklist_blocklist` | [alsyundawy/mikrotik-blacklist](https://github.com/alsyundawy/mikrotik-blacklist) | GITHUB | 24,962 | 1.8% | 0.0% | 49 | 🆕 NEU |
| `alsyundawy_mikrotik_blacklist_ipsum` | [alsyundawy/mikrotik-blacklist](https://github.com/alsyundawy/mikrotik-blacklist) | GITHUB | 15,067 | 1.8% | 0.0% | 49 | 🆕 NEU |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | [alsyundawy/mikrotik-blacklist](https://github.com/alsyundawy/mikrotik-blacklist) | GITHUB | 3,349 | 1.8% | 0.0% | 49 | 🆕 NEU |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | [alsyundawy/mikrotik-blacklist](https://github.com/alsyundawy/mikrotik-blacklist) | GITHUB | 4,626 | 1.8% | 0.0% | 49 | 🆕 NEU |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | [alsyundawy/mikrotik-blacklist](https://github.com/alsyundawy/mikrotik-blacklist) | GITHUB | 627 | 1.8% | 0.0% | 49 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `wolffcatskyy/crowdsec-blocklist-import` | GITHUB | Zu alt: 48d |
| `poddmo/ufw-blocklist` | GITHUB | Zu alt: 470d |
| `JasonLovesDoggo/caddy-defender` | GITHUB | Keine IP-Datei |
| `MISP/MISP` | GITHUB | IP-Datei 3620d alt |
| `muchdogesec/obstracts` | GITHUB | Keine IP-Datei |
| `kaifcodec/user-scanner` | GITHUB | Keine IP-Datei |
| `rix4uni/medium-writeups` | GITHUB | Keine IP-Datei |
| `CriticalPathSecurity/Zeek-Intelligence-Feeds` | GITHUB | Keine IP-Datei |
| `mthcht/ThreatIntel-Reports` | GITHUB | Keine IP-Datei |
| `osintph/threatintel-platform` | GITHUB | Keine IP-Datei |
| `ninoseki/mihari` | GITHUB | Keine IP-Datei |
| `OpenCTI-Platform/opencti` | GITHUB | IP-Datei 234d alt |
| `EndlessFractal/Threat-Intel-Feed` | GITHUB | Keine IP-Datei |
| `Bert-JanP/Open-Source-Threat-Intel-Feeds` | GITHUB | Keine IP-Datei |
| `deepfield/public-research` | GITHUB | Keine IP-Datei |
| `GreedyBear-Project/GreedyBear` | GITHUB | Keine IP-Datei |
| `IOCoin/DIONS` | GITHUB | Keine IP-Datei |
| `inversify/monorepo` | GITHUB | IP-Datei 253d alt |
| `abdullahbutt/deutsch-lernen-goethe-a1-c2` | GITHUB | Keine IP-Datei |
| `The-Z-Labs/bof-launcher` | GITHUB | Keine IP-Datei |
| `chainreactors/malice-network` | GITHUB | Keine IP-Datei |
| `nickvourd/SkyFall-Pack` | GITHUB | Keine IP-Datei |
| `spellshift/realm` | GITHUB | IP-Datei 49d alt |
| `chainreactors/malefic` | GITHUB | Größe: 0 IPs |
| `activecm/rita` | GITHUB | Keine IP-Datei |
| `BishopFox/sliver` | GITHUB | Zu alt: 31d |
| `CroodSolutions/BeaconatorC2` | GITHUB | Zu alt: 40d |
| `mwakidenis/mwakidenis` | GITHUB | Keine IP-Datei |
| `grisuno/LazyOwn` | GITHUB | IP-Datei 665d alt |
| `drcrypterdotru/warworm-stealer` | GITHUB | Keine IP-Datei |
| `epsylon/ufonet` | GITHUB | Zu alt: 37d |
| `Bialomazur/Brutus` | GITHUB | Zu alt: 55d |
| `Syn2Much/VisionC2` | GITHUB | Zu alt: 74d |
| `onionj/pybotnet` | GITHUB | Zu alt: 82d |
| `adysec/nuclei_poc` | GITHUB | IP-Datei 213d alt |
| `5rahim/seanime` | GITHUB | Keine IP-Datei |
| `horsicq/Detect-It-Easy` | GITHUB | Keine IP-Datei |
| `sefinek/UFW-AbuseIPDB-Reporter` | GITHUB | Keine IP-Datei |
| `romainmarcoux/malicious-hash` | GITHUB | Keine IP-Datei |
| `PBH-BTN/BTN-Collected-Rules` | GITHUB | Keine IP-Datei |
| `ipverse/as-ip-blocks` | GITHUB | Keine IP-Datei |
| `antoinevastel/avastel-bot-ips-lists` | GITHUB | Keine IP-Datei |
| `trick77/nftables-blacklist` | GITHUB | IP-Datei 56d alt |
| `Adamm00/IPSet_ASUS` | GITHUB | Keine IP-Datei |
| `maravento/blackip` | GITHUB | IP-Datei 368d alt |
| `K3V1991/Passing-SafetyNet-with-Magisk-Zygisk-and-DenyList` | GITHUB | Zu alt: 813d |
| `rainbowdashlabs/reputation-bot` | GITHUB | Keine IP-Datei |
| `toborrm9/malicious_extension_sentry` | GITHUB | Keine IP-Datei |
| `phishingclub/phishingclub` | GITHUB | Keine IP-Datei |
| `sublime-security/sublime-rules` | GITHUB | Größe: 0 IPs |
| `sublime-security/sublime-platform` | GITHUB | IP-Datei 1254d alt |
| `0xPugal/fuzz4bounty` | GITHUB | Keine IP-Datei |
| `vanhauser-thc/thc-hydra` | GITHUB | Keine IP-Datei |
| `jakka351/Ford-ECU-Bruteforcer` | GITHUB | Zu alt: 46d |
| `PHPAuth/PHPAuth` | GITHUB | Zu alt: 167d |
| `kulkansecurity/gitxray` | GITHUB | Zu alt: 176d |
| `r3bo0tbx1/tor-guard-relay` | GITHUB | IP-Datei 88d alt |
| `InnerWarden/innerwarden` | GITHUB | IP-Datei 98d alt |
| `djkurlander/knock-knock` | GITHUB | Keine IP-Datei |
| `RiskyMH/honeypot` | GITHUB | Keine IP-Datei |
| `cowrie/cowrie` | GITHUB | Keine IP-Datei |
| `bruneaug/DShield-SIEM` | GITHUB | IP-Datei 55d alt |
| `jasonxtn/Kraken` | GITHUB | Zu alt: 644d |
| `matricali/cbrutekrag` | GITHUB | Zu alt: 687d |
| `EntySec/Shreder` | GITHUB | Zu alt: 712d |
| `abusix/xarf` | GITHUB | IP-Datei 1410d alt |
| `elastic/detection-rules` | GITHUB | IP-Datei 64d alt |
| `utmstack/UTMStack` | GITHUB | Größe: 0 IPs |
| `JMousqueton/CTI-MSTeams-Bot` | GITHUB | Keine IP-Datei |
| `privtools/ransomposts` | GITHUB | Keine IP-Datei |
| `RansomLook/RansomLook` | GITHUB | Keine IP-Datei |
| `f6-dfir/Ransomware` | GITHUB | Größe: 2 IPs |
| `ThreatLabz/ransomware_notes` | GITHUB | Keine IP-Datei |
| `BushidoUK/Ransomware-Tool-Matrix` | GITHUB | Keine IP-Datei |
| `dmdhrumilmistry/pyhtools` | GITHUB | Keine IP-Datei |
| `AiGptCode/AiGPT-WordPress-Exploitation-Framework` | GITHUB | Zu alt: 36d |
| `TheDuffman85/linux-update-dashboard` | GITHUB | Keine IP-Datei |
| `kdeldycke/meta-package-manager` | GITHUB | Keine IP-Datei |
| `PatchMon/PatchMon` | GITHUB | Keine IP-Datei |
| `lbr38/repomanager` | GITHUB | Keine IP-Datei |
| `nccgroup/SteppingStones` | GITHUB | Keine IP-Datei |
| `D7EAD/mkPIVM` | GITHUB | Keine IP-Datei |
| `cisagov/ansible-role-cobalt-strike` | GITHUB | Keine IP-Datei |
| `nettitude/CLR-Stomp` | GITHUB | Zu alt: 45d |
| `memN0ps/doublepulsar-rs` | GITHUB | Zu alt: 51d |
| `dn9uy3n/Modern-Red-Team-Infrastructure` | GITHUB | Zu alt: 62d |
| `RedSiege/C2concealer` | GITHUB | Zu alt: 82d |
| `memN0ps/armory-rs` | GITHUB | Zu alt: 92d |
| `PhoenixC2/PhoenixC2` | GITHUB | Zu alt: 43d |
| `kpcyrd/authoscope` | GITHUB | Zu alt: 928d |
| `Laiteux/Milky` | GITHUB | Zu alt: 1656d |
| `Patrowl/PatrowlHearsData` | GITHUB | Keine IP-Datei |
| `GhostTroops/TOP` | GITHUB | Keine IP-Datei |
| `ycdxsb/PocOrExp_in_Github` | GITHUB | IP-Datei 1202d alt |
| `nomi-sec/PoC-in-GitHub` | GITHUB | Keine IP-Datei |
| `stanford-esrg/lzr` | GITHUB | Zu alt: 179d |
| `aleksibovellan/opnsense-suricata-nmaps` | GITHUB | Zu alt: 236d |
| `Charcoal-SE/SmokeDetector` | GITHUB | Keine IP-Datei |
| `pwlgrzs/Mikrotik-Blacklist` | GITHUB | Größe: 0 IPs |
| `katlogic/solana-arbitrage-bot` | GITHUB | Keine IP-Datei |
| `ebrasha/free-v2ray-public-list` | GITHUB | Keine IP-Datei |
| `Pawdroid/Free-servers` | GITHUB | Keine IP-Datei |
| `peasoft/NoMoreWalls` | GITHUB | Keine IP-Datei |
| `qr243vbi/nekobox` | GITHUB | Keine IP-Datei |
| `MKultra6969/MK_XRAYchecker` | GITHUB | Keine IP-Datei |
| `wazuh/wazuh-docker` | GITHUB | Keine IP-Datei |
| `sstklen/trump-code` | GITHUB | IP-Datei 111d alt |
| `chainreactors/zombie` | GITHUB | Keine IP-Datei |
| `skjolber/3d-bin-container-packing` | GITHUB | Keine IP-Datei |
| `CERT-Polska/Artemis` | GITHUB | Keine IP-Datei |
| `platformbuilds/SpamhausIPLists` | GITHUB | Zu alt: 858d |
| `spacepatcher/firehol-ip-aggregator` | GITHUB | Zu alt: 1277d |
| `0xtf/testmynids.org` | GITHUB | Zu alt: 1770d |
| `acepanel/panel` | GITHUB | Keine IP-Datei |
| `docker-mailserver/docker-mailserver` | GITHUB | Keine IP-Datei |
| `MHSanaei/3x-ui` | GITHUB | Keine IP-Datei |
| `tomMoulard/fail2ban` | GITHUB | Keine IP-Datei |
| `DigitalRuby/IPBan` | GITHUB | Keine IP-Datei |
| `crazy-max/docker-fail2ban` | GITHUB | Keine IP-Datei |
| `TheDuffman85/crowdsec-web-ui` | GITHUB | Keine IP-Datei |
| `maxlerebourg/crowdsec-bouncer-traefik-plugin` | GITHUB | Keine IP-Datei |
| `crowdsecurity/crowdsec-docs` | GITHUB | Keine IP-Datei |
| `hhftechnology/crowdsec_manager` | GITHUB | Keine IP-Datei |
| `jasonish/evebox` | GITHUB | Keine IP-Datei |
| `tenzir/tenzir` | GITHUB | IP-Datei 197d alt |
| `OISF/suricata` | GITHUB | Keine IP-Datei |
| `olegzhr/altprobe` | GITHUB | IP-Datei 57d alt |
| `cisagov/Malcolm` | GITHUB | IP-Datei 52d alt |
| `sous-chefs/snort` | GITHUB | Keine IP-Datei |
| `mwakidenis/Mpesa-Based_Wi-Fi-Hotspot_Billing_System` | GITHUB | Keine IP-Datei |
| `sakib-m/IP-Prefix-List` | GITHUB | Keine IP-Datei |
| `Davie3/mikrotik-cloudflare-iplist` | GITHUB | Keine IP-Datei |
| `rekryt/iplist` | GITHUB | Keine IP-Datei |
| `mirceanton/mikrotik-terraform` | GITHUB | Keine IP-Datei |
| `browningluke/terraform-provider-opnsense` | GITHUB | Keine IP-Datei |
| `browningluke/opnsense-go` | GITHUB | Keine IP-Datei |
| `O-X-L/ansible-opnsense` | GITHUB | IP-Datei 279d alt |
| `opnsense/docs` | GITHUB | Keine IP-Datei |
| `EvilBit-Labs/opnDossier` | GITHUB | Keine IP-Datei |
| `travisghansen/hass-opnsense` | GITHUB | Keine IP-Datei |
| `onzack/grafana-dashboards` | GITHUB | Keine IP-Datei |
| `AthennaMind/opnsense-exporter` | GITHUB | Zu alt: 38d |
| `pfrest/pfSense-pkg-RESTAPI` | GITHUB | Keine IP-Datei |
| `mbierman/Firewalla-NextDNS-CLI-install` | GITHUB | Zu alt: 81d |
| `mbierman/unifi-installer-for-Firewalla` | GITHUB | Zu alt: 348d |
| `duggytuxy/syswarden` | GITHUB | Größe: 0 IPs |
| `firewalld/firewalld` | GITHUB | IP-Datei 5050d alt |
| `cloudnativelabs/kube-router` | GITHUB | Keine IP-Datei |
| `rfxn/advanced-policy-firewall` | GITHUB | Zu alt: 43d |
| `Winds-Studio/Leaf` | GITHUB | Keine IP-Datei |
| `DreamVoid/MiraiMC` | GITHUB | Keine IP-Datei |
| `FloatTech/ZeroBot-Plugin` | GITHUB | Keine IP-Datei |
| `Quan666/ELF_RSS` | GITHUB | Keine IP-Datei |
| `Colter23/bilibili-dynamic-mirai-plugin` | GITHUB | Keine IP-Datei |
| `MrXiaoM/Overflow` | GITHUB | Zu alt: 32d |
| `YunYouJun/mirai-ts` | GITHUB | Keine IP-Datei |
| `MadokaProject/Madoka` | GITHUB | Keine IP-Datei |
| `tcpfin-dev/terylene` | GITHUB | Zu alt: 75d |
| `CyberMonitor/APT_CyberCriminal_Campagin_Collections` | GITHUB | IP-Datei 1529d alt |
| `3nock/SpiderSuite` | GITHUB | Keine IP-Datei |
| `tsale/TeleTracker` | GITHUB | Keine IP-Datei |
| `l4rm4nd/LinkedInDumper` | GITHUB | Keine IP-Datei |
| `misiektoja/github_monitor` | GITHUB | Keine IP-Datei |
| `misiektoja/psn_monitor` | GITHUB | Keine IP-Datei |
| `kpcyrd/sn0int` | GITHUB | Keine IP-Datei |
| `drego85/tosint` | GITHUB | Keine IP-Datei |
| `spmedia/Telegram-Channel-Joiner` | GITHUB | Keine IP-Datei |
| `qeeqbox/social-analyzer` | GITHUB | Keine IP-Datei |
| `misiektoja/xbox_monitor` | GITHUB | Keine IP-Datei |
| `Bevigil/BeVigil-OSINT-CLI` | GITHUB | Keine IP-Datei |
| `yt-dlp/yt-dlp` | GITHUB | Keine IP-Datei |
| `megadose/toutatis` | GITHUB | Keine IP-Datei |
| `3nock/sub3suite` | GITHUB | Keine IP-Datei |
| `hstsethi/in-mob-prefix` | GITHUB | Keine IP-Datei |
| `sockysec/Telerecon` | GITHUB | Keine IP-Datei |
| `s0md3v/Zen` | GITHUB | Keine IP-Datei |
| `aydinnyunus/exiflooter` | GITHUB | Keine IP-Datei |
| `Datalux/Osintgram` | GITHUB | Keine IP-Datei |
| `akamhy/waybackpy` | GITHUB | Keine IP-Datei |
| `kaifcodec/user-scanner.git` | GITHUB | Keine IP-Datei |
| `atiilla/gitrecon` | GITHUB | Keine IP-Datei |
| `OSINTI4L/cupidcr4wl` | GITHUB | Keine IP-Datei |
| `misiektoja/lol_monitor` | GITHUB | Keine IP-Datei |
| `misiektoja/instagram_monitor` | GITHUB | Keine IP-Datei |
| `finos/perspective` | GITHUB | Keine IP-Datei |
| `lukeslp/antisocial` | GITHUB | Keine IP-Datei |
| `matiash26/steam-osint` | GITHUB | Keine IP-Datei |
| `gorhill/uBlock` | GITHUB | Keine IP-Datei |
| `tomnomnom/waybackurls` | GITHUB | Keine IP-Datei |
| `its0x08/duckduckgo` | GITHUB | Keine IP-Datei |
| `zbetcheckin/Security_list` | GITHUB | Keine IP-Datei |
| `vognik/maltego-telegram` | GITHUB | Keine IP-Datei |
| `mantisfury/ArkhamMirror` | GITHUB | Keine IP-Datei |
| `owasp-amass/amass` | GITHUB | Keine IP-Datei |
| `fauvidoTechnologies/PyBrowserAutomation` | GITHUB | Keine IP-Datei |
| `sqren/fb-sleep-stats` | GITHUB | Keine IP-Datei |
| `nox-project/nox-framework` | GITHUB | Keine IP-Datei |
| `hamodywe/telegram-scraper-TeleGraphite` | GITHUB | Keine IP-Datei |
| `hmaverickadams/DeHashed-API-Tool` | GITHUB | Keine IP-Datei |
| `GeiserX/Website-Diff` | GITHUB | Keine IP-Datei |
| `narkopolo/fb_friend_list_scraper` | GITHUB | Keine IP-Datei |
| `XD-MHLOO/Osintgraph` | GITHUB | Keine IP-Datei |
| `vflame6/leaker` | GITHUB | Keine IP-Datei |
| `loseys/Oblivion` | GITHUB | Keine IP-Datei |
| `Lissy93/personal-security-checklist` | GITHUB | Keine IP-Datei |
| `ANG13T/SatIntel` | GITHUB | Keine IP-Datei |
| `misiektoja/spotify_profile_monitor` | GITHUB | Keine IP-Datei |
| `david3107/squatm3gator` | GITHUB | Keine IP-Datei |
| `misiektoja/lastfm_monitor` | GITHUB | Keine IP-Datei |
| `sundowndev/PhoneInfoga` | GITHUB | Keine IP-Datei |
| `cybersader/WebsiteTechMiner-py` | GITHUB | Keine IP-Datei |
| `FlowingMedia/TimeFlow` | GITHUB | Keine IP-Datei |
| `khashashin/ogi` | GITHUB | Keine IP-Datei |
| `thewhiteh4t/nexfil` | GITHUB | Keine IP-Datei |
| `dgtlmoon/changedetection.io` | GITHUB | Keine IP-Datei |
| `s-rah/onionscan` | GITHUB | Keine IP-Datei |
| `six2dez/reconftw` | GITHUB | Keine IP-Datei |
| `p1ngul1n0/blackbird` | GITHUB | Keine IP-Datei |
| `tomsec8/IntelHub` | GITHUB | Keine IP-Datei |
| `misiektoja/spotify_monitor` | GITHUB | Keine IP-Datei |
| `eth0izzle/the-endorser` | GITHUB | Keine IP-Datei |
| `wireservice/csvkit` | GITHUB | Keine IP-Datei |
| `snooppr/shotstars` | GITHUB | Keine IP-Datei |
| `jsvine/waybackpack` | GITHUB | Keine IP-Datei |
| `momenbasel/keyFinder` | GITHUB | Keine IP-Datei |
| `bibanon/tubeup` | GITHUB | Keine IP-Datei |
| `spmedia/Crypto-Scam-and-Crypto-Phishing-Threat-Intel-Feed` | GITHUB | Keine IP-Datei |
| `GeiserX/BuscaPaginasBlancas` | GITHUB | Keine IP-Datei |
| `Alaa-abdulridha/SerpScan` | GITHUB | Keine IP-Datei |
| `smicallef/spiderfoot` | GITHUB | IP-Datei 1551d alt |
| `AccentuSoft/LinkScope_Client` | GITHUB | Keine IP-Datei |
| `misiektoja/steam_monitor` | GITHUB | Keine IP-Datei |
| `tejado/telegram-nearby-map` | GITHUB | Keine IP-Datei |
| `ArthurHeitmann/arctic_shift` | GITHUB | Keine IP-Datei |
| `GreyNoise-Intelligence/pygreynoise` | GITHUB | Keine IP-Datei |
| `IvanGlinkin/CCTV` | GITHUB | Keine IP-Datei |
| `DataSploit/datasploit` | GITHUB | Keine IP-Datei |
| `shadawck/glit` | GITHUB | Keine IP-Datei |
| `milo2012/osintstalker` | GITHUB | Keine IP-Datei |
| `rmusser01/Infosec_Reference` | GITHUB | Keine IP-Datei |
| `counteractive/incident-response-plan-template` | GITHUB | Keine IP-Datei |
| `ThreatResponse/margaritashotgun` | GITHUB | Keine IP-Datei |
| `JPCERTCC/SysmonSearch` | GITHUB | IP-Datei 2859d alt |
| `log2timeline/dftimewolf` | GITHUB | Keine IP-Datei |
| `aws-samples/aws-incident-response-runbooks` | GITHUB | Keine IP-Datei |
| `MagnetForensics/dumpit-linux` | GITHUB | Keine IP-Datei |
| `ufrisk/MemProcFS` | GITHUB | Keine IP-Datei |
| `endgameinc/RTA` | GITHUB | Keine IP-Datei |
| `kacos2000/MFT_Browser` | GITHUB | Keine IP-Datei |
| `gfoss/PSRecon` | GITHUB | Keine IP-Datei |
| `phantomcyber/playbooks` | GITHUB | IP-Datei 351d alt |
| `CrowdStrike/falcon-orchestrator` | GITHUB | Keine IP-Datei |
| `AJMartel/IRTriage` | GITHUB | Keine IP-Datei |
| `sandialabs/scot` | GITHUB | Keine IP-Datei |
| `PowerShellMafia/CimSweep` | GITHUB | Keine IP-Datei |
| `504ensicsLabs/LiME` | GITHUB | Keine IP-Datei |
| `airbnb/streamalert` | GITHUB | IP-Datei 2773d alt |
| `mkorman90/VolatilityBot` | GITHUB | Keine IP-Datei |
| `shamubernetes/home-k8s` | GITHUB | IP-Datei 206d alt |
| `secnotes/dailycve` | GITHUB | Keine IP-Datei |
| `Surfboardv2ray/TGParse` | GITHUB | Keine IP-Datei |
| `kdr/overcast` | GITHUB | Größe: 0 IPs |
| `ebrasha/abdal-proxy-hub` | GITHUB | Keine IP-Datei |
| `timgerstel/suspicious_IPs` | GITHUB | Keine IP-Datei |
| `vmheaven/VMHeaven.io-Free-Proxy-List` | GITHUB | Keine IP-Datei |
| `notfaj/ester` | GITHUB | Keine IP-Datei |
| `Tempest-Solutions-Company/threat-feeds` | GITHUB | Keine IP-Datei |
| `tikoci/centrs` | GITHUB | Keine IP-Datei |
| `Nikopmpm/Fsociety-CVE-2024-0670-CheckMK-LPE` | GITHUB | Keine IP-Datei |
| `hnordt/vps-bootstrap` | GITHUB | Keine IP-Datei |
| `TheeAmir/scambuster-preview` | GITHUB | Keine IP-Datei |
| `V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB` | GITHUB | Keine IP-Datei |
| `Gberegbe/infrastructure-security-automation` | GITHUB | Keine IP-Datei |
| `zloi-user/hideip.me` | GITHUB | Keine IP-Datei |
| `MrMarble/proxy-list` | GITHUB | Keine IP-Datei |
| `evania-maker/PhoneAgent` | GITHUB | IP-Datei 204d alt |
| `DhruvKachchhi/pfsense-firewall-lab` | GITHUB | Keine IP-Datei |
| `mizanur1989/CodeStalker` | GITHUB | Keine IP-Datei |
| `RioMMO/ProxyFree` | GITHUB | Keine IP-Datei |
| `anxb26/angie-modsecurity-docker` | GITHUB | Keine IP-Datei |
| `mikenob39wang/phone-number-location-tracking-tool` | GITHUB | Keine IP-Datei |
| `Farhan9488/CVE-2025-55182-research` | GITHUB | Keine IP-Datei |
| `VPSLabCloud/VPSLab-Free-Proxy-List` | GITHUB | Keine IP-Datei |
| `Yoora69/pklnet` | GITHUB | Keine IP-Datei |
| `jaschadub/compromised-packages-check` | GITHUB | Keine IP-Datei |
| `abdusamra/web-attack-log-analyzer` | GITHUB | Keine IP-Datei |
| `chalie56/proxy-multi-protocol-checker` | GITHUB | Keine IP-Datei |
| `pedrodeivid/osint-resources` | GITHUB | Keine IP-Datei |
| `eliezerfrn/dont-be-shy-hulud` | GITHUB | IP-Datei 212d alt |
| `DeepakMudili/cf-ssl-check` | GITHUB | Keine IP-Datei |
| `stormsia/proxy-list` | GITHUB | Keine IP-Datei |
| `batoasihhm/seed-phrase-generator` | GITHUB | Keine IP-Datei |
| `nigerbartus/Shai-Hulud-2.0-Detector` | GITHUB | Keine IP-Datei |
| `breensstudios/Red_Team_Collaboration` | GITHUB | Keine IP-Datei |
| `Yuyazkyle/Learning_Logs_Advanced` | GITHUB | Keine IP-Datei |
| `sanjuthomas/security-event-rag-demo` | GITHUB | Keine IP-Datei |
| `Gaplox00/Azure_GRC` | GITHUB | Keine IP-Datei |
| `tasiedev/telegram-account-osint` | GITHUB | Keine IP-Datei |

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
| `cbuijs_accomplist` | GITHUB | 99,731 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,444 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 118,814 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 106,612 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 628 | 36.7% | 8 | 2026-07-03 |
| `turntuptechnologies_iocs` | GITHUB | 29 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 52,112 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 96,468 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,577 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 121 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 223,002 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,894 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,678 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 6,953 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 7,227 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 166,003 | 18.9% | 1 | 2026-05-28 |
| `idleadmin_threatfeed` | GITHUB | 51,321 | 41.9% | 0 | 2026-04-09 |
| `turbolabit_zzfirewall` | GITHUB | 99,140 | 66.4% | 0 | 2026-05-03 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 45,745 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,434 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 111,134 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 517 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,170 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 191,710 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,461 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 112,223 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 110,371 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 32,107 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 18,571 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 15,367 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,795 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 7,411 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,482 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cps_abusech` | GITHUB | 7,607 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,695 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,610 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 3,968 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,603 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,123 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 3,483 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,747 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 3,048 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,313 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 2,004 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,951 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_socks_proxy_7d` | GITHUB | 1,455 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,329 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,268 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,213 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,186 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,109 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 993 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 998 | 13.1% | 0 | 2026-07-04 |

---
*Generiert: 2026-07-04 04:25 UTC*