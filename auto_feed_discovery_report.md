# Auto Feed Discovery – Report
**Aktualisiert:** 2026-05-28 19:15 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **6843** |
| davon GitHub (Topics+Code) | **6806** |
| davon GitLab | **37** |
| davon Awesome-Lists | **1019** |
| Tools/Libraries vor Eval gefiltert | **857** |
| davon Hard-Reject (awesome-Liste etc.) | **96** |
| EVAL-Kandidaten (nach Stratifizierung) | **210** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluiert | **217** |
| Neu angenommen | **6** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feeds aktualisiert | **30** |
| Abgelehnt (dieser Run) | **210** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **36** |
| IPs in seen_db bestätigt | **698167** |
| Neue IPs eingetragen | **350** |
| seen_db gesamt | **4,766,377** |
| HQ-Referenz-IPs (6 Quellen) | **139481** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **140** |
| Repo zu alt (>30d) | **64** |
| IP-Datei veraltet (>30d) | **5** |
| Falsche Größe (<100 / >500k IPs) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `cbuijs_accomplist_adblock_ip` | [cbuijs/accomplist](https://github.com/cbuijs/accomplist) | GITHUB | 127,705 | 0.6% | 1.5% | 20 | 🆕 NEU |
| `cbuijs_accomplist_plain_black_ip4cidr` | [cbuijs/accomplist](https://github.com/cbuijs/accomplist) | GITHUB | 127,705 | 0.6% | 1.5% | 20 | 🆕 NEU |
| `turbolabit_zzfirewall_blacklist` | [TurboLabIt/zzfirewall](https://github.com/TurboLabIt/zzfirewall) | GITHUB | 85 | 66.4% | 0.0% | 0 | 🔄 Update |
| `wintergate_ic_wic_resources_permanent_blacklist` | [WinterGate-IC/wic-resources](https://github.com/WinterGate-IC/wic-resources) | GITHUB | 508 | 67.0% | 0.0% | 0 | 🆕 NEU |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) | GITHUB | 10,628 | 75.0% | 0.0% | 4721 | 🆕 NEU |
| `kamalmjt_emerging_attackers_badips` | [kamalmjt/emerging-attackers](https://github.com/kamalmjt/emerging-attackers) | GITHUB | 162,907 | 18.9% | 0.0% | 1 | 🆕 NEU |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | [ziyadnz/threat-intel-ip-feeds](https://github.com/ziyadnz/threat-intel-ip-feeds) | GITHUB | 106,405 | 36.7% | 0.0% | 8 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `Bhai4You/otpbomber` | GITHUB | Zu alt: 49d |
| `shidahuilang/SS-SSR-TG-iptables-bt` | GITHUB | IP-Datei 1692d alt |
| `wazuh/wazuh-dashboard-plugins` | GITHUB | Keine IP-Datei |
| `fkie-cad/COMIDDS` | GITHUB | Keine IP-Datei |
| `ossec/ossec-hids` | GITHUB | IP-Datei 3272d alt |
| `selimfirat/pysad` | GITHUB | Keine IP-Datei |
| `ubc-provenance/PIDSMaker` | GITHUB | Keine IP-Datei |
| `rfxn/linux-malware-detect` | GITHUB | IP-Datei 36d alt |
| `wazuh/wazuh-ansible` | GITHUB | Keine IP-Datei |
| `nextcloud/suspicious_login` | GITHUB | Keine IP-Datei |
| `joshspeagle/brutus` | GITHUB | Keine IP-Datei |
| `praetorian-inc/brutus` | GITHUB | Keine IP-Datei |
| `spmedia/PhishingSecLists` | GITHUB | Keine IP-Datei |
| `agourlay/zip-password-finder` | GITHUB | Keine IP-Datei |
| `Amal-David/keyleak-detector` | GITHUB | Keine IP-Datei |
| `hslatman/caddy-crowdsec-bouncer` | GITHUB | Zu alt: 45d |
| `bunkerity/bunkerweb-plugins` | GITHUB | Zu alt: 45d |
| `psycho0verload/traefik-crowdsec-stack` | GITHUB | Zu alt: 151d |
| `ccdcoe/CDMCS` | GITHUB | Keine IP-Datei |
| `3CORESec/testmynids.org` | GITHUB | Zu alt: 321d |
| `jasonish/py-idstools` | GITHUB | Zu alt: 322d |
| `eworm-de/routeros-scripts` | GITHUB | Keine IP-Datei |
| `jeff-nasseri/mikrotik-mcp` | GITHUB | Keine IP-Datei |
| `mirceanton/external-dns-provider-mikrotik` | GITHUB | Keine IP-Datei |
| `danikf/tik4net` | GITHUB | Keine IP-Datei |
| `FingerlessGlov3s/OPNsensePIAWireguard` | GITHUB | Zu alt: 43d |
| `pfrest/pfSense-pkg-saml2-auth` | GITHUB | Keine IP-Datei |
| `kulunkilabs/vibenetbackup` | GITHUB | Zu alt: 33d |
| `sexibytes/sexigraf` | GITHUB | Zu alt: 56d |
| `htrgouvea/nipe` | GITHUB | Keine IP-Datei |
| `x-way/iptables-tracer` | GITHUB | Keine IP-Datei |
| `hknutzen/Netspoc` | GITHUB | Keine IP-Datei |
| `miniupnp/miniupnp` | GITHUB | Keine IP-Datei |
| `firehol/firehol` | GITHUB | Zu alt: 58d |
| `zfl9/chinadns-ng` | GITHUB | Zu alt: 292d |
| `nadoo/glider` | GITHUB | Zu alt: 455d |
| `zw963/asuswrt-merlin-transparent-proxy` | GITHUB | Zu alt: 953d |
| `janeczku/go-ipset` | GITHUB | Zu alt: 1184d |
| `duan602728596/qqtools` | GITHUB | Zu alt: 133d |
| `DreamVoid/Chat2QQ` | GITHUB | Zu alt: 148d |
| `MrXiaoM/Eden` | GITHUB | Zu alt: 157d |
| `g1331/xiaomai-bot` | GITHUB | Zu alt: 199d |
| `niuhuan/rust_proc_qq` | GITHUB | Zu alt: 271d |
| `lss233/kirara-ai` | GITHUB | Zu alt: 334d |
| `Sora233/DDBOT` | GITHUB | Zu alt: 346d |
| `cnlimiter/onebot-client` | GITHUB | Zu alt: 370d |
| `YunYouJun/el-bot` | GITHUB | Zu alt: 425d |
| `Nova-Committee/McBot` | GITHUB | Zu alt: 438d |
| `khjxiaogu/MiraiSongPlugin` | GITHUB | Zu alt: 567d |
| `cssxsh/meme-helper` | GITHUB | Zu alt: 581d |
| `R00tS3c/DDOS-RootSec` | GITHUB | Zu alt: 602d |
| `mamoe/mirai` | GITHUB | Zu alt: 612d |
| `zmh-program/web-mirai-panel` | GITHUB | Zu alt: 626d |
| `GardenHamster/Theresa3rd-Bot` | GITHUB | Zu alt: 640d |
| `SAGIRI-kawaii/sagiri-bot` | GITHUB | Zu alt: 645d |
| `saladandonionrings/leaky` | GITHUB | Zu alt: 98d |
| `cryptwareapps/Malware-Database` | GITHUB | Zu alt: 99d |
| `Isaacdelly/Plutus` | GITHUB | Zu alt: 144d |
| `shaddy43/BrowserSnatch` | GITHUB | Zu alt: 187d |
| `sankha-ghosh/Browser-Data-Grabber` | GITHUB | Zu alt: 205d |
| `sqlerrorthing/ShadowSniff` | GITHUB | Zu alt: 230d |
| `stegman-ux/Butcher-Tools` | GITHUB | Zu alt: 316d |
| `xmrig/xmrig-cuda` | GITHUB | Zu alt: 172d |
| `cornjosh/Aminer` | GITHUB | Zu alt: 247d |
| `metal3d/docker-xmrig` | GITHUB | Zu alt: 269d |
| `xmrig/xmrig-deps` | GITHUB | Zu alt: 328d |
| `giansalex/monero-miner-docker` | GITHUB | Zu alt: 383d |
| `CyberSecByte/termux-miner` | GITHUB | Zu alt: 832d |
| `hinto-janai/monero-bash` | GITHUB | Zu alt: 1129d |
| `cryptoprofitswitcher/CryptoProfitSwitcher` | GITHUB | Zu alt: 1267d |
| `apache/creadur-rat` | GITHUB | Keine IP-Datei |
| `pathetic/async-rust-rat` | GITHUB | Keine IP-Datei |
| `bigratmonster/bigrat.monster` | GITHUB | Keine IP-Datei |
| `anirudhmalik/xhunter` | GITHUB | Keine IP-Datei |
| `RatInABox-Lab/RatInABox` | GITHUB | Zu alt: 49d |
| `AryanVBW/ANDRO` | GITHUB | Zu alt: 59d |
| `XZB-1248/Spark` | GITHUB | Zu alt: 73d |
| `someshsrichandan/RavanRAT` | GITHUB | Zu alt: 78d |
| `iss4cf0ng/Alien` | GITHUB | Zu alt: 82d |
| `NullCode1337/NullRAT` | GITHUB | Zu alt: 83d |
| `Marven11/EtherGhost` | GITHUB | Keine IP-Datei |
| `openspug/spug` | GITHUB | IP-Datei 2163d alt |
| `ReaJason/No-One` | GITHUB | Keine IP-Datei |
| `chaitin/mimicry` | GITHUB | Zu alt: 69d |
| `trzsz/trzsz.js` | GITHUB | Zu alt: 83d |
| `dromara/orion-visor` | GITHUB | Zu alt: 110d |
| `p0dalirius/Wordpress-webshell-plugin` | GITHUB | Zu alt: 118d |
| `JoelGMSec/PyShell` | GITHUB | Zu alt: 185d |
| `elliottophellia/aizawa` | GITHUB | Zu alt: 186d |
| `pen4uin/java-memshell-generator` | GITHUB | Zu alt: 280d |
| `chrisallenlane/novahot` | GITHUB | Zu alt: 291d |
| `carloslack/KoviD` | GITHUB | Keine IP-Datei |
| `marcocesarato/PHP-Antimalware-Scanner` | GITHUB | Keine IP-Datei |
| `m0nad/Diamorphine` | GITHUB | Zu alt: 31d |
| `s0ld13rr/claude-code-backdoor` | GITHUB | Zu alt: 42d |
| `bboylyg/BackdoorLLM` | GITHUB | Zu alt: 76d |
| `Cr4sh/s6_pcie_microblaze` | GITHUB | Zu alt: 82d |
| `vakhov/fresh-proxy-list` | GITHUB | Keine IP-Datei |
| `iplocate/free-proxy-list` | GITHUB | Keine IP-Datei |
| `berkay-digital/Proxy-Scraper` | GITHUB | Keine IP-Datei |
| `Cymmetria/micros_honeypot` | GITHUB | Keine IP-Datei |
| `Cymmetria/MTPot` | GITHUB | Keine IP-Datei |
| `ncouture/MockSSH` | GITHUB | Keine IP-Datei |
| `mrschyte/dockerpot` | GITHUB | Keine IP-Datei |
| `mycert/ESPot` | GITHUB | Keine IP-Datei |
| `graneed/bwpot` | GITHUB | Keine IP-Datei |
| `referefref/canarytokendetector` | GITHUB | Keine IP-Datei |
| `mdp/honeypot.go` | GITHUB | Keine IP-Datei |
| `omererdem/honeything` | GITHUB | Keine IP-Datei |
| `Marist-Innovation-Lab/PasitheaHoneypot` | GITHUB | Keine IP-Datei |
| `RevengeComing/DemonHunter` | GITHUB | Keine IP-Datei |
| `christophe77/express-honeypot` | GITHUB | Keine IP-Datei |
| `ayrus/afterglow-cloud` | GITHUB | Keine IP-Datei |
| `thinkst/canarytokens` | GITHUB | Keine IP-Datei |
| `Phype/telnet-iot-honeypot` | GITHUB | Keine IP-Datei |
| `eymengunay/EoHoneypotBundle` | GITHUB | Keine IP-Datei |
| `hatching/vmcloak` | GITHUB | Keine IP-Datei |
| `deroux/longitudinal-analysis-cowrie` | GITHUB | Keine IP-Datei |
| `GovCERT-CZ/Wordpot-Frontend` | GITHUB | Keine IP-Datei |
| `UHH-ISS/honeygrove` | GITHUB | Keine IP-Datei |
| `tillmannw/honeytrap` | GITHUB | Keine IP-Datei |
| `DataSoft/Nova` | GITHUB | Keine IP-Datei |
| `shiva-spampot/shiva` | GITHUB | Keine IP-Datei |
| `Joss-Steward/honeypotDisplay` | GITHUB | Keine IP-Datei |
| `christophe77/node-ftp-honeypot` | GITHUB | Keine IP-Datei |
| `torque59/nosqlpot` | GITHUB | Keine IP-Datei |
| `jpyorre/IntelligentHoneyNet` | GITHUB | Keine IP-Datei |
| `secureworks/dcept` | GITHUB | Keine IP-Datei |
| `shbhmsingh72/Honeypot-Research-Papers` | GITHUB | Keine IP-Datei |
| `gregcmartin/Kippo_JunOS` | GITHUB | Keine IP-Datei |
| `huuck/ADBHoney` | GITHUB | Keine IP-Datei |
| `xme/dshield-docker` | GITHUB | Keine IP-Datei |
| `thinkst/opencanary` | GITHUB | Keine IP-Datei |
| `xiaoxiaoleo/HoneyMysql` | GITHUB | Keine IP-Datei |
| `r0hi7/HoneySMB` | GITHUB | Keine IP-Datei |
| `desaster/kippo` | GITHUB | Keine IP-Datei |
| `andrewmichaelsmith/manuka` | GITHUB | Keine IP-Datei |
| `jesparza/peepdf` | GITHUB | Keine IP-Datei |
| `lcashdol/WAPot` | GITHUB | Keine IP-Datei |
| `CHH/stack-honeypot` | GITHUB | Keine IP-Datei |
| `HoneySat/honeysat-deploy` | GITHUB | Keine IP-Datei |
| `nsmfoo/dicompot` | GITHUB | Keine IP-Datei |
| `bjeborn/basic-auth-pot` | GITHUB | Keine IP-Datei |
| `mushorg/snare` | GITHUB | Keine IP-Datei |
| `citronneur/rdpy` | GITHUB | Keine IP-Datei |
| `Cymmetria/honeycomb_plugins` | GITHUB | Keine IP-Datei |
| `yvesago/imap-honey` | GITHUB | Keine IP-Datei |
| `run41/honey_ports` | GITHUB | Keine IP-Datei |
| `d1str0/drupot` | GITHUB | Keine IP-Datei |
| `katkad/Glastopf-Analytics` | GITHUB | Keine IP-Datei |
| `czardoz/hornet` | GITHUB | Keine IP-Datei |
| `MattCarothers/mhn-core-docker` | GITHUB | Keine IP-Datei |
| `GovCERT-CZ/Shockpot-Frontend` | GITHUB | Keine IP-Datei |
| `honeynet/ghost-usb-honeypot` | GITHUB | Keine IP-Datei |
| `mfontani/kippo-stats` | GITHUB | Keine IP-Datei |
| `jedie/django-kippo` | GITHUB | Keine IP-Datei |
| `schmalle/medpot` | GITHUB | Keine IP-Datei |
| `tnich/honssh` | GITHUB | Keine IP-Datei |
| `mushorg/imhoneypot` | GITHUB | IP-Datei 4920d alt |
| `alexbredo/honeypot-camera` | GITHUB | Keine IP-Datei |
| `ZafarAabid/face-id` | GITHUB | Keine IP-Datei |
| `CroatiaSecurity/Sentinel` | GITHUB | Keine IP-Datei |
| `paulo-cesar-security/cybersecurity-portfolio` | GITHUB | Keine IP-Datei |
| `aziontech/azion-console-kit` | GITHUB | Keine IP-Datei |
| `aaronmarchant96-max/uap-footage-analyzer` | GITHUB | Keine IP-Datei |
| `DyniePro/CVE-2026-25643` | GITHUB | Keine IP-Datei |
| `ErtiPrenci/inventory-public` | GITHUB | Keine IP-Datei |
| `szl-holdings/sentra` | GITHUB | Keine IP-Datei |
| `omas231/map1` | GITHUB | Keine IP-Datei |
| `crownshield-sec/soc-portfolio` | GITHUB | Keine IP-Datei |
| `Filearsip/wapp` | GITHUB | Keine IP-Datei |
| `Chrenavete/Axie-Infinity-Bot-Crypto-Cheat-Auto-Farm-Clicker-Game-Api-Hack` | GITHUB | Keine IP-Datei |
| `Judaca73/ghost-os` | GITHUB | Keine IP-Datei |
| `AlchemyLink/Raven-subscribe` | GITHUB | Keine IP-Datei |
| `gen0sec/synapse` | GITHUB | Keine IP-Datei |
| `mitre-attack/attack-website` | GITHUB | Keine IP-Datei |
| `Hat071/planning-template` | GITHUB | Keine IP-Datei |
| `MEET-UC/seithar-research` | GITHUB | Keine IP-Datei |
| `QuantumS14/DoesTheDogWatchPlex` | GITHUB | Keine IP-Datei |
| `Dreamer599/ai-intelligence-hub` | GITHUB | Keine IP-Datei |
| `BornToBeRoot/NETworkManager` | GITHUB | Keine IP-Datei |
| `CHUMENII/COM-UACBypass-Privilege-Escalation` | GITHUB | Keine IP-Datei |
| `apialerts/apt` | GITHUB | Keine IP-Datei |
| `jmpsec/osctrl` | GITHUB | Keine IP-Datei |
| `agentveil-protocol/agentveil-sdk` | GITHUB | Keine IP-Datei |
| `macadmins/sofa` | GITHUB | Keine IP-Datei |
| `Trivexion/FscanOutput-Beautify` | GITHUB | Keine IP-Datei |
| `Fluxenn/Dogs-House-Game-Bot-Auto-Trading-Clicker-Crypto-Exchange-Telegram-Hack-Cheat` | GITHUB | Keine IP-Datei |
| `anupamsarashwat1-cloud/smvdu-titan-x` | GITHUB | Größe: 0 IPs |
| `Althariv/Heroes-of-Mavia-Hack-Game-Bot-Auto-Farm-Clicker-Crypto-Token-Api-Cheat` | GITHUB | Keine IP-Datei |
| `pbkangafoo/webcat` | GITHUB | Keine IP-Datei |
| `hrbrmstr/cisa-known-exploited-vulns` | GITHUB | Keine IP-Datei |
| `VictoriaMetrics/VictoriaLogs` | GITHUB | Keine IP-Datei |
| `FAlhumaid/DFIR_Radar_RSS` | GITHUB | Keine IP-Datei |
| `Tsugar0106/Norwegian-WiFi-Wordlist` | GITHUB | Keine IP-Datei |
| `RogoLabs/cve.icu` | GITHUB | Keine IP-Datei |
| `Undercat037/number-checker` | GITHUB | Keine IP-Datei |
| `LUANNNN1-ops/rouletteboxd` | GITHUB | Keine IP-Datei |
| `Suwanna45/Scan-port-localhost` | GITHUB | Keine IP-Datei |
| `pkeenan87/Neo` | GITHUB | Keine IP-Datei |
| `realizelol/torblocklist` | GITHUB | Keine IP-Datei |
| `HamzaHabib-786/nullsec-bluetooth` | GITHUB | Keine IP-Datei |
| `Dieans/Universal-News-Scraper` | GITHUB | Keine IP-Datei |
| `Hadrysel/WhatsApp-Network-Tracker` | GITHUB | Keine IP-Datei |
| `NishanthGSuryavamshi/thinksec` | GITHUB | Keine IP-Datei |
| `BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer` | GITHUB | Keine IP-Datei |
| `MiguelArmando/Bug-Bounty-Roadmap` | GITHUB | Keine IP-Datei |
| `jaimvizalla01/aiwhisperer` | GITHUB | Keine IP-Datei |
| `clolomagico123/ai-security-lab` | GITHUB | Keine IP-Datei |
| `akramul2540/Islamic-Republic-Influence-Networks` | GITHUB | Keine IP-Datei |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist_v2` | GITHUB | 10,628 | 75.0% | 4721 | 2026-05-28 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | GITHUB | 10,628 | 75.0% | 4721 | 2026-05-28 |
| `cbuijs_accomplist` | GITHUB | 96,887 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,439 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_plain_black_ipcidr` | GITHUB | 127,705 | 0.6% | 20 | 2026-05-28 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 127,705 | 0.6% | 20 | 2026-05-28 |
| `cbuijs_accomplist_plain_black_ip4cidr` | GITHUB | 127,705 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_ipv4_blacklist` | GITHUB | 106,405 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 106,405 | 36.7% | 8 | 2026-05-28 |
| `turntuptechnologies_iocs` | GITHUB | 61 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 38,121 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 94,911 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,155 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 100 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 220,922 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 7,923 | 69.0% | 4 | 2026-05-24 |
| `fadouse_clash_threat_intel` | GITHUB | 5,191 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 5,361 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips_txt` | GITHUB | 162,907 | 18.9% | 1 | 2026-05-28 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 162,907 | 18.9% | 1 | 2026-05-28 |
| `idleadmin_threatfeed` | GITHUB | 49,732 | 41.9% | 0 | 2026-04-09 |
| `turbolabit_zzfirewall` | GITHUB | 99,243 | 66.4% | 0 | 2026-05-03 |
| `kraloveckey_ipsets_blocklist` | GITHUB | 16,854 | 13.1% | 0 | 2026-05-10 |
| `wintergate_ic_wic_resources_permanent_blacklist_v2` | GITHUB | 503 | 67.0% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 39,911 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_iblocklist_ciarmy_malicious` | GITHUB | 12,472 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_et_tor` | GITHUB | 7,500 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,414 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_blocklist_de_ssh` | GITHUB | 5,722 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_blocklist_de_bruteforce` | GITHUB | 731 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_snort_ip_blocklist` | GITHUB | 1,386 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_alienvault_reputation` | GITHUB | 609 | 13.1% | 0 | 2026-05-24 |
| `wintergate_ic_wic_resources_permanent_blacklist_v3` | GITHUB | 508 | 67.0% | 0 | 2026-05-28 |
| `turbolabit_zzfirewall_blacklist` | GITHUB | 85 | 66.4% | 0 | 2026-05-28 |
| `wintergate_ic_wic_resources_permanent_blacklist` | GITHUB | 508 | 67.0% | 0 | 2026-05-28 |

---
*Generiert: 2026-05-28 19:15 UTC*