# Auto Feed Discovery – Report
**Aktualisiert:** 2026-08-12 21:17 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **9889** |
| davon GitHub (Topics+Code) | **9812** |
| davon GitLab | **77** |
| davon Awesome-Lists | **2400** |
| Tools/Libraries vor Eval gefiltert | **1278** |
| davon Hard-Reject (awesome-Liste etc.) | **153** |
| EVAL-Kandidaten (nach Stratifizierung) | **380** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **380** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **378** |
| Neu angenommene Feed-Dateien | **6** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **196** |
| Abgelehnte Repositories (dieser Run) | **378** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **202** |
| IPs in seen_db bestätigt | **3708762** |
| Neue IPs eingetragen | **90547** |
| seen_db gesamt | **13,199,949** |
| HQ-Referenz-IPs (6 Quellen) | **123364** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **250** |
| Repo zu alt (>30d) | **69** |
| IP-Datei veraltet (>30d) | **27** |
| Falsche Größe (<30 / >2,000,000 IPs) | **26** |
| Overlap mit HQ-Feeds zu gering (<20%) | **6** |
| Sonstige | **2** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `gazpitchy92_ip_blocklist_blacklist` | [gazpitchy92/ip-blocklist](https://github.com/gazpitchy92/ip-blocklist) | GITHUB | 268,777 | 23.1% | 0.5% | 6 | 🆕 NEU |
| `oktayalver_siberkapan_list` | [OktayAlver/siberkapan-list](https://github.com/OktayAlver/siberkapan-list) | GITHUB | 38,770 | 23.4% | 0.0% | 0 | 🆕 NEU |
| `oktayalver_siberkapan_list_all_feed` | [OktayAlver/siberkapan-list](https://github.com/OktayAlver/siberkapan-list) | GITHUB | 15,961 | 53.4% | 0.0% | 0 | 🆕 NEU |
| `oktayalver_siberkapan_list_honeypot_feed` | [OktayAlver/siberkapan-list](https://github.com/OktayAlver/siberkapan-list) | GITHUB | 12,443 | 46.6% | 0.0% | 0 | 🆕 NEU |
| `oktayalver_siberkapan_list_nginx_feed` | [OktayAlver/siberkapan-list](https://github.com/OktayAlver/siberkapan-list) | GITHUB | 2,603 | 71.1% | 0.0% | 0 | 🆕 NEU |
| `oktayalver_siberkapan_list_fortigate_feed` | [OktayAlver/siberkapan-list](https://github.com/OktayAlver/siberkapan-list) | GITHUB | 72 | 63.9% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `djkurlander/knock-knock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AynOps/AynOps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `devops-ia/helm-opencti` | GITHUB | IP-Datei 338d alt |
| `fastfire/deepdarkCTI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f6-dfir/Ransomware` | GITHUB | Größe: 2 IPs |
| `mrwadams/attackgen` | GITHUB | Größe: 4 IPs |
| `OTT-Cybersecurity-LLC/lyrie-ai` | GITHUB | IP-Datei 107d alt |
| `MHSanaei/3x-ui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alireza0/s-ui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bannedbook/fanqiang` | GITHUB | IP-Datei 2294d alt |
| `2dust/v2rayN` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MKultra6969/MK_XRAYchecker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `surgioproject/surgio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Gozargah/Nabzram` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jichangtuijian-cheap/cheap-airports` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Luffy-del/Honeypot-Spam-Buster` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sstklen/trump-code` | GITHUB | IP-Datei 150d alt |
| `agourlay/zip-password-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xdea/tactical-exploitation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vscodev/XArchiver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HomelessPhD/BTC32` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skjolber/3d-bin-container-packing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joshspeagle/brutus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anvaka/isect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RozhakDev/Facemash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ymsniper/BBF` | GITHUB | Zu alt: 39d |
| `saurabhwadekar/pycrack` | GITHUB | Zu alt: 43d |
| `acepanel/panel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sous-chefs/fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomMoulard/fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `docker-mailserver/docker-mailserver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crazy-max/docker-fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `robertdebock/ansible-role-fail2ban` | GITHUB | Zu alt: 44d |
| `devnulli/EvlWatcher` | GITHUB | Zu alt: 68d |
| `jasonish/evebox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `daffainfo/suricata-rules` | GITHUB | Größe: 0 IPs |
| `FCSC-FR/shovel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jasonish/docker-suricata` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ccdcoe/CDMCS` | GITHUB | Zu alt: 51d |
| `sakib-m/IP-Prefix-List` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2GT-Media-Group-LLC/mikrotik-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeff-nasseri/mikrotik-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hotspotbilling/phpnuxbill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cacti/plugin_mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomaae/homeassistant-mikrotik_router` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vadims06/topolograph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pfrest/pfSense-pkg-RESTAPI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pfrest/pfSense-pkg-saml2-auth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `travisghansen/hass-pfsense` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `felixhaeberle/pfsense-captive-portal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kulunkilabs/vibenetbackup` | GITHUB | Zu alt: 109d |
| `heiher/hev-socks5-tproxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `miniupnp/miniupnp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hknutzen/Netspoc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Derssa/Torollo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Anipaleja/nginx-defender` | GITHUB | IP-Datei 382d alt |
| `ukanth/afwall` | GITHUB | IP-Datei 2266d alt |
| `cloudnativelabs/kube-router` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jaymzh/iptstate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qoomon/docker-host` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zhaoweih/Shadowsocks-Tutorial` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x-way/iptables-tracer` | GITHUB | Zu alt: 34d |
| `htrgouvea/nipe` | GITHUB | Zu alt: 46d |
| `alexhaydock/pinewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pymumu/smartdns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `random-archer/mkinitcpio-systemd-tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FoobarOy/foomuuri` | GITHUB | IP-Datei 134d alt |
| `metal-stack/firewall-controller` | GITHUB | IP-Datei 2302d alt |
| `Sergeydigl3/zapret-discord-youtube-linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zywe03/realm-xwPF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sepandhaghighi/samila` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `black-desk/cgtproxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pspete/psPAS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NInagusev47/Silent-Crypto-Miner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NullCode1337/NullRAT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vxaboveground/Overlord` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bia-technologies/rat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ladysnake/RATs-Mischief` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RatInABox-Lab/RatInABox` | GITHUB | Zu alt: 34d |
| `Hacker-nk/online-hackings` | GITHUB | Zu alt: 50d |
| `Hacker-nk/online-hacking` | GITHUB | Zu alt: 50d |
| `loafiieee/Lo4f-Malware` | GITHUB | Zu alt: 60d |
| `Pericena/Droidjack` | GITHUB | Zu alt: 61d |
| `marlkiller/rust-desk-light` | GITHUB | Zu alt: 65d |
| `pathetic/async-rust-rat` | GITHUB | Zu alt: 85d |
| `bigratmonster/bigrat.monster` | GITHUB | Zu alt: 100d |
| `AryanVBW/ANDRO` | GITHUB | Zu alt: 135d |
| `someshsrichandan/RavanRAT` | GITHUB | Zu alt: 154d |
| `arsium/EagleMonitorRAT` | GITHUB | Zu alt: 168d |
| `canarddu38/DUCKSPLOIT` | GITHUB | Zu alt: 171d |
| `NoahOksuz/OSRipper` | GITHUB | Zu alt: 173d |
| `Kr9jd/HotRAT` | GITHUB | Zu alt: 209d |
| `bitgodhack/AndroidHack_BackDoor` | GITHUB | Zu alt: 210d |
| `jxroot/ZeroPulse` | GITHUB | Zu alt: 224d |
| `DeskX11/DeskX` | GITHUB | Zu alt: 233d |
| `FujiwaraChoki/BlxdMoon` | GITHUB | Zu alt: 233d |
| `WhiteeRabbit/Triton_RAT` | GITHUB | Zu alt: 241d |
| `Gagniuc/Malware-Scanner` | GITHUB | Zu alt: 254d |
| `AryanVBW/Andro-CLI` | GITHUB | Zu alt: 289d |
| `alby77689-design/Wuzen-Framework---Advanced-Mobile-Security-Research-Platform` | GITHUB | Zu alt: 312d |
| `Suburbanno/SWRATT` | GITHUB | Zu alt: 326d |
| `Tocsiop/R8HEX` | GITHUB | Zu alt: 354d |
| `Ephrimgnanam/Cute-RATs` | GITHUB | Zu alt: 364d |
| `Garneg/TelegramRAT` | GITHUB | Zu alt: 366d |
| `Cvar1984/sussyfinder` | GITHUB | Größe: 0 IPs |
| `yasserbdj96/hiphp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fahrj/reverse-ssh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tuconnaisyouknow/BadUSB_adminAccountCreator` | GITHUB | Zu alt: 56d |
| `carloslack/KoviD` | GITHUB | Zu alt: 73d |
| `bboylyg/BackdoorLLM` | GITHUB | Zu alt: 152d |
| `Cr4sh/s6_pcie_microblaze` | GITHUB | Zu alt: 158d |
| `Aegrah/PANIX` | GITHUB | Zu alt: 168d |
| `amaitou/DarkSpy` | GITHUB | Zu alt: 204d |
| `VoxelHax/OpenBukloit` | GITHUB | Zu alt: 219d |
| `reveng007/reveng_rtkit` | GITHUB | Zu alt: 249d |
| `azuk4r/nmap_backdoor` | GITHUB | Zu alt: 288d |
| `MadExploits/Gecko` | GITHUB | Zu alt: 369d |
| `creaktive/tsh` | GITHUB | Zu alt: 467d |
| `st4inl3s5/kizagan` | GITHUB | Zu alt: 472d |
| `ProxyScraper/ProxyScraper` | GITHUB | Overlap zu gering: 1.6% |
| `Surfboardv2ray/TGParse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iplocate/free-proxy-list` | GITHUB | Overlap zu gering: 7.9% |
| `MrMarble/proxy-list` | GITHUB | Overlap zu gering: 0.6% |
| `sunny9577/proxy-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `berkay-digital/Proxy-Scraper` | GITHUB | Overlap zu gering: 5.6% |
| `papapapapdelesia/Emilia` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Skillter/ProxyGather` | GITHUB | IP-Datei 32d alt |
| `firestreamspace/privatezilla-tool-pro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Radianceyecairn/moz-pro-secure-shift` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DockDictator/ipvanish-shield-vault` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `por-cli/por-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salarcode/SmartProxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ictinnovations/ictcore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SEKOIA-IO/automation-library` | GITHUB | IP-Datei 327d alt |
| `rulezet/rulezet-core` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jonaylor89/sherlock-rs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThreatRecall/zettelforge` | GITHUB | IP-Datei 119d alt |
| `blackstork-io/blackstork-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gripebomb/ThreatDeck` | GITHUB | Zu alt: 33d |
| `SEKOIA-IO/Community` | GITHUB | Zu alt: 35d |
| `stnolting/neorv32` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sec-Link/Argus-Agentic-SOC-Platform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Quang-Minh-Phung/DienTu_TKVM_Documents` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0dayInc/pwn` | GITHUB | IP-Datei 848d alt |
| `pzaino/thecrowler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `edoardottt/favirecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `olizimmermann/s3dns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `krishpranav/vesper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nikitastupin/orgs-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `righettod/website-passive-reconnaissance` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `therealdreg/okhi` | GITHUB | Größe: 0 IPs |
| `jaschadub/VectorSmuggle` | GITHUB | Zu alt: 85d |
| `fulldecent/system-bus-radio` | GITHUB | Zu alt: 147d |
| `t0thkr1s/gtfobins-cli` | GITHUB | Zu alt: 189d |
| `R3DRUN3/vermilion` | GITHUB | Zu alt: 272d |
| `AmgdGocha/DriveFS-Sleuth` | GITHUB | Zu alt: 600d |
| `r1vs3c/searchbins` | GITHUB | Zu alt: 755d |
| `ekiojp/dfex` | GITHUB | Zu alt: 852d |
| `jaceddd/text_watermark` | GITHUB | Zu alt: 917d |
| `anfractuosity/musicplayer` | GITHUB | Zu alt: 1072d |
| `DamonMohammadbagher/NativePayload_BSSID` | GITHUB | Zu alt: 1164d |
| `ekiojp/circo` | GITHUB | Zu alt: 1177d |
| `Skiller9090/Lucifer` | GITHUB | Zu alt: 1373d |
| `anfractuosity/ultrasonicnetworking` | GITHUB | Zu alt: 1508d |
| `drivebadger/drivebadger` | GITHUB | Zu alt: 1573d |
| `OlivierLaflamme/DNSWho` | GITHUB | Zu alt: 2031d |
| `soapbucket/sbproxy` | GITHUB | Größe: 0 IPs |
| `aziontech/azion-console-kit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corazawaf/coraza-spoa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FWGS/xash3d-fwgs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `imperva/terraform-provider-incapsula` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coreruleset/coreruleset` | GITHUB | IP-Datei 41d alt |
| `kejilion/sh` | GITHUB | IP-Datei 773d alt |
| `corazawaf/coraza` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wallarm/docker-wallarm-node` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hoangtuvungcao/mango-waf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chen2he/orange-cloud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fuomag9/caddy-proxy-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zentinelproxy/zentinel` | GITHUB | IP-Datei 176d alt |
| `jx-sec/jxwaf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mr-xn/BurpSuite-collections` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f5devcentral/NGINX-Declarative-API` | GITHUB | IP-Datei 207d alt |
| `matrixleons/evilwaf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uwaserver/uwas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corazawaf/coraza-caddy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corazawaf/libinjection-go` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microlinkhq/is-antibot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `roxy-wi/roxy-wi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coreruleset/go-ftw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `416rehman/DeepZero` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201` | GITHUB | Zu alt: 99d |
| `onlytoxi/CVE-2025-8088-Winrar-Tool` | GITHUB | Zu alt: 359d |
| `x86byte/Stuxnet-Rootkit` | GITHUB | Zu alt: 697d |
| `CloudDefenseAI/falco_extended_rules` | GITHUB | Zu alt: 888d |
| `AgainstTheWest/NginxDay` | GITHUB | Zu alt: 1583d |
| `TinToSer/ios-RCE-Vulnerability` | GITHUB | Zu alt: 2570d |
| `kubeshark/kubeshark` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EONRaider/violent-python3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3proxy/3proxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pasadoorian/fettle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yokai-2510/tg_tl_first_tick_zerodha` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ammy215/Honeypot-system` | GITHUB | Größe: 0 IPs |
| `logseeker/logseeker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `leizongmin/ZeroWeb` | GITHUB | IP-Datei 65d alt |
| `nerolabs/silt` | GITHUB | Größe: 0 IPs |
| `sworrl/ClAudit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `asr-orzz/MatchCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pricewill1995/totalosint-v15-osint-tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MajidAkramKashmiri/ccs-chicago` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `domcolelak/outside` | GITHUB | Größe: 0 IPs |
| `Gilamonster-Foundation/newt-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PostPerfection/imfwizard` | GITHUB | Größe: 0 IPs |
| `aeoncity-hub/my-aeon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AuvroIslam/Entitle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maravento/uhm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `patirckk1994/tradep2p2` | GITHUB | Größe: 0 IPs |
| `anketci54-coder/coinoskobi-dexbot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gveerendra8356/vulnara-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manuelmoreira82/datuva-es` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Chau143/Microsoft-Sentinel-Playbooks-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bamfs1976-art/gameweek-edge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `paraday960/Game` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aphilp1/stormwatch-live` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joerodriguez/kioku-enclave` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mostafaafrouzi/TelegramToolsBot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kochj23/nova-journal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `proxmint/free-proxy-list` | GITHUB | Overlap zu gering: 7.8% |
| `zfd430792-coder/Testbot-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `santosdev11/BotComDCiber` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enriqueHV/holaVEcinos-web-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hayalows/v2trading` | GITHUB | Größe: 0 IPs |
| `developers-insights/comunidad-latina` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hmalviya9/lockdownindia` | GITHUB | IP-Datei 109d alt |
| `NizamuddinSameer-1/yt-comment-reply` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Brantlab/Alerts-VWCERT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OtezVikentiy/gotcha` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ARUNAVA85/arunava85.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HetavChaudhari/GECP-Placement-Portal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ayvazyan10/asterisk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Linsars/ip-risk-data` | GITHUB | Größe: 0 IPs |
| `hr-mes/ermete-os` | GITHUB | Größe: 0 IPs |
| `Sals3-Official/sals3-portal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `castrojo/destiny-vids` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joryirving/home-ops` | GITHUB | IP-Datei 72d alt |
| `enesakmehmet/Davet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iAnonymous3000/site-behavior-lab` | GITHUB | Größe: 0 IPs |
| `BicameralAI/bicameral-integrations` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swsloan/eh-investigator-agent` | GITHUB | Größe: 0 IPs |
| `akashmandole/pkmn-alert` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dgocker/uz801-display` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evilkels/ai-clip-assembler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shihap12/byd-voice-assistant` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joshclark-xyz/genysis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NicolasAllevato/OPSYN-Landing-Page` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `officialputuid/KangProxy` | GITHUB | Identischer Inhalt wie officialputuid_proxyforeveryone |
| `officialputuid/KangProxy` | GITHUB | Identischer Inhalt wie officialputuid_proxyforeveryone_proxies |
| `MohammadAsad0/elevate-people` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XHLEIK/Hisab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vayuport/vayuport` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joeljediel17/Joel-Figueroa-PR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hayredin950/Hayredin950` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ANIKETCHAND/AP-console` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Seijin18/EVI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shaneowenmichelon-hub/College-Marketing-Agency-site` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `review-yeti-ai/review-yeti-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Search-In/jnpa-uc3-poc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AymanChabbaki/Comments-Remover` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JithendraNara/tplinkctl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marica7731/daily-song-list` | GITHUB | Größe: 0 IPs |
| `itsnaaur/kondo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `labbersanon/sakms` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gorka2354/zarya-terminal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ishioni/homelab-ops` | GITHUB | IP-Datei 973d alt |
| `paulrobinson010/CycleHUD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RajaMuhammadAwais/RISKX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `clanford06/op-price-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `will-white/home-k8s-cluster` | GITHUB | Größe: 0 IPs |
| `p4v1c/GamecoreRenew` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zachproffitt/builder-jobs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AxonOS-BCI/axonos-community-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Instinctes/nightfall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fahadi03/abdullah-al-fahad` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Venkat5599/KP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rimpianto/mikrotik.mAP2nd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `geekseverin/Port_S` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JoshuaDavid/hex-rl-cot-deconfusion` | GITHUB | Größe: 0 IPs |
| `Oz4462/aegis-messenger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dhawanx9/protective-intel-watch-v3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rix4uni/medium-writeups` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HEMANTH2208/DataVue-AI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ferya3/artaleca` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `quotationyy/2026moonfestbbq` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nezun/let-kasni` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `goodgamebrok/tugasbot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `songyaeji/sec-feed-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Abhishek05git/llm-financial-analyst` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aloworld-org/alo-workplace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gravelfreeman/k8s-gitops` | GITHUB | IP-Datei 93d alt |
| `RioMMO/ProxyFree` | GITHUB | Overlap zu gering: 5.6% |
| `mimetrix/eob-tmm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ClatTribe/tsengine` | GITHUB | Größe: 0 IPs |
| `RAD786/kauffman-garage-doors` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nxck2005/capstone` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yasar882/Windows-Authentication-Threat-Detection-Lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `4ng3lpro114/xayven` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `organics-jpg/kalshi-probability-model-bot-gpt55-export` | GITHUB | IP-Datei 86d alt |
| `pedrolinard/Auth-System` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DeepTempo/flowprep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexmorbo/seasonfill` | GITHUB | IP-Datei 51d alt |
| `consultoriaestercarvalho/semana-da-psicologia-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tanguille/cluster` | GITHUB | Größe: 0 IPs |
| `Vedd-Patel/DarkPulse-Intel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Worren073/NaviCash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aperskii/berqiqch-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BlizzHacker/romarr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lalitprajapat47/Face-Emotion-Music-Player` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `janj2185-svg/Project-Sylora-2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hithim1411-ux/cie-instruments-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `psfaruk/Minimum-pair-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jss-on/autoforge` | GITHUB | Größe: 0 IPs |
| `bcamaterial2023/da-infotech-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Babayaga-commits/waf-blocklist` | GITHUB | Größe: 0 IPs |
| `The-Orange-Way/Orange-Way-Me` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nithindyavegowda/lol` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `talos-kernel/talos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magolito/autobot-scanner-backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitfox-enter/RSSForge` | GITHUB | IP-Datei 31d alt |
| `rsagacom/goudaner-world` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KavehShoorideh/catspace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `StewAlexander-com/live-tech-news` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hukaichun/AgentSouk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KKAIlab/ferroscope` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crossservicesgroup-ai/CrossServicesSite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PleiadesM/Relevance` | GITHUB | IP-Datei 36d alt |
| `wxycs/bdlive-vod` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maheshaggarwal21/raphael` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `redyasar10-web/rigs-registry` | GITHUB | Größe: 0 IPs |
| `BlockChain-BailBonds/archon-sigilagi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kristofdegrave/homeassistant-smart-charging` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jss510/craigslist-westchester-deals` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ernestod1998/Job_Scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RajeshShrirao/opinion-os` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `moWerk/asteroid-docking-bay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mcrombie/colony-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bikki084/My-Mail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yugalredhu097/Transcendents` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coredev-uk/home-ops` | GITHUB | IP-Datei 36d alt |
| `noainred/The.DVC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chule305/alpaca-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PR0M3TH3AN/bitlogin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `donutloop/donutloop-genesis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HammedGado/SOC-Malware-Traffic-Analysis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HansGuaraden/Crypto_Cracker_Tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Extenedi/DeleteShadowCopies` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nileshshrivastav-dev/Portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tannerbroberts/OST-Agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Timtam/rabbit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Trivexion/FscanOutput-Beautify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Team-Triada/triada-news` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AqilJaafree/Angelfish` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `daneshavaran2/parkfava` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Omerfishel/Sapir-Cyber-Learn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mittelsdorfkjell01-sys/dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `theta42/theta-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XxAndysitoxX/nmap-security-vault` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mudler/vllm.cpp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codeformech/coldplay_concert_notifier` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `justinjudefernandes/Tines-SOAR-Integration-with-Wazuh-Automated-Security-Response` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Roberdan/roberdan-os` | GITHUB | Größe: 0 IPs |
| `fariello/agent-workflows` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `donislawdev/BeanNetworkTester` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `georgemourelatos456-sys/Tarmax-asphalt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VitaliyIvanov11/Lacupedas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Anike10/isp_codex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Stevoisiak/Annoyance-Blocklist` | GITHUB | Größe: 0 IPs |
| `whiskybeer/toolrecall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fyphost/linkva.se` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Harshityadav9838/pexora` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ionfury/homelab` | GITHUB | IP-Datei 190d alt |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 31,344 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 17,074 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 11,029 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 9,588 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 538 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 5,943 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,925 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,739 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 2,234 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,508 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,012 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,135 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,345 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 676 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 686 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 532 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 317 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 46,746 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 21,246 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 20,140 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 8,763 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,228 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,337 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 2,528 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 204,109 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,172 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,157 | 2.6% | 116 | 2026-07-05 |
| `breakingtechfr_proxy_free` | GITHUB | 43,636 | 0.6% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_all` | GITHUB | 46,647 | 0.5% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks4` | GITHUB | 16,351 | 1.9% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks5` | GITHUB | 15,547 | 2.2% | 55 | 2026-07-14 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,627 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 118,856 | 0.1% | 1560 | 2026-08-01 |
| `hookzof_socks5_list` | GITHUB | 160 | 22.1% | 1030 | 2026-08-04 |
| `mohammedcha_proxripper` | GITHUB | 53,227 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,893 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,506 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,523 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 93,231 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,795 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 93,565 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 102,666 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,522 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 93,243 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,199 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 105,967 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 539 | 36.7% | 8 | 2026-07-03 |
| `darzanebor_mikroblack` | GITHUB | 41,628 | 26.6% | 13 | 2026-07-05 |
| `ankaboot_source_email_open_data` | GITHUB | 488,498 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,837 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 171,098 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 177,019 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 140,654 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 109,994 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 105,659 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 121,541 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 100,277 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 196,767 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 61,108 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 101,823 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 36,934 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 28,333 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 24,766 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 24,284 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 22,228 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 32,773 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 14,978 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,384 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,995 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 14,395 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 8,394 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,628 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 7,640 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 5,823 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,987 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 9,465 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 4,970 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,697 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 2,750 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,655 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,576 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,733 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 4,758 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 43,683 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 4,144 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 3,834 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 51,266 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,350 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,038 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,513 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 865 | 17.2% | 9 | 2026-07-08 |
| `sereinfy_adrules` | GITHUB | 1,420 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 82,879 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 286,183 | 22.0% | 6 | 2026-07-08 |
| `gazpitchy92_ip_blocklist_blacklist` | GITHUB | 268,777 | 23.1% | 6 | 2026-08-12 |
| `officialputuid_proxyforeveryone` | GITHUB | 5,090 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 4,262 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 4,721 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,555 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 24 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 69,430 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 75,830 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,144 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 124 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 205,938 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,436 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,683 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 187,542 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 33,823 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 7,486 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 3,484 | 34.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_compromised` | GITHUB | 15,520 | 65.9% | 2 | 2026-08-01 |
| `securitylist1568_fortigate` | GITHUB | 166 | 28.1% | 2 | 2026-08-02 |
| `cyberh4ck3r_free_proxy_list` | GITHUB | 3,139 | 1.7% | 2 | 2026-08-12 |
| `cyberh4ck3r_free_proxy_list_socks4_proxies` | GITHUB | 2,402 | 2.6% | 2 | 2026-08-12 |
| `cyberh4ck3r_free_proxy_list_socks5_proxies` | GITHUB | 1,995 | 3.3% | 2 | 2026-08-12 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 9,987 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 9,972 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n3` | GITHUB | 9,983 | 76.5% | 3 | 2026-08-09 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,056 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 16,174 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 16,291 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,296 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 59,319 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 53,786 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,459 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 128,680 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 517 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,168 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 193,127 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,525 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 121,421 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 132,376 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,237 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 33,309 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 25,195 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 17,078 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,774 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 7,045 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 6,738 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,674 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,628 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 3,500 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,318 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,124 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,533 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,092 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,640 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 3,300 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,924 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,757 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,338 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,004 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 956 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 970 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 935 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 807 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,888 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 746 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,457 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 735 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,279 | 6.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_maltrail_scanners` | GITHUB | 16,854 | 14.9% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_iblocklist_cruzit_web_attacks` | GITHUB | 13,871 | 0.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 5,631 | 5.0% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,127 | 24.2% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,436 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,542 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,209 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 12,201 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,213 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 93,404 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 97,726 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 89,938 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 92,491 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 96,893 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 87,359 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,589 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 49,629 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 123 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets` | GITHUB | 109,725 | 9.4% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 23,840 | 65.2% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 12,608 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 4,142 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,685 | 5.0% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,856 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,520 | 5.8% | 0 | 2026-08-11 |
| `saidurrahman22_linux_av_edr` | GITHUB | 100 | 62.0% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 38,770 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 15,961 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 12,443 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 2,603 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 72 | 63.9% | 0 | 2026-08-12 |

---
*Generiert: 2026-08-12 21:17 CEST (Europe/Berlin)*