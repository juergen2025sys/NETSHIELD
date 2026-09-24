# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-24 23:40 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **11374** |
| davon GitHub (Topics+Code) | **11284** |
| davon GitLab | **90** |
| davon Awesome-Lists | **2400** |
| Tools/Libraries vor Eval gefiltert | **1523** |
| davon Hard-Reject (awesome-Liste etc.) | **164** |
| EVAL-Kandidaten (nach Stratifizierung) | **460** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **460** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **458** |
| Neu angenommene Feed-Dateien | **11** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **192** |
| Abgelehnte Repositories (dieser Run) | **458** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **203** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **163315** |
| SQLite-Refresh-Cache-Hits | **189/192** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **374** |
| Repo zu alt (>30d) | **39** |
| Falsche Größe (<30 / >2,000,000 IPs) | **22** |
| IP-Datei veraltet (>30d) | **19** |
| Overlap mit HQ-Feeds zu gering (<20%) | **4** |
| Sonstige | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `brandontroidl_blocklist_all_90d` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 3,779 | 67.6% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_30d_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 3,438 | 69.3% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_7d_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 857 | 62.7% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_24h_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 399 | 65.7% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_standard_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 101 | 55.4% | 0.0% | 0 | 🆕 NEU |
| `feezony_feezony_ip_blocklist_split` | [feezony/feezony-ip-blocklist-split](https://github.com/feezony/feezony-ip-blocklist-split) | GITHUB | 98,573 | 0.2% | 0.0% | 0 | 🆕 NEU |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | [feezony/feezony-ip-blocklist-split](https://github.com/feezony/feezony-ip-blocklist-split) | GITHUB | 91,166 | 1.5% | 0.0% | 0 | 🆕 NEU |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | [feezony/feezony-ip-blocklist-split](https://github.com/feezony/feezony-ip-blocklist-split) | GITHUB | 92,771 | 1.9% | 0.0% | 0 | 🆕 NEU |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_28` | [feezony/feezony-ip-blocklist-split](https://github.com/feezony/feezony-ip-blocklist-split) | GITHUB | 92,667 | 2.0% | 0.0% | 0 | 🆕 NEU |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | [feezony/feezony-ip-blocklist-split](https://github.com/feezony/feezony-ip-blocklist-split) | GITHUB | 91,351 | 2.2% | 0.0% | 0 | 🆕 NEU |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | [feezony/feezony-ip-blocklist-split](https://github.com/feezony/feezony-ip-blocklist-split) | GITHUB | 88,741 | 2.1% | 0.5% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `cbuijs/hagezi` | GITHUB | Identischer Inhalt wie configserverapps_service_blocklists_blocklist |
| `ErcinDedeoglu/crypto-market-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zsazsa-project/zsazsa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SimulPiscator/AirSane` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `r0075h3ll/Oralyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `devnulli/EvlWatcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DigitalRuby/IPBan` | GITHUB | Zu alt: 34d |
| `Aldaviva/Fail2Ban4Win` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jasonish/evebox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `olegzhr/altprobe` | GITHUB | IP-Datei 139d alt |
| `DCSO/balboa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DCSO/fever` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gl0bal01/malware-analysis-claude-skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeff-nasseri/mikrotik-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cacti/plugin_mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MrAriaNet/Get-IP-Iran` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mirceanton/mikrotik-terraform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2GT-Media-Group-LLC/mikrotik-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `danikf/tik4net` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Davie3/mikrotik-cloudflare-iplist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sakib-m/IP-Prefix-List` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eworm-de/routeros-scripts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vadims06/topolograph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mirceanton/external-dns-provider-mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `napalm-automation-community/napalm-ros` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rekryt/iplist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CA17/TeamsACS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `luqasz/librouteros` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomaae/homeassistant-mikrotik_router` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CodePagol/ISP-Mikrotik-Billing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pfrest/pfSense-pkg-saml2-auth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pfrest/pfSense-pkg-RESTAPI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rbicelli/pfsense-zabbix-template` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Eigenrouter/eigenrouter` | GITHUB | Zu alt: 57d |
| `travisghansen/hass-pfsense` | GITHUB | Zu alt: 61d |
| `felixhaeberle/pfsense-captive-portal` | GITHUB | Zu alt: 65d |
| `Derssa/Torollo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `duggytuxy/syswarden` | GITHUB | IP-Datei 94d alt |
| `cloudnativelabs/kube-router` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qoomon/docker-host` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hknutzen/Netspoc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drduh/config` | GITHUB | IP-Datei 556d alt |
| `lenny-ts/caddy-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `miniupnp/miniupnp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `htrgouvea/nipe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x-way/iptables-tracer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hongwenjun/vps_setup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zhaoweih/Shadowsocks-Tutorial` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jaymzh/iptstate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `heiher/hev-socks5-tproxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ruped24/toriptables2` | GITHUB | Zu alt: 42d |
| `Anipaleja/nginx-defender` | GITHUB | IP-Datei 425d alt |
| `ukanth/afwall` | GITHUB | Zu alt: 49d |
| `FoobarOy/foomuuri` | GITHUB | IP-Datei 177d alt |
| `sepandhaghighi/samila` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Pwnzer0tt1/firegex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `voxpupuli/puppet-nftables` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `openwrt/firewall4` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexhaydock/pinewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zywe03/realm-xwPF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pymumu/smartdns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pspete/psPAS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MelisaPeteRs2006/Silent-Crypto-Miner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ruzickap/malware-cryptominer-container` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bia-technologies/rat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `canarddu38/DUCKSPLOIT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ericfreese/rat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hacker-nk/online-hackings` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hacker-nk/online-hacking` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AdvDebug/NoMoreCookies` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HasnainDarkNet/AndroRAT12` | GITHUB | Zu alt: 34d |
| `hamzaharoon1314/SpyNote` | GITHUB | Zu alt: 42d |
| `NullCode1337/NullRAT` | GITHUB | Zu alt: 47d |
| `Ladysnake/RATs-Mischief` | GITHUB | Zu alt: 58d |
| `RatInABox-Lab/RatInABox` | GITHUB | Zu alt: 77d |
| `loafiieee/Lo4f-Malware` | GITHUB | Zu alt: 103d |
| `Pericena/Droidjack` | GITHUB | Zu alt: 104d |
| `pathetic/async-rust-rat` | GITHUB | Zu alt: 128d |
| `bigratmonster/bigrat.monster` | GITHUB | Zu alt: 143d |
| `AryanVBW/ANDRO` | GITHUB | Zu alt: 178d |
| `someshsrichandan/RavanRAT` | GITHUB | Zu alt: 197d |
| `arsium/EagleMonitorRAT` | GITHUB | Zu alt: 211d |
| `NoahOksuz/OSRipper` | GITHUB | Zu alt: 216d |
| `Kr9jd/HotRAT` | GITHUB | Zu alt: 252d |
| `jxroot/ZeroPulse` | GITHUB | Zu alt: 267d |
| `DeskX11/DeskX` | GITHUB | Zu alt: 276d |
| `FujiwaraChoki/BlxdMoon` | GITHUB | Zu alt: 276d |
| `WhiteeRabbit/Triton_RAT` | GITHUB | Zu alt: 284d |
| `Gagniuc/Malware-Scanner` | GITHUB | Zu alt: 297d |
| `AryanVBW/Andro-CLI` | GITHUB | Zu alt: 332d |
| `alby77689-design/Wuzen-Framework---Advanced-Mobile-Security-Research-Platform` | GITHUB | Zu alt: 355d |
| `Suburbanno/SWRATT` | GITHUB | Zu alt: 369d |
| `Cvar1984/sussyfinder` | GITHUB | Größe: 0 IPs |
| `yasserbdj96/hiphp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bboylyg/BackdoorLLM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fahrj/reverse-ssh` | GITHUB | Zu alt: 67d |
| `sagsooz/Webshell-bypass` | GITHUB | Zu alt: 78d |
| `tuconnaisyouknow/BadUSB_adminAccountCreator` | GITHUB | Zu alt: 99d |
| `carloslack/KoviD` | GITHUB | Zu alt: 116d |
| `Aegrah/PANIX` | GITHUB | Zu alt: 211d |
| `amaitou/DarkSpy` | GITHUB | Zu alt: 247d |
| `VoxelHax/OpenBukloit` | GITHUB | Zu alt: 262d |
| `reveng007/reveng_rtkit` | GITHUB | Zu alt: 292d |
| `azuk4r/nmap_backdoor` | GITHUB | Zu alt: 331d |
| `bitsadmin/revbshell` | GITHUB | Zu alt: 337d |
| `MadExploits/Gecko` | GITHUB | Zu alt: 412d |
| `iplocate/free-proxy-list` | GITHUB | Overlap zu gering: 1.1% |
| `zloi-user/hideip.me` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gfpcom/free-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dpangestuw/Free-Proxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sunny9577/proxy-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `papapapapdelesia/Emilia` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MrMarble/proxy-list` | GITHUB | Overlap zu gering: 3.1% |
| `Surfboardv2ray/TGParse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mauricegift/free-proxies` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `berkay-digital/Proxy-Scraper` | GITHUB | Overlap zu gering: 5.3% |
| `vakhov/fresh-proxy-list` | GITHUB | IP-Datei 229d alt |
| `fyvri/fresh-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ProxyScraper/ProxyScraper` | GITHUB | Overlap zu gering: 1.4% |
| `Skillter/ProxyGather` | GITHUB | IP-Datei 75d alt |
| `por-cli/por-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nfx/slrp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `awarexone/Agentic-Bug-Hunter` | GITHUB | Größe: 0 IPs |
| `SEKOIA-IO/automation-library` | GITHUB | IP-Datei 162d alt |
| `mitre-attack/attack-website` | GITHUB | IP-Datei 787d alt |
| `7onez/cti-expert` | GITHUB | IP-Datei 68d alt |
| `ibnaleem/rules` | GITHUB | IP-Datei 109d alt |
| `rulezet/rulezet-core` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SEKOIA-IO/Community` | GITHUB | IP-Datei 937d alt |
| `jonaylor89/sherlock-rs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ibnaleem/gosearch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ictinnovations/ictcore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `soxoj/telegram-bot-dumper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre-attack/attack-navigator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gameworkerkim/CYBER-THREAT-INTELLIGENCE-REPORT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RansomLook/RansomLook` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThreatRecall/zettelforge` | GITHUB | IP-Datei 162d alt |
| `blackstork-io/blackstork-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ictinnovations/ictagent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EvoluxBR/greenswitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `INFOKOM-KI/Wazuh-MCP-Server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SpinalHDL/VexRiscv` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elsechord/CyberGuard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `M507/AI-SOC-Agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sec-Link/Argus-Agentic-SOC-Platform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `freelabz/secator` | GITHUB | Größe: 0 IPs |
| `soxoj/maigret` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pzaino/thecrowler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0dayInc/pwn` | GITHUB | IP-Datei 891d alt |
| `ejfkdev/dj` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AynOps/AynOps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenOSINT/OpenOSINT` | GITHUB | Größe: 0 IPs |
| `AnonCatalyst/Ominis-OSINT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `olizimmermann/s3dns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stanislav-web/OpenDoor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cyreslab-AI/shodan-mcp-server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `leebaird/discover` | GITHUB | Größe: 0 IPs |
| `nikitastupin/orgs-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zyrexnn/Cybermes` | GITHUB | IP-Datei 36d alt |
| `referefref/modpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/honeybits` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sjinks/ssh-honeypotd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nsmfoo/dicompot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/weblogic_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hugsy/codebro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpr5/ngrep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `phdphuc/mac-a-mal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CyberShadow/RABCDAsm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `quark-engine/quark-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JamesHabben/evolve` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vivisect/vivisect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xd4d/de4dot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codypierce/hackers-grep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AbertayMachineLearningGroup/CryptoKnight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/iocs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `devttys0/binwalk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ytisf/muninn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/flare-floss` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `msuhanov/regf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MITRECND/chopshop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jessek/hashdeep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misterch0c/malSploitBase` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rurik/Noriben` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elceef/dnstwist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cisco-Talos/ROPMEMU` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LDO-CERT/orochi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/ember` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aquynh/capstone` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NationalSecurityAgency/ghidra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dynetics/Malfunction` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hugsy/gef` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/yarGen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ashishb/android-security-awesome` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre/multiscanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `owasp-amass/amass` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NovaCode37/Prism-platform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaifcodec/user-scanner.git` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wireservice/csvkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `narkopolo/fb_friend_list_scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FlowingMedia/TimeFlow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sundowndev/PhoneInfoga` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s0md3v/Photon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dgtlmoon/changedetection.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gorhill/uBlock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fauvidoTechnologies/PyBrowserAutomation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OSINTI4L/cupidcr4wl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yt-dlp/yt-dlp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spmedia/Crypto-Scam-and-Crypto-Phishing-Threat-Intel-Feed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `p1ngul1n0/blackbird` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atiilla/OsintEye` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/spotify_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bevigil/BeVigil-OSINT-CLI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `matiash26/steam-osint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/lastfm_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `six2dez/reconftw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AbdaullahAG/Threat_Intel_Project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s-rah/onionscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hamodywe/telegram-scraper-TeleGraphite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jsvine/waybackpack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `obitouka/InstagramPrivSniffer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `david3107/squatm3gator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3nock/sub3suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `heldersepu/gmapcatcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khashashin/ogi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/Wayback-Archive` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loseys/Oblivion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atiilla/gitrecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `subzeroid/insto` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drego85/tosint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s0md3v/Zen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cybersader/WebsiteTechMiner-py` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mantisfury/ArkhamMirror` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cga-harvard/Data_Science_Big_Data_Projects` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tejado/telegram-nearby-map` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hmaverickadams/DeHashed-API-Tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mxrch/GHunt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ANG13T/SatIntel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rmusser01/Infosec_Reference` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GreyNoise-Intelligence/pygreynoise` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bibanon/tubeup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `milo2012/osintstalker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vognik/maltego-telegram` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/github_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qeeqbox/social-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shadawck/glit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `akamhy/waybackpy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `seekr-osint/seekr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spmedia/Telegram-Channel-Joiner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/lol_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `l4rm4nd/LinkedInDumper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khast3x/h8mail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vericle/intellyweave` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hstsethi/in-mob-prefix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vflame6/leaker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TeehanLax/Hyperlapse.js` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Berchez/OSINT-steam` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IvanGlinkin/CCTV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomnomnom/waybackurls` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3nock/SpiderSuite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lissy93/personal-security-checklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s0md3v/Orbit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `finos/perspective` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aydinnyunus/exiflooter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Datalux/Osintgram` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atenreiro/opensquat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sockysec/Telerecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lukeslp/antisocial` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DataSploit/datasploit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `megadose/toutatis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomsec8/IntelHub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `snooppr/snoop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sqren/fb-sleep-stats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `megadose/holehe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Turner-Levey/section-16-deadline-calculator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/spotify_profile_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `proseltd/Telepathy-Community` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tsale/TeleTracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Moresyl/metaclean` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eth0izzle/the-endorser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Pumpurri/domino-trainer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HellManu/Horus-Eye` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `remarkablepc/WINBARS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bwoods1998/long-term-capital-management` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fabfish/clfly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Roarge/sysml-federation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mbace1/Suds-Jack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EritikWoW/RansomGuard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ZenonPB/agente-prospeccao` | GITHUB | Größe: 0 IPs |
| `Hmouhaned/MarketMuse-Keyless-Access-Bundle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `idanbuller/DetectionEngineering` | GITHUB | Größe: 0 IPs |
| `knndphr/fh4-garage-swap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `defenw29-svg/laboratorio-de-defensa-de-Docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `L0lopop/Link-Guard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `king55581/Bluestacks-5-Kitsune-Root` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `raheshcse/Email-Spam-Detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sugeng69/nmap-security-scanner-8.10-full` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `destinaga-cpu/nitro-pdf-suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bhodgs01/bot-farm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rnehra220-afk/village-poll` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `niti3/nx-filter-legacy-releases` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XxcarrasgodxX/C0py-Pr0tect-Byp4ss` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kibertoad/chaos-overlords-new-chrome` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pooya23/watchdog-anti-malware-4-3-34-repack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vincamok/goproxify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pkqv8s4w6w-cmyk/Mcclient` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CryptoJones/OSApplyTrack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sneat-dev/wb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-crypto` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sanchomuzax/PicasaPy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uchetsai-creator/project_starter_v5` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ducloves/content-bot-pro-ultra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jess-maina/avast-security-toolkit-suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maximilianfeix/proxy-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nuku/Emberhold` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `archessar/smartshow-3d-2024-edition` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `victorisaaz-bot/prime-edge-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TongIncomeWheel/AQE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `githaltwastaken/Overtone` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yivas/pi-setup-share` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AbdaullahAG/AbdaullahAG` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DranakCorps-bot/EQBuddy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alporokh/imarket2web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kevin9327/kevin9327` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Okura66/kahn1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xin10ylop/fomo-memebot` | GITHUB | Größe: 0 IPs |
| `ThorOdinson246/whatisit-nl2sh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TaNiShK1911/HHGoa_Task-4` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MonarchCastleTech/cyber-exposure-map` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Andy87877/GitHub-Star-Manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aponanwar/al-insaf-general-hospital` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Taran8851/surviden` | GITHUB | Größe: 0 IPs |
| `javaNoviceProgrammer/Ngspice_OpenVAF_Enhancements` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Githubhshzhzhzshdhehehshhdhdhdhejjshhs/mobikin-transfer-pro-mobile` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `issaquahd/cloudlabworks-site` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zmoham1/jboard_zm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arijitpodder/VerifAI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iwannis0/found-digital-growth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `theia-hq/tightbeam` | GITHUB | Größe: 0 IPs |
| `Dyslectric/ThreadBNC` | GITHUB | Größe: 0 IPs |
| `meghanshsahu/Roon-1-8-No-Authentication-Patch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rackbops/rackbops-discord-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alishahid003-droid/gem-alert-s1c` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GasDirect/employee-ordering-site` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Binaryzero/Waveshare-Widgets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `psandhir/horustrace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `essam12e/JADDID` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `emathier/optiboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gunn4r/uo-pack-rat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fizzl13/presign-guard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BehnamJalaliCo/CoinePro-App` | GITHUB | Größe: 0 IPs |
| `GG8000/wordleaf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pairomaniac/sr2-patcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `peterdtitan/seda-storefront` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `riteshekbote/cycode-hunt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-hermes-skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `opensoft/openxFactory` | GITHUB | Größe: 0 IPs |
| `enhansome/enhansome-cdk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ethanbell528-cmd/fda-project-1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NTPhong04102k4/AioKin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `submerseknights318/As-One-We-Survive-Compact` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `engenhariainversa/termhub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keshavgarg24/tokunseba` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xdubois-57/scoutmagic` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PLANETA9091/privateB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gmi-security/Vuln` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SysAdminDoc/OpenRadar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zxaylex/sentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `7m7n/Cyber-Oman-Shield-v1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `svagionitis/PelcoD-Controller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `essisoli1996/pretrade-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jesus-Escala/solvia-landing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dlacksgud11111-tech/news-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `John-UNOwen/Mirako-Machine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HOMEPAD2026/HOMEPAD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FlorentLatifi/Gjurm-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `electrocrem/neon-shell` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `patriciobo/noticias-geopolitica` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jluisreyvargas/tfm-alerta-temprana-oob-backup` | GITHUB | IP-Datei 131d alt |
| `rezabehroozi/4so-platform-factory` | GITHUB | Größe: 0 IPs |
| `jluisreyvargas/tfm-alerta-temprana-oob` | GITHUB | IP-Datei 131d alt |
| `msapgroup/Godseye` | GITHUB | Größe: 0 IPs |
| `amalsebstn/applyai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MaxGuzman0715/tryvera` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JTHEPA/Sentry-correlate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CostaSurvivor/xat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Wondermonger-daydreaming/latent-lisp` | GITHUB | Größe: 0 IPs |
| `htwsy/writing-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omacom/omarchy-plugin-marketplace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zarrouk-Meriem/jilaltufan-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abdurrehmansajidhafiz1-cell/trading-scanner-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sandrikkk/real-estate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ironman1pro/roofing-agency-site` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MichaelDViau/webOrg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `seetrex-hq/trust-monitor` | GITHUB | IP-Datei 58d alt |
| `alexandrec90/devkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sushishy/AutoTali` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `absence-1962phoneme/Pragmata-Community-Edition` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vahidlesani/smc-scanner2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ashrafiucse/security-audit-skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wiles7-molder/The-Whims-of-the-Gods-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tiberiumilitaru89/portofoliu-tiberiu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tohudgins/Homelab` | GITHUB | Größe: 0 IPs |
| `LucaFrankfurt/AIfirstPMO` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `k8se10/MW32011NCP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LucasSavio31/WMS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sjpurtill-ui/tomorrow-and-tomorrow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0abir/amardns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PeshoVurtoleta/lite-logn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jtmasters3/nfl-news-hub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ApatheticMioz/Anser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kirubaLS/research-sample` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `remiotore/log-timeline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mediactl/clustarr` | GITHUB | Größe: 0 IPs |
| `v3ni94/IMMOWARE24` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `akashmandole/pkmn-alert` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UnknownDev2018/Kov-Sec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Levango7/MAOP` | GITHUB | IP-Datei 45d alt |
| `enchi244/TagHunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FreeCuli/zero-cloud-hardware-architecture` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `barleezy/Lexi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Olivaire/sleep-duck-eye` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cenetex/ilXyr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beechnutjaundice74065/Dungeons-And-Furry-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rkittan7/panelvault` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mike1978uk/win95-intel-inboard-386pc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mahin820-tech/mahin820-tech` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UBIQRA/cyber-threat-intelligence-program` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ardhtor/GEEHUB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3ldr1tch/enterprise-pivot-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qzyu999/inference-exchange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ratul-netizen/veyronis` | GITHUB | Größe: 0 IPs |
| `Fused-Gaming/campaign-graph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WelcomeToYourGalaxy/sports-feed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gdoteof/chuggy-fabric` | GITHUB | Größe: 0 IPs |
| `jampick/retrogrid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benabdinadama-hash/mvs-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ai-positon2/intelligence-platform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hopetmpy/ABOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Skram-Games/Word-Scrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HamieTon-Dev/ACII_TD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Laufbursche42/tr-lb-edition` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johalputt/VayuPress` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OPX-Aminul/OPX-Demon` | GITHUB | Größe: 0 IPs |
| `tamar1818/orbita-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coyotecontuses341218/Too-Deep-To-Quit-Beta-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dumb-Tony/MoonGoons` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `garb-heap74/Wardens-of-Avalon-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `procorners-labs/school-app-yemen-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ychua-tech/app-amazonas-PWA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sampathmannam/dailybeat-fdroid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `haranguearraign-325/Among-Shadows-Beta-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ozaneski13/gh2discord` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafael-alani/dothomelab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vaultureau/Vaultureau` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `biptybop/netwho` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jwal7000/menu-display-horizontal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `possn/Vestra` | GITHUB | Größe: 0 IPs |
| `Back-Road-Creative/band-coach` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 32,031 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 19,409 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,404 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 11,701 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,837 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,772 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,753 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 3,064 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,953 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,847 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,604 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,312 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 931 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 771 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 781 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 654 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 435 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,143 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,681 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 18,060 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 10,347 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,881 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,509 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,909 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 212,199 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,520 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,732 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,628 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 1,978 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,713 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 11,645 | 64.3% | 938 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 53,482 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,790 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,824 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 116,264 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 91,500 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,217 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,236 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 106,185 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,754 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 122,192 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,573 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 124,536 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 686 | 36.7% | 8 | 2026-07-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist_full` | GITHUB | 129,811 | 49.1% | 8 | 2026-09-24 |
| `ankaboot_source_email_open_data` | GITHUB | 476,242 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,445 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 172,410 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 170,949 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 137,652 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 154,061 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 102,127 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 112,706 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 97,505 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 233,293 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 57,443 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 176,371 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 35,448 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 28,404 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 25,977 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 23,774 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 22,468 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 177,634 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,519 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 12,991 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 6,441 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 21,077 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 13,674 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,394 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 11,165 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 7,198 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 3,109 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 11,370 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 6,116 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,991 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 4,662 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,277 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,759 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,894 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,881 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 102,259 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 2,160 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,421 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 58,970 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 4,019 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_1d` | GITHUB | 3,778 | 80.5% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 3,395 | 79.4% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_threat_intelligence` | GITHUB | 61,038 | 41.0% | 10 | 2026-09-24 |
| `ian_lusule_proxies` | GITHUB | 3,562 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,678 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,385 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 266,902 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 7,922 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 6,787 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 7,396 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,486 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 89 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 95,139 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 96,910 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,557 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 40 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 96,497 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,823 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,708 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 147 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 17,403 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 17,263 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 21,126 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,360 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 60,295 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 62,490 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,728 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 130,063 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 350 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,167 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 195,346 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,533 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 130,055 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 203,021 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 36,253 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 22,584 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 19,549 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,728 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 9,969 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,223 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,638 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 5,184 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,555 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,121 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,529 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 4,859 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,769 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 5,786 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 3,888 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,215 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,365 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,372 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,309 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,290 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,112 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,176 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,784 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,144 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,438 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 688 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,963 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,673 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 983 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 11,854 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,421 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 91,941 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 87,642 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 95,080 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 93,099 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 91,976 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 89,670 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 22,271 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 51,901 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 11,668 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,822 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,692 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,000 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,080 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 42,142 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 20,253 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 12,016 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 6,152 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 40 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 28,539 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 154,005 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 24,635 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 2,929 | 5.1% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,141 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,362 | 9.3% | 0 | 2026-09-13 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,378 | 66.1% | 0 | 2026-09-20 |
| `brandontroidl_blocklist` | GITHUB | 3,778 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,466 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 877 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 430 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 105 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 5,916 | 20.6% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_90d` | GITHUB | 3,779 | 67.6% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d_v2` | GITHUB | 3,438 | 69.3% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d_v2` | GITHUB | 857 | 62.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h_v2` | GITHUB | 399 | 65.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard_v2` | GITHUB | 101 | 55.4% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 98,573 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 91,166 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 92,771 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_28` | GITHUB | 92,667 | 2.0% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 91,351 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 88,741 | 2.1% | 0 | 2026-09-24 |

---
*Generiert: 2026-09-24 23:40 CEST (Europe/Berlin)*