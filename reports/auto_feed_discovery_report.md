# Auto Feed Discovery – Report
**Aktualisiert:** 2026-10-25 10:22 CET (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **11637** |
| davon GitHub (Topics+Code) | **11541** |
| davon GitLab | **96** |
| davon Awesome-Lists | **2396** |
| Tools/Libraries vor Eval gefiltert | **1613** |
| davon Hard-Reject (awesome-Liste etc.) | **196** |
| EVAL-Kandidaten (nach Stratifizierung) | **459** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **459** |
| davon angenommene Repositories | **3** |
| davon abgelehnte Repositories | **456** |
| Neu angenommene Feed-Dateien | **3** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **199** |
| Abgelehnte Repositories (dieser Run) | **456** |
| davon GitLab abgelehnt | **27** |
| Feeds gesamt (aktiv) | **202** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **140628** |
| SQLite-Refresh-Cache-Hits | **5/200** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **345** |
| Repo zu alt (>30d) | **79** |
| Falsche Größe (<30 / >2,000,000 IPs) | **16** |
| IP-Datei veraltet (>30d) | **15** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `helio4k_bad_ip` | [helio4k/Bad-IP](https://github.com/helio4k/Bad-IP) | GITHUB | 2,019 | 43.3% | 0.0% | 0 | 🆕 NEU |
| `cbuijs_hagezi` | [cbuijs/hagezi](https://github.com/cbuijs/hagezi) | GITHUB | 30,620 | 40.7% | 0.0% | 128 | 🆕 NEU |
| `verkombr_block_list_firewalls` | [verkombr/BLOCK-LIST-FIREWALLS](https://github.com/verkombr/BLOCK-LIST-FIREWALLS) | GITHUB | 32 | 46.9% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `Cludes/botnet-live-maps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cognis-digital/c2detect` | GITHUB | Zu alt: 42d |
| `openwrt/packages` | GITHUB | IP-Datei 927d alt |
| `carbonblack/cbfeeds` | GITHUB | Zu alt: 1300d |
| `0x6rss/matkap` | GITHUB | Zu alt: 61d |
| `alexandreborges/malwoverview` | GITHUB | Zu alt: 33d |
| `SpecterOps/at-ps` | GITHUB | Zu alt: 2468d |
| `cporter202/API-mega-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dreadl0ck/netcap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iagox86/dnscat2` | GITHUB | Zu alt: 955d |
| `A-poc/BlueTeam-Tools` | GITHUB | Zu alt: 63d |
| `Owlinkai/redroom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pe3zx/my-infosec-awesome` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frangelbarrera/OSINT-BIBLE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XORCISM-AI/XORCISM` | GITHUB | Zu alt: 57d |
| `interplains/zero-breach` | GITHUB | Overlap zu gering: 0.0% |
| `helixmap/sigwood` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `isms-core-project/isms-core-platform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rookiestar28/ComfyUI-OpenClaw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iamrajivd/pentest` | GITHUB | Zu alt: 2164d |
| `amayer1983/docksentry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neatlabs-ai/packet-capture-analyzer` | GITHUB | Zu alt: 247d |
| `Ignitetechnologies/Command-Control` | GITHUB | Zu alt: 2178d |
| `valITino/OSINToolKit` | GITHUB | Zu alt: 33d |
| `HalilDeniz/RansomwareSim` | GITHUB | Zu alt: 877d |
| `Dev-Lahrani/Thor` | GITHUB | Zu alt: 37d |
| `fwerkor/CapOS` | GITHUB | IP-Datei 219d alt |
| `GChristensen/enso-portable` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ropensci/googleLanguageR` | GITHUB | Zu alt: 264d |
| `yasirhamza/AndroDR` | GITHUB | Größe: 0 IPs |
| `CTI-Driven/Advanced-Threat-Hunting-Ransomware-Groups-Affiliates` | GITHUB | Zu alt: 473d |
| `SARATOGAMarine/WP-Cybersecurity-Assorted-Tools` | GITHUB | Zu alt: 1725d |
| `AgentiaPT/agentia-research` | GITHUB | Zu alt: 174d |
| `TheEddMan/osint-ioc-collector` | GITHUB | Größe: 1 IPs |
| `bitdefender/Bitdefender-Threat-Connect-integration-app` | GITHUB | Zu alt: 2462d |
| `timetology/NetWitness` | GITHUB | Zu alt: 1518d |
| `danielgottt/CyberBodega` | GITHUB | Zu alt: 255d |
| `oasis-tcs/openc2-usecases` | GITHUB | Zu alt: 1649d |
| `yusufsaka007/stierlitz` | GITHUB | Zu alt: 518d |
| `tncsharetool/worldmonitor` | GITHUB | Zu alt: 234d |
| `rickkdev/worldwatcher` | GITHUB | Zu alt: 158d |
| `Azure/Industrial-IoT` | GITHUB | IP-Datei 859d alt |
| `HackTricks-wiki/hacktricks-cloud` | GITHUB | Größe: 0 IPs |
| `MBCProject/mbc-markdown` | GITHUB | Zu alt: 500d |
| `kimd155/QuickResponseC2` | GITHUB | Zu alt: 167d |
| `raj3shp/malscore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lambdaclass/lambdaclass_hacking_learning_path` | GITHUB | Zu alt: 286d |
| `mevaibhavpandey/Maritime-Situational-Awareness` | GITHUB | Zu alt: 208d |
| `Mafifrizi/ARES` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rajmahadevan/kql-lab` | GITHUB | Zu alt: 1071d |
| `HadessCS/Red-team-Interview-Questions` | GITHUB | Zu alt: 562d |
| `blueteamvillage/Project-Obsidian-DC30` | GITHUB | Zu alt: 886d |
| `myguard-labs/nginx-http-sentinel-module` | GITHUB | Zu alt: 76d |
| `all-contributors/allcontributors.org` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alsyundawy/Microsoft-Office-For-MacOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cbuijs/ipasn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `romainmarcoux/malicious-hash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Garyson26/SecOps-IOCs-Radar-X-Twitter` | GITHUB | Zu alt: 37d |
| `muchdogesec/obstracts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xMarcio/pocindex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EndlessFractal/Threat-Intel-Feed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RavinduRathnayaka/LiveThreatMap-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mandiant/capa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecureWithUmer/Exploit-Index` | GITHUB | IP-Datei 109d alt |
| `osintbrazuca/osint-brazuca` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deeztek/Hermes-Secure-Email-Gateway` | GITHUB | IP-Datei 127d alt |
| `lewiswigmore/virus.xcheck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `threathunterX/underground-slang-lexicon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VoidSecSoftwares/voidsyscall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `K4N3CO/Lab-RATS-v1.6` | GITHUB | IP-Datei 41d alt |
| `maxDcb/C2TeamServer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SquidSec/SquidC5` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LAME-Projects/stratum-c2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `The-Z-Labs/bof-launcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `b23r0/Heroinn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CroodSolutions/BeaconatorC2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `not-sekiun/Consortium` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rubby2001/Rshell-client` | GITHUB | Zu alt: 44d |
| `ilynyne/discord-bot-ddos` | GITHUB | Zu alt: 45d |
| `Kxiandaoyan/github-C2` | GITHUB | Zu alt: 46d |
| `Team-intN18-SoybeanSeclab/prtstrike` | GITHUB | Zu alt: 50d |
| `CyberCoreAccess/BMHacker-Botnet` | GITHUB | Zu alt: 38d |
| `cyanfish/naps2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TomVN107080/packet-warden` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenFilters/internet-scanners` | GITHUB | IP-Datei 135d alt |
| `Marven11/Fenjing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `akha-security/akca` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nullmoth/1401-probe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GiorgiaAuroraAdorni/smart-receipt-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wpscanteam/wpscan` | GITHUB | IP-Datei 2951d alt |
| `claude-world/claude-skill-antivirus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ramonvermeulen/whosthere` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manuc66/node-hp-scan-to` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bitscoper/bitscoper_cyberkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kristuff/abuseipdb-cli` | GITHUB | Zu alt: 59d |
| `fuko-php/masked` | GITHUB | Zu alt: 31d |
| `fortinetdev/terraform-provider-fortios` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaisero/fireREST` | GITHUB | Zu alt: 52d |
| `x90skysn3k/brutespray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CyberRoute/bruter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `d4t4s3c/RSAcrack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qtc-de/remote-method-guesser` | GITHUB | Zu alt: 52d |
| `theaog/spirit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yamato-Security/hayabusa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `calebevans/mulder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NotYuSheng/TracePcap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Security-Onion-Solutions/securityonion` | GITHUB | IP-Datei 1195d alt |
| `kunai-project/kunai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x783kb/Threat-Analysis-Handbook` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Garyson26/Wiestell_threatIntel_platform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nebulock-Inc/agentic-threat-hunting-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benscha/KQLAdvancedHunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `a2awais/Threat-Hunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `backbay-labs/clawdstrike` | GITHUB | IP-Datei 62d alt |
| `Cyb3r-Monk/Threat-Hunting-and-Detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kdeldycke/meta-package-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wimpysworld/deb-get` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lbr38/repomanager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mominul/packhub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheDuffman85/linux-update-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AOSC-Dev/oma` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sous-chefs/apt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `avaje/avaje-inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mexirica/aptui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aptly-dev/aptly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `whoahaow/rjsxrd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Pawdroid/Free-servers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Barabama/FreeNodes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zhuhaiuk/free-nodes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MHSanaei/3x-ui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NiREvil/vless` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MahanKenway/Freedom-V2Ray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mheidari98/.proxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LeilaoMi/AutoMergePublicNodes-Optimized` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mahdibland/V2RayAggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `peasoft/NoMoreWalls` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jichangtuijian-cheap/cheap-airports` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sub-store-org/Sub-Store` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `surgioproject/surgio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mahdi0024/ProxyCollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lxhao61/integrated-examples` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddify/Hiddify-Manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mehdirzfx/v2ray-sub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jacobax/snippets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `owasp-amass/resolve` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skjolber/3d-bin-container-packing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joshspeagle/brutus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `agourlay/zip-password-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `daturadev/snapcrack` | GITHUB | Zu alt: 46d |
| `s-kachroo/SamsungPractice` | GITHUB | Zu alt: 50d |
| `RozhakDev/Facemash` | GITHUB | Zu alt: 51d |
| `acepanel/panel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crazy-max/docker-fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `docker-mailserver/docker-mailserver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomMoulard/fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sous-chefs/fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aldaviva/Fail2Ban4Win` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yahuisme/vps-setup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `robertdebock/ansible-role-fail2ban` | GITHUB | Zu alt: 32d |
| `mariusdjen/vpskit` | GITHUB | Zu alt: 41d |
| `defense-cr/defense` | GITHUB | Zu alt: 41d |
| `devnulli/EvlWatcher` | GITHUB | Zu alt: 43d |
| `oluceps/nixos-config` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DCSO/fever` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DCSO/balboa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `g3tsyst3m/BriarIDS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MrAriaNet/Get-IP-Iran` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sakib-m/IP-Prefix-List` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Davie3/mikrotik-cloudflare-iplist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vadims06/topolograph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mirceanton/mikrotik-terraform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beeyev/Mikrotik-RouterOS-automatic-backup-and-update` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mirceanton/external-dns-provider-mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2GT-Media-Group-LLC/mikrotik-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `luqasz/librouteros` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `danikf/tik4net` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cacti/plugin_mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `napalm-automation-community/napalm-ros` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pfrest/pfSense-pkg-RESTAPI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rbicelli/pfsense-zabbix-template` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pfrest/pfSense-pkg-saml2-auth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x-way/iptables-tracer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cloudnativelabs/kube-router` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tozd/docker-external-ip` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `heiher/hev-socks5-tproxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hknutzen/Netspoc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `miniupnp/miniupnp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lenny-ts/caddy-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zhaoweih/Shadowsocks-Tutorial` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Derssa/Torollo` | GITHUB | Zu alt: 31d |
| `qoomon/docker-host` | GITHUB | Zu alt: 33d |
| `htrgouvea/nipe` | GITHUB | Zu alt: 42d |
| `Pwnzer0tt1/firegex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `black-desk/cgtproxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pspete/psPAS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ruzickap/malware-cryptominer-container` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MelisaPeteRs2006/Silent-Crypto-Miner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bia-technologies/rat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ericfreese/rat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `canarddu38/DUCKSPLOIT` | GITHUB | Zu alt: 34d |
| `Hacker-nk/online-hackings` | GITHUB | Zu alt: 53d |
| `Hacker-nk/online-hacking` | GITHUB | Zu alt: 53d |
| `AdvDebug/NoMoreCookies` | GITHUB | Zu alt: 61d |
| `Garmask/SilverRAT-FULL-Source-Code` | GITHUB | Zu alt: 71d |
| `yasserbdj96/hiphp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marcocesarato/PHP-Antimalware-Scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bboylyg/BackdoorLLM` | GITHUB | Zu alt: 47d |
| `dpangestuw/Free-Proxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zloi-user/hideip.me` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gfpcom/free-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sunny9577/proxy-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `paulpc/nyx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `1aN0rmus/TekDefense-Automater` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/Loki` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abhinavbom/Threat-Intelligence-Hunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KasperskyLab/klara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dougiep16/actortrackr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/jager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `S03D4-164/Hiryu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mlsecproject/tiq-test` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CrowdStrike/CrowdFMS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EclecticIQ/cabby` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ptr32Void/OSTrICa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yahoo/PyIOCe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ioc-fang/ioc_fanger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Netflix/Scumblr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johestephan/ibmxforceex.checker.py` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ocmdev/rita` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kx499/ostip` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `facebook/ThreatExchange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tripwire/tardis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SupportIntelligence/Icewater` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/Forager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `QTek/QRadio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jheise/threatcrowd_api` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4d31/sqhunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stratosphereips/Manati` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kbandla/APTnotes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InQuest/omnibus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PaloAltoNetworks/minemeld` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mandiant/ioc_writer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheHive-Project/Hippocampe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yelp/threat_intel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spacepatcher/FireHOL-IP-Aggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fhightower/onemillion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `exp0se/harbinger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TAXIIProject/yeti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mlsecproject/combine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yara-Rules/rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `armbues/ioc_parser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `silascutler/MalPipe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `foospidy/HoneyPy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HurricaneLabs/machinae` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BinaryDefense/goatrider` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ciscocsirt/gosint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abusesa/abusehelper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aboutsecurity/rastrea2r` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `michael-yip/ThreatTracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stephenbrannon/IOCextractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spacepatcher/softrace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jheise/threatcmd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/malstrom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brianwarehime/threatnote` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lookingglass/opentpx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CylanceSPEAR/CyBot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpsenior/threataggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EclecticIQ/OpenTAXII` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `STIXProject/stix-viz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityRiskAdvisors/sra-taxii2-server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheHive-Project/Cortex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/cacador` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TAXIIProject/libtaxii` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mgeide/poortego` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InQuest/python-iocextract` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `buffer/pylibemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/honeycomb_plugins` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qeeqbox/honeypots` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MattCarothers/mhn-core-docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `graneed/bwpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERT-Polska/HSN-Capture-HPC-NG` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mfontani/kippo-stats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aelth/ddospot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jadb/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zeerg/helix-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `desaster/kippo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sreinhardt/Docker-Honeynet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CHH/stack-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jedie/django-kippo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrheinen/lophiid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Novetta/delilah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dmpayton/django-admin-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/flux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OWASP/Python-Honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UHH-ISS/honeygrove` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lcashdol/WAPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `antonsatt/ssh-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shbhmsingh72/Honeypot-Research-Papers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/manuka` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ajackal/arctic-swallow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/StrutsHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eymengunay/EoHoneypotBundle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magisterquis/vnclowpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `freak3dot/wp-smart-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/weblogic_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/snare` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hexgolems/pint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `batchmcnulty/Malbait` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christophe77/node-ftp-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERT-Polska/hsn2-bundle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SentryPeer/SentryPeer` | GITHUB | Größe: 0 IPs |
| `hbhzwj/imalse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fw42/honeymap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/glutton` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rubenespadas/DionaeaFR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/phoneyc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `madirish/kojoney2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aplura/Tango` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `katkad/Glastopf-Analytics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/honeyku` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/ghost-usb-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mycert/ESPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cypwnpwnsocute/RedisHoneyPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `buffer/libemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oguzy/ovizart` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dutchcoders/troje` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sec51/honeymail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bjeborn/basic-auth-pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shiva-spampot/shiva` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f0rw4rd/potsnitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thinkst/opencanary` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/micros_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:ajabep/gophish-phishing-dynamic-page-generator` | GITLAB | Zu alt: 1319d |
| `gitlab:oceaniagov-minitrue/minitrue-unpersons` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:Maingron/fascist-blocklist` | GITLAB | Zu alt: 36d |
| `gitlab:WorkofAditya/PhisherMan` | GITLAB | Zu alt: 298d |
| `gitlab:PeterDaveHello/threat-hostlist` | GITLAB | Zu alt: 1316d |
| `gitlab:aurelian.cireasa/omarchy-linux-vps` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:verdettoqr/link-safety-list` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:pro-gineous-group/vps-bootstrap` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:toxy4ny/BL00DYM4RY` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:DanDawson/probeguard-404-firewall-cloudflare` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:ochita/arcferrix-app-releases` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:oceaniagov-minitrue/minitrue-extension` | GITLAB | Zu alt: 36d |
| `gitlab:kikinovak/rh_setup_fail2ban` | GITLAB | Zu alt: 38d |
| `gitlab:andersonmavi30/docker_firewall_automation` | GITLAB | Zu alt: 52d |
| `gitlab:ayinedjimi-consultants/PhishingDetector-AI` | GITLAB | Zu alt: 156d |
| `gitlab:HackingLZ/push_matrix_tool` | GITLAB | Zu alt: 205d |
| `gitlab:HackingLZ/ip-obfuscation` | GITLAB | Zu alt: 205d |
| `gitlab:cossas/bigphish` | GITLAB | Zu alt: 298d |
| `gitlab:arpitxd/phishark` | GITLAB | Zu alt: 546d |
| `gitlab:red-team-labs/evilginx3` | GITLAB | Zu alt: 889d |
| `gitlab:ajabep/poc-google-go-phish-phishing-dynamic-page-generator` | GITLAB | Zu alt: 1319d |
| `gitlab:twinwave-public/commonly-abused-web-services` | GITLAB | Zu alt: 1545d |
| `gitlab:mrTownsend/BeeHive-AntiPhishing` | GITLAB | Zu alt: 1724d |
| `gitlab:franckess/AzureML_WebsiteClassifier` | GITLAB | Zu alt: 1843d |
| `gitlab:curben/phishing-filter-mirror` | GITLAB | Zu alt: 2137d |
| `gitlab:gloomytrousers/spam-reporter` | GITLAB | Zu alt: 2492d |
| `gitlab:aalhour/MailPhishing` | GITLAB | Zu alt: 2532d |
| `Interested-Deving-1896/netclaw` | GITHUB | Größe: 0 IPs |
| `tilas01/veilvoice` | GITHUB | IP-Datei 41d alt |
| `eyalgolan/statecraft-israel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sathi2305/Omnipilot-Ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Imhaohao/calhacks` | GITHUB | Größe: 0 IPs |
| `mazensabry2712/bahnes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yz4git/newgame3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kerio-byte/uchisambot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PulseTV-llc/nationdivided` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `YuriSekaii/CyberHorde-FPS-Roguelike` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3clo1979/camyta-solutions-consulting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mathewstars/Gridzilla` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AslamNazeerShaikh/PythonWebScraping` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shameerariff/open-exploit-research` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Salim-Grav/SR-CoreSync---For-Intelgent-Solutions` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `g-c-3/nightwing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shru14/ai-pulse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `casareanderson/ephor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HALCONDEORO/tesco-ie-grocery-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `napfkuchen1/mtmon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Komaster12454/sdg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Joakimpalm-Zen/xyntetik-runner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `metafrogmeme-droid/001` | GITHUB | Größe: 0 IPs |
| `Cyrax321/CONTINUUM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `richkid2xi/LeakLense` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drsumaiya/drsumaiya.com-upptime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rajath-nayakk/nova-browser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kanishka-namdeo/Unown` | GITHUB | Größe: 0 IPs |
| `yousefjan2007-crypto/robinhood-screener` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `werriesjacob1-cmyk/Full-Count` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thomasnormal/lean-surfaces` | GITHUB | IP-Datei 92d alt |
| `rblmarrero-sketch/Condition-Monitoring` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `naamfung/dsc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nmquan2504/cc-mod-statusbar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amfire-tech/amfire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Musakhan678/Ai-phishing-detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Chenophobia/learn-japanese-anki` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DarylHS/crawl-live` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `malekahmed14112009-cloud/sciencefit-athlete-coach-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abdurrehmansajidhafiz1-cell/trading-scanner-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NavisWORLD/The-beast-box-` | GITHUB | IP-Datei 36d alt |
| `thepigdestroyer/drouter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ahmed-Hammoda/cross-network-intrusion-analysis` | GITHUB | Größe: 0 IPs |
| `syedarifulislamemon2010/Late-Sitting-Holiday-Night-Duty` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `start-again-06/XAI---Explainable-AI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iliangithub/Project_Dirtylands` | GITHUB | Größe: 0 IPs |
| `staude/amiscara-agents` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UmidYul/menu` | GITHUB | IP-Datei 47d alt |
| `Wanfeng1028/muse` | GITHUB | Größe: 0 IPs |
| `drkostas/claude-ops` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AnasMujeeb/meat-corner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aiori-hackathon/A3-PS007-TC042` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gwoot43/detections` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MDJTalha/CountAI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jonamarti/dynasty_game` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gregoryyy/kibitz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CJ-Uy/YAT.lifestyle` | GITHUB | Größe: 0 IPs |
| `kittykatchunks/asterisk_newUI_MCP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abijit2626/Ambit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `holeenlu/sub2api` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrgoonie/zuey-me` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `janpuc/polished` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `unDead41/slay-the-math-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CaptainDarkHeart/eventmap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xaviercallens/HiveMind` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rahul-pamula/Open_Source_Scout` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sadatnitex/visastack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iainchesworthlabs/wordjewelssolver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `YaBoiSean319/nvr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `THEpranavsomalraju/internship-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `01shane89-jpg/AXIOM-APSAP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wmaready/parcel-pigeon` | GITHUB | Größe: 0 IPs |
| `mihailinl/astra-registry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alexeiguch/whybot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `karbburn/MarketLab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lbsa71/fender_offenders` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UnknownDev2018/Kov-Sec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ClearJan/Deskvanic` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `grubstagram/Grubstagram` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omm-hippo/omm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shefar77/Chokepoint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hexide-io/HexIDE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Remus3/Amberstone` | GITHUB | IP-Datei 130d alt |
| `SnatchPlay/therapy-scheduling` | GITHUB | Größe: 0 IPs |
| `casareanderson/farrier` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aleena-Roby/Portide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yorcela/thejobfather` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `primerogueinc/roger-wilco-imaging-pre-alpha` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mycaravam-crypto/logwizz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `taharukaiya/Resume-Maker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vger70/MedReminder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AxAbhishek0309/SentinelAI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arcymonek/seisa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aitherium/awmine` | GITHUB | Größe: 0 IPs |
| `mwangirogers04-cloud/NETOPS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AryanSarang/Insta-auto` | GITHUB | Größe: 0 IPs |
| `jokubasqxw/Aether-OS-beta-testing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hbaslimane/devops-project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 25,099 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 19,796 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 8,580 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,634 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,834 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,738 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,775 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,951 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,951 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,209 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,590 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 1,767 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 557 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 425 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 442 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 396 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 226 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,484 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,663 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 19,917 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 12,553 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 7,049 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,739 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 6,161 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 215,627 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,328 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 6,090 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,644 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 4,077 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 32,717 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 4,617 | 64.3% | 938 | 2026-09-04 |
| `cbuijs_hagezi` | GITHUB | 30,620 | 40.7% | 128 | 2026-10-25 |
| `mohammedcha_proxripper` | GITHUB | 55,551 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,150 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 119,053 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 118,194 | 0.2% | 36 | 2026-07-05 |
| `telekom_security_listbot` | GITHUB | 501 | 10.4% | 22 | 2026-10-18 |
| `dinoz0rg_proxy_list` | GITHUB | 91,756 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,573 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 94,139 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 108,617 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,628 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 105,285 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,820 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 103,728 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 482 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 502,036 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,770 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 173,832 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 82,811 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 172,212 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 175,339 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 104,988 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 85,447 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 258,104 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 50,828 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 204,294 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,572 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 15,724 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 14,173 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 180,089 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 26,249 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 9,895 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,957 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 24,771 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 15,207 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 12,671 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 8,164 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,406 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 3,930 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,360 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,338 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 999 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,490 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,346 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,730 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 3,302 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 123,639 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,226 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 29,753 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 2,778 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 4,354 | 79.4% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,727 | 64.3% | 10 | 2026-10-11 |
| `ian_lusule_proxies` | GITHUB | 3,215 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,396 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,275 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 361,233 | 22.0% | 6 | 2026-07-08 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,323 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 55 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 106,397 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 108,235 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 23,250 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 93 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 106,816 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,246 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,683 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 262 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 19,367 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 18,096 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 26,643 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,388 | 31.1% | 1 | 2026-07-14 |
| `klonet_it_ip_threat_lists` | GITHUB | 130,803 | 51.5% | 1 | 2026-10-11 |
| `klonet_it_ip_threat_lists_blocklist_apache` | GITHUB | 9,576 | 9.7% | 1 | 2026-10-11 |
| `idleadmin_threatfeed` | GITHUB | 55,038 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 69,367 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,734 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 130,480 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 388 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 197,369 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,537 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 130,472 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 223,905 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 36,598 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 19,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 19,922 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,715 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 11,681 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,055 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,625 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 6,559 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,423 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,115 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 5,986 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,858 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 501 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 5,374 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,025 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,214 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,339 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,235 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,310 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,084 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,085 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,661 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,199 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,280 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 537 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,423 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,734 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,194 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 11,301 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,735 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 91,207 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 93,179 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 91,275 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 93,391 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 93,750 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 95,660 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 22,648 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 41,298 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 4,174 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,572 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,060 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 51,944 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 29,411 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 10,588 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 17,037 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 23 | 63.9% | 0 | 2026-08-12 |
| `zgzyh_malicious_website_detection` | GITHUB | 33,747 | 3.1% | 0 | 2026-08-15 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,382 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 17,478 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 6,365 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,579 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 1,318 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 489 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 227 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 8,152 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 90,945 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 94,243 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 92,348 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 85,947 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 89,059 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 29,674 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 3,315 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 3,271 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_20` | GITHUB | 184 | 92.3% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 984 | 76.9% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_24` | GITHUB | 157 | 90.4% | 0 | 2026-09-25 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,278 | 6.8% | 0 | 2026-10-04 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 2,387 | 5.4% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_all_90d` | GITHUB | 6,583 | 61.9% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_aggressive` | GITHUB | 68 | 80.9% | 0 | 2026-10-11 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 177,737 | 17.9% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 20,346 | 59.1% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 9,119 | 80.7% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_tor_exits` | GITHUB | 1,218 | 69.1% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_sblam` | GITHUB | 1,091 | 30.3% | 0 | 2026-10-18 |
| `helio4k_bad_ip` | GITHUB | 2,019 | 43.3% | 0 | 2026-10-25 |
| `verkombr_block_list_firewalls` | GITHUB | 32 | 46.9% | 0 | 2026-10-25 |

---
*Generiert: 2026-10-25 10:22 CET (Europe/Berlin)*