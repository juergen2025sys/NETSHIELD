# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-20 11:26 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **11372** |
| davon GitHub (Topics+Code) | **11282** |
| davon GitLab | **90** |
| davon Awesome-Lists | **2399** |
| Tools/Libraries vor Eval gefiltert | **1563** |
| davon Hard-Reject (awesome-Liste etc.) | **177** |
| EVAL-Kandidaten (nach Stratifizierung) | **460** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **460** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **458** |
| Neu angenommene Feed-Dateien | **4** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **182** |
| Abgelehnte Repositories (dieser Run) | **458** |
| davon GitLab abgelehnt | **4** |
| Feeds gesamt (aktiv) | **186** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **163202** |
| SQLite-Refresh-Cache-Hits | **9/186** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **372** |
| Repo zu alt (>30d) | **50** |
| IP-Datei veraltet (>30d) | **22** |
| Falsche Größe (<30 / >2,000,000 IPs) | **12** |
| Sonstige | **2** |
| Overlap mit HQ-Feeds zu gering (<20%) | **2** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,374 | 66.1% | 0.0% | 0 | 🆕 NEU |
| `gazpitchy92_ip_blocklist_blacklist` | [gazpitchy92/ip-blocklist](https://github.com/gazpitchy92/ip-blocklist) | GITHUB | 359,738 | 19.5% | 0.0% | 6 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_tor_exits` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 1,364 | 66.5% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_sblam` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 1,066 | 25.9% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `Leon406/SubCrawler` | GITHUB | Größe: 0 IPs |
| `CriticalPathSecurity/Zeek-Intelligence-Feeds` | GITHUB | Identischer Inhalt wie kraloveckey_ipsets_blocklist_bds_atif |
| `mrwadams/attackgen` | GITHUB | IP-Datei 68d alt |
| `VoidSecSoftwares/voidsyscall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rubby2001/Rshell-client` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kxiandaoyan/github-C2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `b23r0/Heroinn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nickvourd/SkyFall-Pack` | GITHUB | Zu alt: 50d |
| `nickvourd/CS-Aggressor-Kit` | GITHUB | Zu alt: 62d |
| `CyberCoreAccess/BMHacker-Botnet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khoren93/flutter_zxing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `awslabs/automated-security-helper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frontendnetwork/veganify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RetireJS/retire.js` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bitscoper/bitscoper_cyberkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Atomburstofficial/geiger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wpscanteam/wpscan` | GITHUB | IP-Datei 2916d alt |
| `mondoohq/installer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `greenbone/openvas-scanner` | GITHUB | IP-Datei 52d alt |
| `ossappscollective/OSS-DocumentScanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `navchandar/look-like-scanned` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shadow1ng/fscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CodeDead/Advanced-PortChecker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sefinek/Cloudflare-WAF-To-AbuseIPDB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sefinek/UFW-AbuseIPDB-Reporter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mishakorzik/AllHackingTools` | GITHUB | IP-Datei 1552d alt |
| `sensepost/hash-cracker` | GITHUB | IP-Datei 31d alt |
| `d4t4s3c/RSAcrack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blackorbird/APT_REPORT` | GITHUB | IP-Datei 1730d alt |
| `ahmedkhlief/APT-Hunter` | GITHUB | IP-Datei 1232d alt |
| `utmstack/UTMStack` | GITHUB | IP-Datei 375d alt |
| `osintbrazuca/osint-brazuca` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benscha/KQLAdvancedHunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ethan-Andrews/Exploitarium-Detections` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NotYuSheng/TracePcap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sous-chefs/apt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cybozu-go/aptutil` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nickvourd/COM-Hunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nettitude/CLR-Stomp` | GITHUB | Zu alt: 123d |
| `lintstar/SharpHunter` | GITHUB | Zu alt: 523d |
| `yqcs/ZheTian` | GITHUB | Zu alt: 590d |
| `fortra/No-Consolation` | GITHUB | Zu alt: 697d |
| `fortra/nanodump` | GITHUB | Zu alt: 733d |
| `001SPARTaN/aggressor_scripts` | GITHUB | Zu alt: 766d |
| `b1tg/cobaltstrike-beacon-rust` | GITHUB | Zu alt: 771d |
| `starnightcyber/Miscellaneous` | GITHUB | Zu alt: 793d |
| `naksyn/DojoLoader` | GITHUB | Zu alt: 810d |
| `Adminisme/ServerScan` | GITHUB | Zu alt: 826d |
| `wangfly-me/LoaderFly` | GITHUB | Zu alt: 886d |
| `m3rcer/Chisel-Strike` | GITHUB | Zu alt: 909d |
| `yutianqaq/CSx3Ldr` | GITHUB | Zu alt: 981d |
| `gloxec/CrossC2` | GITHUB | Zu alt: 1035d |
| `hlldz/Phant0m` | GITHUB | Zu alt: 1095d |
| `intbjw/bimg-shellcode-loader` | GITHUB | Zu alt: 1096d |
| `harleyQu1nn/AggressorScripts` | GITHUB | Zu alt: 1178d |
| `baiyies/ScreenshotBOFPlus` | GITHUB | Zu alt: 1201d |
| `lintstar/CS-PushPlus` | GITHUB | Zu alt: 1294d |
| `QAX-A-Team/CobaltStrike-Toolset` | GITHUB | Zu alt: 1398d |
| `xx0hcd/Malleable-C2-Profiles` | GITHUB | Zu alt: 1423d |
| `ScriptIdiot/BOF-patchit` | GITHUB | Zu alt: 1450d |
| `akkuman/EvilEye` | GITHUB | Zu alt: 1475d |
| `hrtywhy/BOF-CobaltStrike` | GITHUB | Zu alt: 1574d |
| `S4ntiagoP/freeBokuLoader` | GITHUB | Zu alt: 1575d |
| `guervild/BOFs` | GITHUB | Zu alt: 1602d |
| `mez-0/InMemoryNET` | GITHUB | Zu alt: 1614d |
| `lintstar/LSTAR` | GITHUB | Zu alt: 1694d |
| `Peco602/cobaltstrike-aggressor-scripts` | GITHUB | Zu alt: 1721d |
| `airbus-cert/Invoke-Bof` | GITHUB | Zu alt: 1746d |
| `HKirito/GoogleAuth` | GITHUB | Zu alt: 1805d |
| `mez-0/winrmdll` | GITHUB | Zu alt: 1835d |
| `z1un/Z1-AggressorScripts` | GITHUB | Zu alt: 1939d |
| `Coalfire-Research/Vampire` | GITHUB | Zu alt: 1993d |
| `EncodeGroup/BOF-RegSave` | GITHUB | Zu alt: 2173d |
| `tomcarver16/BOF-DLL-Inject` | GITHUB | Zu alt: 2208d |
| `alphaSeclab/cobalt-strike` | GITHUB | Zu alt: 2303d |
| `loecho-sec/CobaltStrike_Script_Wechat_Push` | GITHUB | Zu alt: 2343d |
| `Laiteux/Milky` | GITHUB | Zu alt: 1734d |
| `trsi-me/TS-OSINT` | GITHUB | Zu alt: 816d |
| `whoahaow/rjsxrd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Pawdroid/Free-servers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Barabama/FreeNodes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `v2rayA/v2rayA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zhuhaiuk/free-nodes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `free-nodes/fanqiang` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mheidari98/.proxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `huijingfei/Shadowrocket-Rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NiREvil/vless` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blatteprince2/Void-Engine-GD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mahdibland/V2RayAggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xyfqzy/free-nodes` | GITHUB | IP-Datei 260d alt |
| `MahanKenway/Freedom-V2Ray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `peasoft/NoMoreWalls` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2dust/v2rayN` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sub-store-org/Sub-Store` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mhyrzt/xrat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddify/Hiddify-Manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mahdi0024/ProxyCollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amclubs/am-cf-tunnel-sub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amclubs/am-cf-tunnel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jichangtuijian-cheap/cheap-airports` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kwisma/Sub-Store-node` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `seramo/v2ray-config-modifier` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sower-proxy/sower` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qr243vbi/nekobox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shenaba/2s-ui` | GITHUB | Größe: 1 IPs |
| `MHSanaei/3x-ui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sstklen/trump-code` | GITHUB | IP-Datei 189d alt |
| `agourlay/zip-password-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `praetorian-inc/brutus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skjolber/3d-bin-container-packing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `daturadev/snapcrack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s-kachroo/SamsungPractice` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RozhakDev/Facemash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tp7309/TTPassGen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Coding-Enthusiast/FinderOuter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `msrofficial/WiFuX` | GITHUB | Zu alt: 44d |
| `0xdea/tactical-exploitation` | GITHUB | Zu alt: 49d |
| `vscodev/XArchiver` | GITHUB | Zu alt: 50d |
| `HomelessPhD/BTC32` | GITHUB | Zu alt: 51d |
| `joshspeagle/brutus` | GITHUB | Zu alt: 55d |
| `anvaka/isect` | GITHUB | Zu alt: 31d |
| `acepanel/panel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomMoulard/fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sous-chefs/fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yahuisme/vps-setup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `docker-mailserver/docker-mailserver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mariusdjen/vpskit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `defense-cr/defense` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crazy-max/docker-fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `devnulli/EvlWatcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `itiligent/Easy-Guacamole-Installer` | GITHUB | IP-Datei 875d alt |
| `robertdebock/ansible-role-fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DigitalRuby/IPBan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aldaviva/Fail2Ban4Win` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jasonish/evebox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DCSO/balboa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DCSO/fever` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `daffainfo/suricata-rules` | GITHUB | Zu alt: 49d |
| `2GT-Media-Group-LLC/mikrotik-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MrAriaNet/Get-IP-Iran` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mirceanton/external-dns-provider-mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sakib-m/IP-Prefix-List` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeff-nasseri/mikrotik-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Davie3/mikrotik-cloudflare-iplist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eworm-de/routeros-scripts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cacti/plugin_mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `napalm-automation-community/napalm-ros` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `danikf/tik4net` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rekryt/iplist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CA17/TeamsACS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `luqasz/librouteros` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vadims06/topolograph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomaae/homeassistant-mikrotik_router` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CodePagol/ISP-Mikrotik-Billing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mirceanton/mikrotik-terraform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AliKarami/MikroMCP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pavel-odintsov/fastnetmon` | GITHUB | IP-Datei 1059d alt |
| `pfrest/pfSense-pkg-saml2-auth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pfrest/pfSense-pkg-RESTAPI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rbicelli/pfsense-zabbix-template` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ivre/ivre` | GITHUB | IP-Datei 375d alt |
| `frangelbarrera/OSINT-BIBLE` | GITHUB | Identischer Inhalt wie kraloveckey_ipsets_blocklist_bds_atif |
| `mxrch/GHunt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Moresyl/metaclean` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `obitouka/InstagramPrivSniffer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qeeqbox/social-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s0md3v/Photon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thewhiteh4t/nexfil` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `seekr-osint/seekr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `megadose/holehe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/instagram_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kpcyrd/sn0int` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khast3x/h8mail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `snooppr/snoop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `megadose/toutatis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DFIRKuiper/Kuiper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `guardsight/gsvsoc_cirt-playbook-battle-cards` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dfirtrack/dfirtrack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cyb3rfox/Aurora-Incident-Response` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mozilla/MozDef` | GITHUB | IP-Datei 1987d alt |
| `SecurityBrewery/catalyst` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sandialabs/scot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alphasoc/flightsim` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mgreen27/Invoke-LiveResponse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diogo-fernan/ir-rescue` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DFIR-ORC/dfir-orc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `volatilityfoundation/volatility3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Security-Onion-Solutions/security-onion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PagerDuty/incident-response-docs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tclahr/uac` | GITHUB | Größe: 0 IPs |
| `JPCERTCC/MalConfScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TonyPhipps/Meerkat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `counteractive/incident-response-plan-template` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zentralopensource/zentral` | GITHUB | IP-Datei 2023d alt |
| `dfir-iris/iris-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ossec/ossec-hids` | GITHUB | IP-Datei 47d alt |
| `0x4D31/fatt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/deception-as-detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `center-for-threat-informed-defense/adversary_emulation_library` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `clong/DetectionLab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kolide/fleet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `palantir/osquery-configuration` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `osquery/osquery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mvelazc0/Oriana` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `A3sal0n/CyberThreatHunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `docbleach/DocBleach` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marcwebbie/passpie` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fingerprintjs/fingerprint-android` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `insidersec/insider` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `k4m4/movies-for-hackers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zeroq/amun` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bountyyfi/lonkero` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mozilla/sops` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spectralops/netz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uptimejp/sql_firewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nil0x42/phpsploit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aquasecurity/trivy` | GITHUB | IP-Datei 342d alt |
| `nxgn-kd01/react2shell-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sergiomarotco/Network-segmentation-cheat-sheet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ir193/AMExtractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `karimhabush/cyberowl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Khadinxc/Sigma2KQL` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rozgo/anevicon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deepfence/PacketStreamer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pfq/PFQ` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fingerprintjs/fingerprintjs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lanmaster53/recon-ng` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/binarypig` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codeyourweb/fastfinder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marcinguy/scanmycode-ce` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ConradIrwin/dotgpg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kai5263499/container-security-awesome` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `undeadlist/trust-scan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `owasp/nodegoat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `v8blink/Chromium-based-XSS-Taint-Tracking` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dogoncouch/LogESP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pompelmi/pompelmi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fugue/credstash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lyft/confidant` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microsoft/onefuzz` | GITHUB | IP-Datei 1256d alt |
| `certsocietegenerale/swordphish-awareness` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/sunburst_countermeasures` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codeexpress/respounder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ossf/allstar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `snyk-labs/snync` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AltraMayor/gatekeeper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `apiiro/combobulator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `facebook/osquery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/santa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PlumHound/PlumHound` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rams3sh/Aaia` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JupiterOne/starbase` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `linuz/Sticky-Keys-Slayer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oasis-open/cti-python-stix2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `latchset/clevis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/ukip` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nccgroup/PMapper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `opensourcesec/CIRTKit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `essandess/macOS-Fortress` | GITHUB | IP-Datei 2785d alt |
| `genuinetools/bane` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ANSSI-FR/AD-control-paths` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `slackhq/nebula` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `securestate/king-phisher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `technosophos/helm-gpg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `censys/censys-python` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sensepost/ruler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `theupdateframework/notary` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `opensourcesec/Forager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `darkoperator/Posh-VirusTotal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sonatype-nexus-community/repo-diff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `awslabs/git-secrets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nsacyber/Windows-Secure-Host-Baseline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coreos/clair` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VirusTotal/yara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sensepost/notruler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keikoproj/kube-forensics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mikeperry-tor/vanguards` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tonarino/innernet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bunkerity/bunkerized-nginx` | GITHUB | IP-Datei 33d alt |
| `Yelp/osxcollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:Maingron/fascist-blocklist` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:oceaniagov-minitrue/minitrue-extension` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:verdettoqr/link-safety-list` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:niclas-zone/ctr/wazuh` | GITLAB | Zu alt: 55d |
| `pkarki05/windows-bruteforce-incident-response` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `irawany304-gif/ASNforge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Correia-jpv/fucking-about-SwiftUI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manishpandit1406/qwik-mailer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `appleweiping/FacetRoute` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `binoremohapatra/PhaseGuard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tejaskh3/aether` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kornet-protocol/NEXUS-CORE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AbhayTiwari111/SecureQ-Cloud` | GITHUB | Größe: 0 IPs |
| `siddhipatil885/SecurePulse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arsam4waffels/phantom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `varunxcode/ctf-task` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ManagementMO/shift` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-k8s-security` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ikunalkumararya/IncidentOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BlockChain-BailBonds/archon-sigilagi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jackie-SDX/Nayla-SD-JACKIE-Fun-WhatsApp-Bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tousle-8-sunlamp/Online-404-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hushchats1/official` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gunners-sticks-8/AIM-War-Protocol-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shreyashub01/android-frontend-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `huddle173654pizzazz/DungeonBox-Leaked-Win64-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trilokesh-sarkar/Report_Transactions` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GnomeMan4201/r4b1t-h0le` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IKAC-FIDS/content-intelligence-backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lubothebook/lumen-gate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ornament9edamame/Stage-Tour-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hashaam105/learnforge-support-assistant` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rudi-bruchez/sql-auditor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `onesyue/yuelink-ci` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `notices-barren495/The-Streamers-Alt-Account-Labyrinth-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `notices-barren495/Living-Hell-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `saurabh-bits-pilani/atlas-risk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `leolouis/Nineteen99` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tero-k/verkkokyyla` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Deagletworks/Crystal-Ark-White-Material` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `berkayturanci/ai-jury` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kenja1970/Techniek-OpsBoard-Pro-V2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ezpickle2026/ezpickle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zarvistechnologies-design/AI-Voice-platform-backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joeskolengaden/pixelselect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carnage-sunned523436/Rain98-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `castlemilk/token-horizon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fanxuankai/Kiro-account-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AronAlander/footytest` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `josehelioaraujo/comprai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rahanahu/wgft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `harishma2007/netwatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MarcoColomb0/twenty` | GITHUB | Größe: 0 IPs |
| `Cyb3Raya/osint-watchfloor` | GITHUB | IP-Datei 41d alt |
| `dommango/agentmats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `embolden-stricter-1/Debauchery-Magic-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `canopies-jiggered-29/Lilys-World-XD-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2h2d-co/pi-openai-codex-compat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pendulumgames/ValheimSagas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yookiop/SteamDataOfficial` | GITHUB | Größe: 0 IPs |
| `jersputra4/SocialReports` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `notices171917-military/Price-for-Freedom-Gold-and-Sand-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `phantasm-elated8/Lost-in-the-Roots-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SHWE1530/KAAMSETU` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `garyanewsome/CodebaseSearcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `markec12345678/griblje-museum` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shareefdoha/qima` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zzgpy1/ITV` | GITHUB | IP-Datei 51d alt |
| `Royshacked/botmarket-backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rustleprithee323/Skyclimbers-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Saitanveesh/1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LloydCoder/fas-bench` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qwyoo11/ATM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `costingrube-65/Haunted-By-Femboy-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betwixthawked99459/Cozy-Game-Restoration-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gunners-sticks-8/Epic-Seven-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hoanguyen6611/map-food-byhoane` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rustleprithee323/Laceys-Flash-Games-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `habachcp6/RAG2ATTCK` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `primmest663-jell/After-Inc-Revival-Community-Edition` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BloodCorrupt/throttwin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gamey685674thumb/CrocApoca-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tanishpiro/Payshield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zombiegirlcz/kali_core_emulator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Pheonix-Studio-cat/cut-video-connector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sifatbro786/skynest` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aceknight4/honeypot-siem-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anzai3/ChromeTabX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `reprise-7136parching/Wandering-Wolf-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `smolders-outdoor-4/The-Dead-We-Knew-Open-World-Survival-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `goan92/immoApp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sagivo/llmempire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `armaanmeer10/receipts-of-a-life` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xxxvmidst71/Invokyr-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Latand/live-log-viewer-next` | GITHUB | Größe: 0 IPs |
| `soroshimukherjee/soil-sidekick-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `asagberman/base-preflight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `senti67/KisanSetu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lidebao513/testHub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `saboaua/scam-checker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `awdawmip/enterprise-math` | GITHUB | Größe: 0 IPs |
| `canyuda/agent-guard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kschnieders/server2pick` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diffused-gamey-7753/Final-Fantasy-Resonance-Beta-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `notices-barren495/Mars-Tactics-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AS24xADITYA/VoiceGuard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `epnasis/aish` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `costingrube-65/ANOMALITH-Early-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EddieOfAlhana/hubaajto` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betwixthawked99459/Rivage-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `helioskozak-cloud/news-desk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pranavk-7117/SecAgentHub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Syed-Bipul-Rahman/Security-Guard` | GITHUB | Overlap zu gering: 0.0% |
| `dshyleshkarthik7-hue/linuxlab-hybrid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `embolden-stricter-1/Halloween-The-Game-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Correia-jpv/fucking-beautiful-docs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mihailinl/astra-registry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ZulkaifAhmad/GenAi-MERN-ResumeBuilder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sonti22/jobhunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ChristineTham/ipnx-v12` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `7inaydas-cmyk/flash-computer-use` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ArpanMaheshwari144/Prep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `prashanta-dev7/blog-agent-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lucky007696/FLOWSTATE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jd0e1337/cs2-serverbrowser-ip-blocklist` | GITHUB | Overlap zu gering: 0.0% |
| `toma86hawk/technocore-flop-japan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drsumaiya/drsumaiya.com-upptime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `farukatasoy/Tracon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gunners-sticks-8/Kitsune-Adashino-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ossykora17-rgb/Vent-AI-Therapist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nickdotname/ugc-factory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zerobudian/gfw-x` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kaushik2210/gitVisualise` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x812033727/travel_scanner` | GITHUB | Größe: 0 IPs |
| `GEEKProtocol0110/geek-protocol-hq` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xsynaptic/resonance` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shabir-ahmad-sabe/SABE-Statistical-AI-Battle-Engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wy32428011/babylon-3d-plus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OppaAI/Aiko-Onmyoji` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arifahmeddana-lab/Test` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inipew/goultroid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AbhinavKumar36/Orion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rustleprithee323/Five-Laps-at-Freddys-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `flops-464-cutlet/Arcane-Eats-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `euphony-lorn-6141/PHASE-ZERO-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shizukutanaka/Kaname` | GITHUB | Größe: 0 IPs |
| `reprise-7136parching/MEAT-GRINDER-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betwixthawked99459/Minecraft-Dungeons-II-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pratham-1002-adg/fmhy-blocklists` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dhruv-79/cloudguard-soc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yogesh2jadhav/codexray_v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `john-walks-slow/token-speed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `myselfpankajk4/strota-x` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `obligate-8-deader/Honeycomb-Community-Edition` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `monkeyAtheist/VScode-EXT---QPM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `leitwacht/malicious-packages` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gunners-sticks-8/Northgard-Battlegrounds-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `notices-barren495/Slutopia-PreRelease-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JadeSure/bargain-hunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bruno2000p/Phishing-detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nodes-467105-dawdles/CONTROL-Resonant-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Soumit-das-oss/Error_404` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aicologne/aic-hardware-deals` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vincamok/goproxify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IHUI-INF-AI/IHUI-AI` | GITHUB | Größe: 0 IPs |
| `scarlettzhangxh/exitliq` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `geoffry1210/synapse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lantisprime/pi-extensions` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Afro-Digital/Pharmacy-Managemnt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ihsanmp/Crypto-Analis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DNSBunker/CTI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KerberoSec/Growww` | GITHUB | Größe: 0 IPs |
| `BsTdjab2/MoreAboutS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ornament9edamame/Ved-Recure-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anthnel/devdesk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ahs786-web/trading-events-calendar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `praneeth132006/RedBlueSkills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bs9zw69ff9-source/dhxguhjjjhh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carnage-sunned523436/Well-Dweller-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `reprise-7136parching/Stronghold-4-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 33,185 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 21,023 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 8,854 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 12,096 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,845 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,764 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,774 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 3,125 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,952 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,069 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,762 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,528 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 761 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 547 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 599 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 493 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 321 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,182 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,620 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 17,820 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,556 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,353 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,252 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,439 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 214,991 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,470 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,474 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,648 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 1,720 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,698 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 12,141 | 64.3% | 938 | 2026-09-04 |
| `cbuijs_hagezi` | GITHUB | 52,987 | 40.7% | 123 | 2026-09-17 |
| `mohammedcha_proxripper` | GITHUB | 53,956 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,159 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,913 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,913 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 93,863 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,266 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 93,089 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 105,800 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,717 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 120,459 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,552 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 125,908 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 675 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 478,308 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,397 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 172,308 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 168,585 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 138,124 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 155,121 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 98,559 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 115,876 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 97,492 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 230,634 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 57,808 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 171,973 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 34,637 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 28,793 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 26,264 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 23,974 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 21,725 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 177,194 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,627 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 11,283 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 6,992 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 20,552 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 13,452 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,285 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 10,919 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 7,054 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 3,233 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 11,802 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,236 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,201 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 4,040 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,143 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 4,365 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,834 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,894 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 98,562 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,395 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,050 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 58,588 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 4,236 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,385 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,448 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,258 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 372,100 | 22.0% | 6 | 2026-07-08 |
| `gazpitchy92_ip_blocklist_blacklist` | GITHUB | 359,738 | 19.5% | 6 | 2026-09-20 |
| `officialputuid_proxyforeveryone` | GITHUB | 7,396 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 6,232 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 7,690 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,459 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 51 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 93,166 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 97,734 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,531 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 67 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 227,746 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,549 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,708 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 377 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 16,956 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 16,881 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 20,026 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,348 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 61,373 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 61,603 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,721 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 130,971 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 349 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 194,829 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,535 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 130,964 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 203,086 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,103 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 36,328 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 494 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 24,599 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 21,127 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,728 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 12,013 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,696 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,638 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,692 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 5,000 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,783 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,112 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,532 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 6,191 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,823 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 5,004 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 3,358 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,230 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,363 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,397 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,334 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,316 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,084 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,186 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,220 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,171 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,411 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 687 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,446 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,811 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,224 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 10,837 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 93,049 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 93,484 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 92,553 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 91,054 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 92,278 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 95,600 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 89,421 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 22,532 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 52,631 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 11,388 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,760 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,210 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,040 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 42,346 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 20,444 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 12,333 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 6,130 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 39 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 27,626 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 152,154 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 18,686 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,253 | 5.1% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,114 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,220 | 9.3% | 0 | 2026-09-13 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,374 | 66.1% | 0 | 2026-09-20 |
| `claudiusdecimius_ioc_ipsets_tor_exits` | GITHUB | 1,364 | 66.5% | 0 | 2026-09-20 |
| `claudiusdecimius_ioc_ipsets_sblam` | GITHUB | 1,066 | 25.9% | 0 | 2026-09-20 |

---
*Generiert: 2026-09-20 11:26 CEST (Europe/Berlin)*