# Auto Feed Discovery – Report
**Aktualisiert:** 2026-11-08 12:29 CET (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 3 |
| Kandidaten gesamt | **11638** |
| davon GitHub (Topics+Code) | **11557** |
| davon GitLab | **81** |
| davon Awesome-Lists | **2410** |
| Tools/Libraries vor Eval gefiltert | **1646** |
| davon Hard-Reject (awesome-Liste etc.) | **190** |
| EVAL-Kandidaten (nach Stratifizierung) | **456** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **456** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **454** |
| Neu angenommene Feed-Dateien | **4** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **187** |
| Abgelehnte Repositories (dieser Run) | **454** |
| davon GitLab abgelehnt | **2** |
| Feeds gesamt (aktiv) | **191** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **142921** |
| SQLite-Refresh-Cache-Hits | **13/194** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **369** |
| Repo zu alt (>30d) | **36** |
| Falsche Größe (<30 / >2,000,000 IPs) | **26** |
| IP-Datei veraltet (>30d) | **22** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 7,156 | 13.1% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,226 | 69.7% | 0.0% | 0 | 🆕 NEU |
| `cbuijs_hagezi` | [cbuijs/hagezi](https://github.com/cbuijs/hagezi) | GITHUB | 29,318 | 37.9% | 0.0% | 129 | 🆕 NEU |
| `criticalpathsecurity_zeek_intelligence_feeds` | [CriticalPathSecurity/Zeek-Intelligence-Feeds](https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds) | GITHUB | 1,629 | 88.6% | 0.0% | 406 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `SecOps-Institute/SpamhausIPLists` | GITHUB | Größe: 0 IPs |
| `ErcinDedeoglu/crypto-market-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ErcinDedeoglu/WhisperDock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `poddmo/ufw-blocklist` | GITHUB | Zu alt: 597d |
| `Truvis/Suricata_Threat-Hunting-Rules` | GITHUB | Zu alt: 2247d |
| `hookprobe/hookprobe` | GITHUB | Größe: 0 IPs |
| `gl0bal01/intel-codex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `panguard-ai/panguard-ai` | GITHUB | IP-Datei 148d alt |
| `BishopFox/sliver` | GITHUB | IP-Datei 283d alt |
| `activecm/rita` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chu0119/Pojun` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `YDHCUI/manjusaka` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MayankFawkes/Python-Botnet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `epsylon/ufonet` | GITHUB | Zu alt: 43d |
| `yankywilson/jdy-botnet-threat-analysis` | GITHUB | Zu alt: 137d |
| `CirqueiraDev/KryptonC2` | GITHUB | Zu alt: 148d |
| `Syn2Much/VisionC2` | GITHUB | Zu alt: 201d |
| `Xart3mis/AKILT` | GITHUB | Zu alt: 223d |
| `CirqueiraDev/OverburstC2` | GITHUB | Zu alt: 294d |
| `kdfgjijkdtfh-cmyk/AQW-Packet-Insight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jflex-de/jflex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `osociety/network_tools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `topscoder/nuclei-wordfence-cve` | GITHUB | IP-Datei 205d alt |
| `RetireJS/retire.js` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `awslabs/automated-security-helper` | GITHUB | Größe: 0 IPs |
| `ossappscollective/OSS-DocumentScanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ostorlab/oxo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manisandro/gImageReader` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hahwul/smugglex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `margelo/react-native-vision-camera` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `doo/scanbot-sdk-example-react-native` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maurosoria/dirsearch` | GITHUB | IP-Datei 745d alt |
| `0liverFlow/HookPhish` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `matricali/cbrutekrag` | GITHUB | Zu alt: 814d |
| `Vigil-SOC/vigil` | GITHUB | Größe: 0 IPs |
| `chainguard-dev/osquery-defense-kit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WithSecureOpenSource/chainsaw` | GITHUB | IP-Datei 728d alt |
| `thalesgroup-cert/Watcher` | GITHUB | IP-Datei 67d alt |
| `Securonix/AutonomousThreatSweeper` | GITHUB | IP-Datei 1255d alt |
| `rami3l/pacaptr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vegardit/fast-apt-mirror.sh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cisagov/ansible-role-cobalt-strike` | GITHUB | Zu alt: 125d |
| `TH3xACE/EDR-Test` | GITHUB | Zu alt: 1322d |
| `S1ckB0y1337/Cobalt-Strike-CheatSheet` | GITHUB | Zu alt: 1734d |
| `stanford-esrg/lzr` | GITHUB | Zu alt: 306d |
| `stanford-esrg/gps` | GITHUB | Zu alt: 1370d |
| `elddy/NimScan` | GITHUB | Zu alt: 1732d |
| `jaime681/html5-game-build-tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `huijingfei/Shadowrocket-Rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2dust/v2rayN` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alvin9999-newpac/Sing-Box-Plus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kwisma/Sub-Store-node` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mhyrzt/xrat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dawn-lc/ArchivePasswordTestTool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wobqqq/oc-fortify-smart-ip-blocker-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrhenrike/MikrotikAPI-BF` | GITHUB | Zu alt: 43d |
| `rulezet/rulezet-core` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cisagov/Malcolm` | GITHUB | IP-Datei 83d alt |
| `vulncheck-oss/initial-access-community` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrixs/ru_asn_prefixes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CodePagol/ISP-Mikrotik-Billing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecOps-7/MikroDash` | GITHUB | Größe: 0 IPs |
| `eworm-de/routeros-scripts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hotspotbilling/phpnuxbill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EvilFreelancer/docker-routeros` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pavel-odintsov/fastnetmon` | GITHUB | IP-Datei 1108d alt |
| `olivierb46/PyFRC2G` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sepandhaghighi/samila` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pymumu/smartdns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `onyks-os/TransparentTorProxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splify2/steer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ion-storm/emotet-malware-killer` | GITHUB | Zu alt: 2461d |
| `StellarLawyer/monero-miner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SettlementCourse/genesis-miner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anirudhmalik/xhunter` | GITHUB | Zu alt: 190d |
| `XZB-1248/Spark` | GITHUB | Zu alt: 237d |
| `thisisnzed/Pandora` | GITHUB | Zu alt: 257d |
| `seqre/rast` | GITHUB | Zu alt: 278d |
| `itaymigdal/Nimbo-C2` | GITHUB | Zu alt: 283d |
| `Tomiwa-Ot/moukthar` | GITHUB | Zu alt: 363d |
| `Ixve/Red-Team-Tools` | GITHUB | Zu alt: 368d |
| `sqlerrorthing/ShadowSniff` | GITHUB | Zu alt: 394d |
| `thedudefello/ToxicDatabase` | GITHUB | Zu alt: 420d |
| `AiGptCode/AiGPT-WordPress-Exploitation-Framework` | GITHUB | Zu alt: 163d |
| `s0ld13rr/claude-code-backdoor` | GITHUB | Zu alt: 206d |
| `malwarekid/OnlyShell` | GITHUB | Zu alt: 258d |
| `tgmtproxy/telegram-mtproto-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mauricegift/free-proxies` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `purpleveterantake/clion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Skillter/ProxyGather` | GITHUB | IP-Datei 120d alt |
| `papapapapdelesia/Emilia` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ictinnovations/ictcore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `soxoj/telegram-bot-dumper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fastfire/deepdarkCTI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zsazsa-project/zsazsa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ssnkhan/adversarial-threat-modelling` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RansomLook/RansomLook` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gameworkerkim/CYBER-THREAT-INTELLIGENCE-REPORT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gripebomb/ThreatDeck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `K2SOsint/Legendary_OSINT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wagga40/LogsTotal` | GITHUB | IP-Datei 42d alt |
| `Liberty91LTD/cti-skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typedb-osi/typedb-cti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anpa1200/Unpacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `banaxou/dark-sherlock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jonaylor89/sherlock-rs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blackstork-io/blackstork-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stnolting/neorv32` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `INFOKOM-KI/Wazuh-MCP-Server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stnolting/neorv32-setups` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AnonCatalyst/Ominis-OSINT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `soxoj/maigret` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nikitastupin/orgs-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `j3ssie/osmedeus` | GITHUB | IP-Datei 92d alt |
| `edoardottt/favirecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `7WaySecurity/cloud_osint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `projectdiscovery/urlfinder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stanislav-web/OpenDoor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `c0dejump/HawkScan` | GITHUB | IP-Datei 1986d alt |
| `Zyrexnn/Cybermes` | GITHUB | IP-Datei 81d alt |
| `w0h1v/mcp-shodan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SomeKirill/wordlist_generator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `olizimmermann/s3dns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lu1sDV/wafmeow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `projectdiscovery/public-bugbounty-programs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `natlas/natlas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vflame6/leaker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AmgdGocha/DriveFS-Sleuth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `R3DRUN3/vermilion` | GITHUB | Zu alt: 68d |
| `ELMERIKH/TelecordC2` | GITHUB | Zu alt: 624d |
| `SitinCloud/Owlyshield` | GITHUB | Zu alt: 846d |
| `LyndLabs/DNS-DriveBy` | GITHUB | Zu alt: 1078d |
| `tasooshi/exfilkit` | GITHUB | Zu alt: 1760d |
| `GuardianWAF/GuardianWAF` | GITHUB | IP-Datei 93d alt |
| `wangwanjie/gately` | GITHUB | Größe: 0 IPs |
| `JayHoltslander/jays-wp-htaccess` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `padrino/padrino-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shuaiZend/PingWAF` | GITHUB | IP-Datei 36d alt |
| `maxlerebourg/crowdsec-bouncer-traefik-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `roxy-wi/roxy-wi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tempesta-tech/tempesta` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bukaleyang/zhongkui-waf` | GITHUB | IP-Datei 815d alt |
| `FWGS/xash3d-fwgs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aaPanel/aaWAF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Safe3/uusec-waf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uwaserver/uwas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lancard/nginx-webui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VultureProject/vulture-base` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `owasp-modsecurity/ModSecurity` | GITHUB | IP-Datei 736d alt |
| `corazawaf/libcoraza` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `416rehman/DeepZero` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nicolasrodetr-cmyk/py-firewall-network-monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `netalertx/NetAlertX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `greyhat-academy/lists.d` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3proxy/3proxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Y0oshi/Project-Deep-Focus` | GITHUB | Zu alt: 45d |
| `edoardottt/pphack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `karthikkbala/MISP-QRadar-Integration` | GITHUB | Zu alt: 1635d |
| `0x4D31/galah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/medpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InnerWarden/innerwarden` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/conpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sjinks/mysql-honeypotd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joda32/owa-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xBallpoint/trapster-community` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johnnykv/heralding` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christophe77/express-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yvesago/imap-honey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `knalli/honeypot-for-tcp-32764` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ashmckenzie/go-sshoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jekil/UDPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeytrap/honeytrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sjinks/ssh-honeypotd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bocajspear1/honeyhttpd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/tanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `darkarnium/kako` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IllusiveNetworks-Labs/WebTrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/honeybits` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/modpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kryptoslogic/rdppot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `naorlivne/dshp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nsmfoo/dicompot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sa7mon/miniprint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/honeydet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RevengeComing/DemonHunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpr5/ngrep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RPISEC/Malware` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hempnall/broyara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JamesHabben/evolve` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/malwarehouse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ashishb/android-security-awesome` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/flare-vm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corkami/pics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ch3k1/squidmagic` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Konloch/bytecode-viewer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hugsy/gef` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keithjjones/cuckoo-modified-api` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KoreLogicSecurity/mastiff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vivisect/vivisect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `F-Secure/see` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joxeankoret/pyew` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maliceio/malice` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `unipacker/unipacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/stringsifter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre/multiscanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellman/xortool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rurik/Noriben` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HynekPetrak/javascript-malware-collection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NationalSecurityAgency/ghidra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gurnec/HashCheck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `angr/angr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sycurelab/DECAF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmersonElectricCo/boomerang` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/iocs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbremer/sflock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `moyix/panda` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AbertayMachineLearningGroup/CryptoKnight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `phdphuc/mac-a-mal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MITRECND/chopshop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RamadhanAmizudin/python-icap-yara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aptnotes/data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/flare-floss` | GITHUB | IP-Datei 33d alt |
| `programa-stic/barf-project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BinaryAnalysisPlatform/bap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `guelfoweb/peframe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kevthehermit/VolUtility` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `9b/pdfxray_lite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keithjjones/visualize_logs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `williballenthin/python-evt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ShaneK2/inVtero.net` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ANSSI-FR/polichombr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `simsong/bulk_extractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `extremecoders-re/pyinstxtractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomchop/malcom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OMENScan/AChoir` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omriher/CapTipper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aquynh/capstone` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bwall/bamfdetect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `airbnb/binaryalert` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/IPinfo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `9b/malpdfobj` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `robbyFux/Ragpicker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sooshie/packerid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misterch0c/malSploitBase` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `msuhanov/regf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uppusaikiran/yara-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Defense-Cyber-Crime-Center/DC3-MWCP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rurik/Java_IDX_Parser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `quark-engine/quark-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/NoMoreXOR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keithjjones/fileintel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `merces/aleph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diogo-fernan/malsub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rieck/malheur` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vmt/udis86` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uppusaikiran/malware-organiser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x64dbg/ScyllaHide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aol/moloch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `radareorg/cutter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vduddu/Malware` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hugsy/codebro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `season-lab/bluepill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BromiumLabs/PackerAttacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jnraber/VirtualDeobfuscator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `504ensicsLabs/DAMM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swwwolf/wdbgark` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `monnappa22/Limon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FGRibreau/mailchecker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/AnalyzePDF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tklengyel/drakvuf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `michael-yip/MaltegoVT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sketchymoose/TotalRecall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CyberShadow/RABCDAsm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codypierce/hackers-grep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ytisf/muninn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/ember` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LordNoteworthy/al-khaser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rjhansen/nsrllookup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:owlsecx/OHoneyToken` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:owlsecx/OTarpit` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ashin-06/synthetic-fraud-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ashin-06/split-learning-credit-bureau` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diablomike20/Andersen` | GITHUB | Größe: 0 IPs |
| `Ashin-06/soc-copilot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shaman-oss/passfab-unlocker-desktop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `affinity-ops/OS-Cicada` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ashin-06/sanctions-fuzzy-screening` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `P1gBagPt-Homelab/home-server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Brinsleym/scorecraft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NorthOfPotential/KratosOS` | GITHUB | IP-Datei 34d alt |
| `fwlhh/mimic` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Serpe-nt/Kage` | GITHUB | Größe: 0 IPs |
| `fordkuppp/jenosize-ai-devops-assignment-patsakorn` | GITHUB | Größe: 0 IPs |
| `yannmh007/innocent` | GITHUB | Größe: 0 IPs |
| `Ashin-06/payment-phish-guard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `discopotato-houte/Emsisoft-Anti-Malware` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `psrockstar098/devworld` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `July-X/dsh-xlink` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codefort-sec/codefort` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Banzaaaaai/Security-Digest` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Gatlarf/netlens` | GITHUB | Größe: 0 IPs |
| `victoralexandreofc122/Servidor-missoes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Decryptos/Security-project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rimpianto/proxmox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `patildevendra01/nse-day-trader-skill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlexHyslop/WebsiteSecurity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Its-Anandu/ISTE-WEBDEV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IvanBBaev/facebook-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jasperwoodchuck/ai-web-threat-intelligence` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `luisdiko14-lab/Cool.game` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Gabrielcarvfer/carteiro` | GITHUB | Größe: 0 IPs |
| `celikj/intern` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `udirobert/cantheria` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `demonanic/Gauntlet-s-survival` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JustinL330/just-to-cube` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neodix42/crypto-wallet` | GITHUB | Größe: 0 IPs |
| `berion1982/NetzScanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ArpanMaheshwari144/Prep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sudeepksingh/aigw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `a36d/FumbleBee` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Easyere/cubacadabra-wasm-runtime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ashin-06/federated-fraud-shield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arleoarlo-max/Arcane-Chip-Forge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dyli2009-cmd/tillsyno` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lmmx/mibz2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KrishBhayani/ML-Assignment-2-Bank-Marketing-Classification` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mathilde-Team/Gcm4` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vanshcodeworks/burrow` | GITHUB | Größe: 0 IPs |
| `soguttu-lgtm/aiseesoft-unlocker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kavinash0310/aura-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Stolls32/quant-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `foenix2018/pink-war` | GITHUB | Größe: 0 IPs |
| `StateofIntent/epistemic-happ` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `derinmilletc-dev/KA-STRADE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ashin-06/chargeback-dispute-arbiter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `artemo777/Avero` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ennajari/Snitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ijlakh-cyber/security-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cpyeoman-crypto/project-25-26-seravo-0-sapor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `valcriss/infrastructure` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ashin-06/behavioral-auth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fuyuki0/unlimitedpipe-feeds` | GITHUB | IP-Datei 35d alt |
| `Phuxt162005/IoT_He_thong_phong_hoc_thong_minh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `newmassrael/watching-zenoh` | GITHUB | Größe: 0 IPs |
| `state-vector/bridge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ashin-06/atproof` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hazelfjeld/ai-atlas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlmasAina/Hike-up` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omikhan4901/asr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `absolutezero-25/Dark-Void` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitsugue/argus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `just-every/run-pencil` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RYTZZ/comsoc-qr-attendance` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ashin-06/adversarial-fraud-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nadeem-majeedch/CyberSecurity` | GITHUB | Größe: 0 IPs |
| `badboy1959/I-Know-This` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Antarsoft/morphness` | GITHUB | Größe: 0 IPs |
| `waynestate/rollcall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `asimu-prancing/Once-Human` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maryan-qc/therapy-scheduling` | GITHUB | Größe: 0 IPs |
| `Konan69/wsl-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fmsouza/lanekeep` | GITHUB | IP-Datei 100d alt |
| `stalkr318/Softperfect-Network-Scanner-Full-Version-Unlocked` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hal-c2/hal-c2` | GITHUB | Größe: 0 IPs |
| `IamDejman/fm-lens` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MASK1440/instamart-copilot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fuma2514/Fuma2514` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheSimulationMagician/hi8ctane` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `etyloppihacilem/qrprotec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `banqueenie6/360-Nsa-Cyber-Weapons-Defense-Tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DCastellanos4/F.R.I.D.A.Y-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HarenaFiantso/pqscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Holdi601/3DHeat-GameCapture` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Priyanshu2068/portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jcshowalter23/open-late` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zackshal/opla-security-lab` | GITHUB | Größe: 0 IPs |
| `MBHudson/Autonomous` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jdotc1/MacScope-app` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OneBusAway/sidecar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chkm8-agent/r3lik-site-pages` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gabebartolo-spec/Afl-auto-battler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hornetrish/Phantom-Camo-Companion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mozgovojilya9-a11y/Deal-Radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shigeya-t/Langria` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tannergolden/tannergolden` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gopalaakkrishna/sports-model` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HiyokoSauna37/honeypot-report` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neitanod/searchfor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SejatiDimedia/harnessly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `akachwaha27/shorts-autopilot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pahayward/LateralCMS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NUYSEC/nuymonnn` | GITHUB | Overlap zu gering: 0.0% |
| `MichaelRoe-Software/phone-remote-for-stremio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `staccDOTsol/birth-image-runtime` | GITHUB | Größe: 0 IPs |
| `theyappie/yappie-pro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nexus-Aethra/DSHBox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `scarlettzhangxh/exitliq` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arturomed31-cyber/roblox-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stevelasudata/sky-dragon-duel-brain` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dvitoS/tcg-ai-market` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fixman93/toogoodtogo-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `muzam2/vision-bass-player` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ihsanmp/Crypto-Analis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sgjigis-glitch/MortalShell-Omnipresence` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pharn-dev/pharn-ci` | GITHUB | Größe: 0 IPs |
| `Ninsei-Labs/sdk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joevermonticalbo20/cartiq` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Azathothas/psgen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Habibullah-hub/SAAD-YOUSUF-KAKAR-Ultimate-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alfatraktorbow53/Dauntless` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aicologne/aic-hardware-deals` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Desifighter/selfhelp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Abbagigo13/silentproof` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cptlight/shennong` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Daddyg88/Starling` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pixelspy-1/Yet-Another-Cleaner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `princedangola130-creator/grid-bot-core` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `avdalyanhayk/anna-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `devonflap/RYNOSCAN` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rhutsul/leave-portal` | GITHUB | Größe: 0 IPs |
| `shortsjunction55-crypto/ledger-forge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ranxianglei/billion-context` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dennis-Otto/paperless-sync` | GITHUB | Größe: 0 IPs |
| `rofbeasts-sys/wissensduell` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nghuyenthevinh2000/social-content` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `raqune89/Omarchy-Plugins` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `daeken/Alkyhol` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Snowstormme/tennisd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jedharveycambel18-arch/gecko-tcp-bridge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NRTechnology/DefenseOps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ggb52-wq/edla-judge-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nicoletanyt/FSDP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vzroslieigry/maxagent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `asfaltobollente/allod` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kjin17/agora-smallvillage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ManuelAFernandezFdez/home-network-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aptenodyte/ca-cert-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thefeetwashers/Wholesaling-OS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PRINCE2-AI/lexsi-agentic-hinglish` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `soheylfalahzade/perception-aware-corridor-control` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DIYgod/pinky` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hardikg2907/sparmate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ahs786-web/trading-events-calendar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NoobInDaHause/Kepler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vipios/ai-assistant` | GITHUB | Größe: 0 IPs |
| `Munaqib80/HORNET-RAT-Stealth-Suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SirStormz/u1-doctor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andyydz/sentinel-soc-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tianjanahary05-source/reason-14-installer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pandecora1971-dev/bnpnama` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `szymonrychu/agents-orchestrator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jaredsia-svg/psycheai-app` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `davletovaalmira11-creator/polymarket-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xuancanh/YAAP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 25,565 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 17,412 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,058 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,398 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,800 | 0.2% | 120 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 5,295 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 5,984 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 766 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,114 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 821 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 601 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 532 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 374 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,974 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,974 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 20,600 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 13,964 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 7,941 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 5,093 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 7,093 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 216,284 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 5,025 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 6,305 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,633 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 4,547 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 32,722 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 4,367 | 64.3% | 938 | 2026-09-04 |
| `cbuijs_hagezi` | GITHUB | 29,318 | 37.9% | 129 | 2026-11-08 |
| `criticalpathsecurity_zeek_intelligence_feeds` | GITHUB | 1,629 | 88.6% | 406 | 2026-11-08 |
| `mohammedcha_proxripper` | GITHUB | 54,646 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,698 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 118,282 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 118,287 | 0.2% | 36 | 2026-07-05 |
| `telekom_security_listbot` | GITHUB | 513 | 10.4% | 22 | 2026-10-18 |
| `dinoz0rg_proxy_list` | GITHUB | 91,825 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,807 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 94,652 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 109,527 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 65,016 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 102,559 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 16,227 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 97,800 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 511 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 500,911 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 220,069 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 174,824 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 92,308 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 173,094 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 177,372 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 90,095 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 95,154 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 280,574 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 53,358 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 222,054 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 22,439 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 16,850 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 15,035 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 181,343 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,980 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 11,371 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 8,643 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 26,921 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 15,958 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 13,378 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 24,177 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,836 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 3,796 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,822 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,706 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 1,523 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 5,168 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 3,569 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,285 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,863 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 133,711 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 593 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 28,993 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 2,243 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 4,084 | 79.4% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 6,313 | 64.3% | 10 | 2026-10-11 |
| `ian_lusule_proxies` | GITHUB | 3,411 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,468 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,365 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 377,861 | 22.0% | 6 | 2026-07-08 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,326 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 49 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 106,397 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 110,803 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 23,362 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 92 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 109,442 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,299 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,758 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 74 | 28.1% | 2 | 2026-08-02 |
| `runtechx_dns_runtech_ao` | GITHUB | 20,077 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 29,834 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,409 | 31.1% | 1 | 2026-07-14 |
| `klonet_it_ip_threat_lists` | GITHUB | 141,051 | 51.5% | 1 | 2026-10-11 |
| `klonet_it_ip_threat_lists_blocklist_apache` | GITHUB | 9,066 | 9.7% | 1 | 2026-10-11 |
| `idleadmin_threatfeed` | GITHUB | 53,260 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 73,505 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,112 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 139,885 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 197,991 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 142,959 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 219,801 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,103 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 35,261 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 17,259 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 18,185 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,705 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 10,033 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,729 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,618 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 6,559 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,000 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,793 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,124 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,532 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 4,654 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,660 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 1,332 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 6,906 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 991 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,248 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,177 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,087 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,179 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,052 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 917 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,196 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,084 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,279 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 568 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,964 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,429 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 974 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 11,137 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,950 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 93,526 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 93,993 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 93,772 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 92,527 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 95,662 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 108,868 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,122 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 41,530 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,691 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,155 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,000 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,620 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 39,903 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 19,354 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 11,176 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 4,209 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 23 | 63.9% | 0 | 2026-08-12 |
| `zgzyh_malicious_website_detection` | GITHUB | 33,747 | 3.1% | 0 | 2026-08-15 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,789 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 17,948 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 6,365 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,579 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 1,318 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 489 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 227 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 9,544 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 96,438 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 91,073 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 89,545 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 90,772 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 90,413 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 34,119 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 4,491 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 4,436 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 1,483 | 76.9% | 0 | 2026-09-25 |
| `brandontroidl_blocklist_all_90d` | GITHUB | 6,583 | 61.9% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_aggressive` | GITHUB | 68 | 80.9% | 0 | 2026-10-11 |
| `claudiusdecimius_ioc_ipsets_tor_exits` | GITHUB | 1,241 | 69.1% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_sblam` | GITHUB | 1,077 | 30.3% | 0 | 2026-10-18 |
| `helio4k_bad_ip` | GITHUB | 2,193 | 43.3% | 0 | 2026-10-25 |
| `verkombr_block_list_firewalls` | GITHUB | 884 | 46.9% | 0 | 2026-10-25 |
| `blawoblowa_blackened` | GITHUB | 1,243 | 56.0% | 0 | 2026-11-01 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 7,156 | 13.1% | 0 | 2026-11-08 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,226 | 69.7% | 0 | 2026-11-08 |

---
*Generiert: 2026-11-08 12:29 CET (Europe/Berlin)*