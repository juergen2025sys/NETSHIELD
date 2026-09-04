# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-04 21:28 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 25 |
| Kandidaten gesamt | **10577** |
| davon GitHub (Topics+Code) | **10494** |
| davon GitLab | **83** |
| davon Awesome-Lists | **2397** |
| Tools/Libraries vor Eval gefiltert | **1375** |
| davon Hard-Reject (awesome-Liste etc.) | **149** |
| EVAL-Kandidaten (nach Stratifizierung) | **382** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **382** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **380** |
| Neu angenommene Feed-Dateien | **1** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **187** |
| Abgelehnte Repositories (dieser Run) | **380** |
| davon GitLab abgelehnt | **7** |
| Feeds gesamt (aktiv) | **188** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **160173** |
| SQLite-Refresh-Cache-Hits | **0/191** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **204** |
| Repo zu alt (>30d) | **149** |
| IP-Datei veraltet (>30d) | **21** |
| Falsche Größe (<30 / >2,000,000 IPs) | **5** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |
| Sonstige | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `criticalpathsecurity_public_intelligence_feeds` | [CriticalPathSecurity/Public-Intelligence-Feeds](https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds) | GITHUB | 31,698 | 3.8% | 0.0% | 133 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `fabriziosalmi/asn-api` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fortinetdev/terraform-provider-fortios` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Deilis/IOC-validator-deivscan` | GITHUB | Zu alt: 1006d |
| `RekitRex21/Dino_Scan` | GITHUB | Zu alt: 194d |
| `Eswar19102005/Scam-Radar` | GITHUB | Zu alt: 145d |
| `mashooquealiamur/blocked-ip-list` | GITHUB | Zu alt: 446d |
| `nextgens/Tor` | GITHUB | Zu alt: 3518d |
| `torproject/torspec` | GITHUB | Zu alt: 165d |
| `ekolis/FrEee` | GITHUB | Zu alt: 96d |
| `securityinabox/siabguide` | GITHUB | Zu alt: 4141d |
| `spurintel/spur-saas-log-enrichment` | GITHUB | Zu alt: 316d |
| `HewlettPackard/foedus_code` | GITHUB | Zu alt: 3357d |
| `ishell/Exploits-Archives` | GITHUB | Zu alt: 4532d |
| `basvandorst/where-is-satoshi` | GITHUB | Zu alt: 874d |
| `zencefilefendi/zencefil-sentinel-soc` | GITHUB | Zu alt: 218d |
| `yao8839836/KGE-LDA` | GITHUB | Zu alt: 2930d |
| `SamPlaysKeys/ip_whois_tool` | GITHUB | Zu alt: 466d |
| `PunamTupe77/security` | GITHUB | Zu alt: 641d |
| `ddagunts/dfirewall` | GITHUB | Zu alt: 323d |
| `slimseidl/NetworkSecurity` | GITHUB | Zu alt: 437d |
| `stratosphereips/Slips-tools` | GITHUB | Zu alt: 87d |
| `rajlivee/End-point-detection-and-Response-` | GITHUB | Zu alt: 68d |
| `rawdela/Week_5_Project` | GITHUB | Zu alt: 172d |
| `sashafrey/topicmod` | GITHUB | Zu alt: 4367d |
| `dimaswahyudi7/IoC-Collections` | GITHUB | Zu alt: 456d |
| `k3nundrum/redteamtips` | GITHUB | Zu alt: 1049d |
| `rawdela/Week_11_Project` | GITHUB | Zu alt: 141d |
| `praisel-ekpenyong/SOC-Automation-Scripts` | GITHUB | Zu alt: 210d |
| `khushalbhasin4488/sih_finals_2025` | GITHUB | Zu alt: 270d |
| `debojit-dev0/ElevateLabs_CS` | GITHUB | Zu alt: 257d |
| `rawdela/Week_10_Project` | GITHUB | Zu alt: 146d |
| `Blackstarproject/Repos` | GITHUB | Zu alt: 640d |
| `zpahuja/EM` | GITHUB | Zu alt: 3433d |
| `real-horizon02/PhishGuard-AI` | GITHUB | Zu alt: 178d |
| `Ununp3ntium115/AbuseBlacklist` | GITHUB | Zu alt: 49d |
| `naveen-verma18/URL_detector` | GITHUB | Zu alt: 328d |
| `gfazzz/kernel-shadows` | GITHUB | IP-Datei 35d alt |
| `EFI-Demo/Endpoint-Forecasting-and-Interpreting` | GITHUB | Zu alt: 1115d |
| `santhosheyzz/Email-Phishing-Analysis` | GITHUB | Zu alt: 464d |
| `toronto-ai/workshops` | GITHUB | Zu alt: 3237d |
| `aalab/paa` | GITHUB | Zu alt: 4236d |
| `gtriggiano/envoy-authorization-service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sayanghosh/LDA-SCVB0` | GITHUB | Zu alt: 4359d |
| `SilverLineFramework/benchmarks` | GITHUB | Zu alt: 1060d |
| `berez23/canvas` | GITHUB | Zu alt: 2010d |
| `superkeyor/ez` | GITHUB | Zu alt: 2311d |
| `rauhul/cs498` | GITHUB | Zu alt: 3125d |
| `saiharish587/RAG-Research` | GITHUB | Größe: 0 IPs |
| `TommyP702/TanPham` | GITHUB | Zu alt: 528d |
| `twothe/SE4-MoreFunMod` | GITHUB | Zu alt: 2651d |
| `Chandan220698/Ineuron-DataScience` | GITHUB | Zu alt: 1492d |
| `yanggao1119/tfidf_cosine_cpp` | GITHUB | Zu alt: 4512d |
| `bobrunner7/Lyndvhar` | GITHUB | Zu alt: 376d |
| `sivapvarma/cse291d-project-topicmodels` | GITHUB | Zu alt: 3726d |
| `Keyuan125/CS441-AppliedMachineLearning` | GITHUB | Zu alt: 1625d |
| `DanielV819/Frauddetection` | GITHUB | Zu alt: 455d |
| `AbrhamSayd/tezcatlipoca-auth` | GITHUB | Zu alt: 301d |
| `KanaOzaki/SVI_GLDA` | GITHUB | Zu alt: 2806d |
| `FelipeCarvalhoS/smash-ultimate-api` | GITHUB | Zu alt: 127d |
| `cpsource/postWolf` | GITHUB | Zu alt: 48d |
| `sujaypat/cs498aml` | GITHUB | Zu alt: 2690d |
| `efeslab/ada-portathon` | GITHUB | Zu alt: 216d |
| `kans/BitBlinder` | GITHUB | Zu alt: 5400d |
| `nramaker/AML_HW7` | GITHUB | Zu alt: 3069d |
| `thisispriyanshu/saheli` | GITHUB | Zu alt: 579d |
| `lbds137/cos435-final-project-2014` | GITHUB | Zu alt: 4487d |
| `maxamin/exploitpack-from-an-APT-infrastructure` | GITHUB | Zu alt: 1660d |
| `tytydraco/yessleep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LaoWang-Lab/multi-dimensional-topic-model` | GITHUB | Zu alt: 3936d |
| `sfeng15/Machine-Learning` | GITHUB | Zu alt: 3671d |
| `sam1016yu/DB-Exp-Sensitivity` | GITHUB | Zu alt: 1557d |
| `FiveEyes/playground` | GITHUB | Zu alt: 3426d |
| `CatalinVoss/anchor-baggage` | GITHUB | Zu alt: 4497d |
| `hellais/torspec` | GITHUB | Zu alt: 5301d |
| `rhiga2/AppliedML` | GITHUB | Zu alt: 3773d |
| `Silentsoul04/packetstorm-papers` | GITHUB | Zu alt: 2110d |
| `Abdul-Sarim-Khan/FLARE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elastic/integrations` | GITHUB | IP-Datei 227d alt |
| `ysfulu/Usom-Balcklist-Sc` | GITHUB | Zu alt: 92d |
| `blackhook/nessus-plugins` | GITHUB | Zu alt: 1147d |
| `kraloveckey/venom` | GITHUB | Zu alt: 38d |
| `Leon406/proxypool` | GITHUB | Zu alt: 1812d |
| `mitchellkrogza/apache-ultimate-bad-bot-blocker` | GITHUB | Overlap zu gering: 0.0% |
| `mitchellkrogza/Fail2Ban.WebExploits` | GITHUB | Zu alt: 1644d |
| `mitchellkrogza/Suspicious.Snooping.Sniffing.Hacking.IP.Addresses` | GITHUB | Zu alt: 1874d |
| `mitchellkrogza/fail2ban-useful-scripts` | GITHUB | Zu alt: 2998d |
| `mitchellkrogza/linux-server-administration-scripts` | GITHUB | Zu alt: 3440d |
| `clash-verge-rev/clash-verge-rev` | GITHUB | IP-Datei 173d alt |
| `GUI-for-Cores/GUI.for.SingBox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `all-contributors/allcontributors.org` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beck-8/subs-check` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `asdlokj1qpi233/subconverter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bestnite/sub2clash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bulianglin/demo` | GITHUB | Zu alt: 108d |
| `derhuerst/email-providers` | GITHUB | Zu alt: 318d |
| `tindy2013/stairspeedtest-reborn` | GITHUB | Zu alt: 1184d |
| `firehol/iprange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `firehol/firehol` | GITHUB | Zu alt: 157d |
| `platformbuilds/Tor-IP-Addresses` | GITHUB | Zu alt: 920d |
| `acidvegas/proxytools` | GITHUB | Zu alt: 760d |
| `cbuijs/ipasn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ebrasha/free-v2ray-public-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ErcinDedeoglu/crypto-market-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `THORCollective/HEARTH` | GITHUB | IP-Datei 40d alt |
| `muchdogesec/obstracts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MalwareSamples/Malware-Feed` | GITHUB | Zu alt: 1967d |
| `0xMarcio/pocindex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CriticalPathSecurity/Zeek-Intelligence-Feeds` | GITHUB | Identischer Inhalt wie kraloveckey_ipsets_blocklist_bds_atif |
| `EndlessFractal/Threat-Intel-Feed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JMousqueton/CTI-MSTeams-Bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `777genius/social-monitor` | GITHUB | IP-Datei 34d alt |
| `RavinduRathnayaka/LiveThreatMap-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `The-Privacy-Commons-Institute/chrome-mal-ids` | GITHUB | Größe: 0 IPs |
| `jm33-m0/emp3r0r` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abdullahbutt/wordfeather` | GITHUB | Größe: 0 IPs |
| `maxDcb/C2TeamServer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chainreactors/malice-network` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Team-intN18-SoybeanSeclab/prtstrike` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ilynyne/discord-bot-ddos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `The-Z-Labs/bof-launcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LAME-Projects/stratum-c2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SquidSec/SquidC5` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dn9uy3n/Modern-Red-Team-Infrastructure` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spellshift/realm` | GITHUB | IP-Datei 921d alt |
| `chainreactors/malefic` | GITHUB | IP-Datei 75d alt |
| `iDigitalFlame/ThunderStorm` | GITHUB | Zu alt: 35d |
| `ElJaviLuki/CobaltStrike_OpenBeacon` | GITHUB | Zu alt: 38d |
| `Coff0xc/AutoRedTeam-Orchestrator` | GITHUB | Zu alt: 40d |
| `lolc2/lolc2.github.io` | GITHUB | Zu alt: 44d |
| `D00Movenok/BounceBack` | GITHUB | Zu alt: 46d |
| `dstours/OctoC2` | GITHUB | Zu alt: 48d |
| `28Zaaky/khaos-c2` | GITHUB | Zu alt: 58d |
| `Jieyab89/Loader-and-shell-code-AV-Evasion` | GITHUB | Zu alt: 62d |
| `r4ulcl/Mythic-OSEP-CheatSheet` | GITHUB | Zu alt: 79d |
| `wsummerhill/C2_RedTeam_CheatSheets` | GITHUB | Zu alt: 85d |
| `BlackSnufkin/Maverick` | GITHUB | Zu alt: 89d |
| `ZZ0R0/Proteus` | GITHUB | Zu alt: 114d |
| `maxDcb/C2Implant` | GITHUB | Zu alt: 116d |
| `mwakidenis/mwakidenis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `illusionsec/DDOS-archive` | GITHUB | IP-Datei 521d alt |
| `deepfield/public-research` | GITHUB | Zu alt: 37d |
| `efxtv/L3MON` | GITHUB | Zu alt: 58d |
| `Bialomazur/Brutus` | GITHUB | Zu alt: 117d |
| `bmshifat/TecSpy` | GITHUB | Zu alt: 203d |
| `0x4meliorate/toxnet` | GITHUB | Zu alt: 208d |
| `zarkones/OnionC2` | GITHUB | Zu alt: 309d |
| `zarkones/ControlSTUDIO` | GITHUB | Zu alt: 381d |
| `slipperysquid/SquidNet` | GITHUB | Zu alt: 386d |
| `zarkones/XENA` | GITHUB | Zu alt: 496d |
| `trackmastersteve/HackServ` | GITHUB | Zu alt: 505d |
| `GoutamHX/MAXXRAT` | GITHUB | Zu alt: 559d |
| `NixWasHere/NebulaC2` | GITHUB | Zu alt: 562d |
| `TomVN107080/packet-warden` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maurosoria/dirsearch` | GITHUB | IP-Datei 680d alt |
| `Fabi019/hid-barcode-scanner` | GITHUB | IP-Datei 532d alt |
| `defended-net/malwatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Udayraj123/OMRChecker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marven11/Fenjing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tencent/AI-Infra-Guard` | GITHUB | IP-Datei 263d alt |
| `mpaymenremora/QuantumSeal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manuc66/node-hp-scan-to` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Samsung/LPVS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `87owo/PYAS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yogeshojha/rengine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `justcallmekoko/ESP32Marauder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AdventDevInc/kudu` | GITHUB | IP-Datei 162d alt |
| `theaog/spirit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ZupIT/horusec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ostorlab/oxo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khoren93/flutter_zxing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `librats/rats-search` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `doo/scanbot-sdk-example-android` | GITHUB | IP-Datei 547d alt |
| `Samsung/CredSweeper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stapelberg/scan2drive` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hounddogai/hounddog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Intsights/PyRepScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kristuff/abuseipdb-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nyvorin/badwords` | GITHUB | Zu alt: 37d |
| `Adamm00/IPSet_ASUS` | GITHUB | Zu alt: 46d |
| `cobaltdisco/Google-Chinese-Results-Blocklist` | GITHUB | Zu alt: 180d |
| `EvotecIT/PSBlackListChecker` | GITHUB | Zu alt: 202d |
| `K3V1991/Passing-SafetyNet-with-Magisk-Zygisk-and-DenyList` | GITHUB | Zu alt: 875d |
| `ThoZed/graylog-cp-watchguard` | GITHUB | Zu alt: 2580d |
| `kaisero/fireREST` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mferland/libzc` | GITHUB | Größe: 0 IPs |
| `bernardladenthin/BitcoinAddressFinder` | GITHUB | Größe: 0 IPs |
| `qtc-de/remote-method-guesser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chaitin/SafeLine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x90skysn3k/brutespray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `napolux/paroleitaliane` | GITHUB | IP-Datei 491d alt |
| `0xPugal/fuzz4bounty` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `samuelcaldas/Bruteforce-Bootloader-Unlocker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rtulke/AirJack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Touti-Sudo/Touti-Cracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `niyankhadka/crypto-wallet-bruteforce` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vanhauser-thc/thc-hydra` | GITHUB | Zu alt: 36d |
| `dreddsa5dies/goHackTools` | GITHUB | Zu alt: 44d |
| `infinition/Bjorn` | GITHUB | Zu alt: 46d |
| `duyet/bruteforce-database` | GITHUB | Zu alt: 46d |
| `MorDavid/BruteForceAI` | GITHUB | Zu alt: 49d |
| `Tuhinshubhra/CMSeeK` | GITHUB | Zu alt: 49d |
| `chkndrp/OneShot-Extended` | GITHUB | Zu alt: 52d |
| `harkerbyte/linux-monster` | GITHUB | Zu alt: 67d |
| `samsesh/SocialBox-Termux` | GITHUB | Zu alt: 77d |
| `X-Stuff/CudaKeeloq` | GITHUB | Zu alt: 80d |
| `aryainjas/Microllect` | GITHUB | Zu alt: 84d |
| `Rem01Gaming/OneShot-Termux` | GITHUB | Zu alt: 85d |
| `animir/node-rate-limiter-flexible` | GITHUB | Zu alt: 88d |
| `ghluka/username-checker` | GITHUB | Zu alt: 106d |
| `jakka351/Ford-ECU-Bruteforcer` | GITHUB | Zu alt: 108d |
| `Antu7/python-bruteForce` | GITHUB | Zu alt: 118d |
| `threat9/routersploit` | GITHUB | Zu alt: 122d |
| `random-robbie/bruteforce-lists` | GITHUB | Zu alt: 127d |
| `ariary/cfuzz` | GITHUB | Zu alt: 136d |
| `marcvincenti/bitp0wn` | GITHUB | Zu alt: 151d |
| `Mr-P4p3r/wordlist-br` | GITHUB | Zu alt: 157d |
| `Cyber-Dioxide/Gmail-Brute` | GITHUB | Zu alt: 159d |
| `r3bo0tbx1/tor-guard-relay` | GITHUB | IP-Datei 50d alt |
| `EntySec/Shreder` | GITHUB | Zu alt: 774d |
| `jm33-m0/mec` | GITHUB | Zu alt: 1513d |
| `pwnesia/ssb` | GITHUB | Zu alt: 1722d |
| `InfosecMatter/SSH-PuTTY-login-bruteforcer` | GITHUB | Zu alt: 2113d |
| `abusix/xarf` | GITHUB | Zu alt: 80d |
| `f-bader/DefenderAndSentinelQueries` | GITHUB | IP-Datei 211d alt |
| `Nebulock-Inc/agentic-threat-hunting-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OISF/suricata` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityClaw/SecurityClaw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `calebevans/mulder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thalesgroup-cert/Watcher` | GITHUB | IP-Datei 130d alt |
| `ethack/tht` | GITHUB | IP-Datei 1553d alt |
| `kdeldycke/meta-package-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wimpysworld/deb-get` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AOSC-Dev/oma` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aptly-dev/aptly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rami3l/pacaptr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typedb/bazel-distribution` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mexirica/aptui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `avaje/avaje-inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lbr38/repomanager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheDuffman85/linux-update-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neur0map/glazepkg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PatchMon/PatchMon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stephenbrannon/IOCextractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpsenior/threataggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `facebook/ThreatExchange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `STIXProject/stix-viz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abhinavbom/Threat-Intelligence-Hunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abusesa/abusehelper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ocmdev/rita` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ptr32Void/OSTrICa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/jager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mandiant/ioc_writer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheHive-Project/Cortex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jheise/threatcrowd_api` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dougiep16/actortrackr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `1aN0rmus/TekDefense-Automater` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HurricaneLabs/machinae` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityRiskAdvisors/sra-taxii2-server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yahoo/PyIOCe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InQuest/omnibus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mlsecproject/tiq-test` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ioc-fang/ioc_fanger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johestephan/ibmxforceex.checker.py` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jheise/threatcmd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Netflix/Scumblr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aboutsecurity/rastrea2r` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SupportIntelligence/Icewater` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheHive-Project/Hippocampe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CrowdStrike/CrowdFMS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `foospidy/HoneyPy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BinaryDefense/goatrider` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mgeide/poortego` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/malstrom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stratosphereips/Manati` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/Forager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brianwarehime/threatnote` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fhightower/onemillion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EclecticIQ/cabby` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PaloAltoNetworks/minemeld` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `silascutler/MalPipe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `armbues/ioc_parser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lookingglass/opentpx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MISP/MISP-Taxii-Server` | GITHUB | IP-Datei 3577d alt |
| `TAXIIProject/libtaxii` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yelp/threat_intel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InQuest/python-iocextract` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `michael-yip/ThreatTracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/cacador` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TAXIIProject/yeti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `exp0se/harbinger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spacepatcher/softrace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kx499/ostip` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CylanceSPEAR/CyBot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `QTek/QRadio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `paulpc/nyx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ciscocsirt/gosint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mlsecproject/combine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KasperskyLab/klara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/Loki` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `S03D4-164/Hiryu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yara-Rules/rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spacepatcher/FireHOL-IP-Aggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tripwire/tardis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EclecticIQ/OpenTAXII` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kbandla/APTnotes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4d31/sqhunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `traetox/sshForShits` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `katkad/Glastopf-Analytics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sjhilt/GasPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sk4ld/gridpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `androguard/androguard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lanjelot/twisted-honeypots` | GITHUB | IP-Datei 3089d alt |
| `fw42/honeymap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/apkinspector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nsmfoo/antivmdetection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tillmannw/honeytrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kryptoslogic/rdppot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `glaslos/honeyprint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hgascon/acapulco` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `citronneur/rdpy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shbhmsingh72/Honeypot-Research-Papers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `torque59/nosqlpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xBallpoint/trapster-community` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thinkst/canarytokens` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gosecure/pyrdp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `buffer/pylibemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HoneySat/honeysat-deploy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/snare` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rubenespadas/DionaeaFR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/MysqlPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fygrave/honeyntp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `freak3dot/wp-smart-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dmpayton/django-admin-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/micros_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tnich/honssh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betheroot/sticky_elephant` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `r0hi7/HoneySMB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nsmfoo/dicompot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/galah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `d1str0/drupot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/honeycomb_plugins` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oguzy/ovizart` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ls1911/GenAIPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrheinen/lophiid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/weblogic_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dutchcoders/troje` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `knalli/honeypot-for-tcp-32764` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERT-Polska/HSN-Capture-HPC-NG` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fofapro/fapro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mojachieee/go-HoneyPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WebDecoy/FCaptcha` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WebDecoy/wordpress-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/honeyalarmg2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/StrutsHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `huuck/ADBHoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `desaster/kippo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mycert/ESPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fnzv/YAFH` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MalwareTech/CitrixHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GetPageSpeed/nginx-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `threatstream/shockpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/canarytokendetector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:Ramisto/onephish` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:krahul02004/RunSteward` | GITLAB | Zu alt: 46d |
| `gitlab:niclas-zone/ctr/cowrie` | GITLAB | Zu alt: 48d |
| `gitlab:freetom/SSH-anti-DoS` | GITLAB | Zu alt: 2936d |
| `gitlab:pH-7/fake-admin-cp-honeypot-v1.2` | GITLAB | Zu alt: 2954d |
| `gitlab:swe_toast/privacy-filter` | GITLAB | Zu alt: 3264d |
| `gitlab:devhops/fail2banreports` | GITLAB | Zu alt: 4521d |
| `nightcodex7/yet-another-luci-app` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `orieg/expanse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jasonwiersum/jasonwiersum.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Raghav549/Drustpoll` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hareeshkumarmarriage/wedding-admin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tousle-8-sunlamp/Minecraft-Dungeons-II-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abbeys-606drone/The-Cabin-Game-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OmarHany-sudo/OrcaSOC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-vulnerable` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ordinals-5-jinns/Breathedge-2-Survival-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gennro/TriuneAutocombat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swarm-ai-research/aeon` | GITHUB | IP-Datei 65d alt |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 29,049 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,480 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,461 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 11,228 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,867 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,640 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,740 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,947 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,952 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,231 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 2,978 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 1,878 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 897 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 567 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 571 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 459 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 269 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 53,741 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,452 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 17,217 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,332 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,770 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,798 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,043 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 213,714 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 5,175 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 2,882 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,641 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 123,904 | 0.1% | 1560 | 2026-08-01 |
| `hookzof_socks5_list` | GITHUB | 236 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,698 | 3.8% | 133 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 53,119 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,477 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,845 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,617 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 93,598 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,240 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,454 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 104,419 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,688 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 124,292 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,394 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 113,888 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 564 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 484,889 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,174 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 171,697 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 182,370 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 147,454 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 129,972 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 108,303 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 129,040 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 104,362 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 214,874 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 69,870 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 150,601 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 35,152 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 25,417 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 25,448 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 22,346 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 19,152 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 36,568 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 16,368 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,193 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 10,144 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 18,143 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 9,686 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,451 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 9,223 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 6,454 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 1,901 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 10,889 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 4,579 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,759 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 862 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,279 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 3,044 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 9,066 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 3,513 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 81,359 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,782 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,062 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 59,933 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 4,531 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,791 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 2,156 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,395 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 85,003 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 281,825 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,704 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,562 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 6,688 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,563 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 24 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 84,758 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 93,531 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,393 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 112 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 223,048 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,194 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,704 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 186,510 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 31,213 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 6,806 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 2,615 | 34.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_compromised` | GITHUB | 15,544 | 65.9% | 2 | 2026-08-01 |
| `securitylist1568_fortigate` | GITHUB | 143 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 14,764 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 14,755 | 76.5% | 3 | 2026-08-09 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,063 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,952 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 15,443 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,334 | 31.1% | 1 | 2026-07-14 |
| `fwahyui_masifa_ipblacklist` | GITHUB | 126,973 | 91.7% | 1 | 2026-08-16 |
| `idleadmin_threatfeed` | GITHUB | 55,033 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 58,276 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,760 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 133,254 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 467 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 194,079 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 133,248 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 164,968 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 33,900 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 21,363 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 15,543 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,747 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 6,484 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,627 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,655 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,580 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 5,000 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,728 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,118 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,537 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,667 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,872 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 1,038 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,093 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,368 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,396 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,394 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,330 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,289 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 962 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,147 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,039 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,026 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,489 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 716 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,468 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,889 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,235 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 14,722 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 91,823 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 93,488 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 94,036 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 92,358 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 91,340 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 90,919 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 88,590 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 24,247 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 44,771 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 316 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 12,452 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,960 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,013 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,720 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 43,612 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 20,975 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 13,561 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 5,872 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 51 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 25,336 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 130,362 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 22,851 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,741 | 5.1% | 0 | 2026-08-23 |

---
*Generiert: 2026-09-04 21:28 CEST (Europe/Berlin)*