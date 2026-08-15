# Auto Feed Discovery – Report
**Aktualisiert:** 2026-08-15 06:35 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **10533** |
| davon GitHub (Topics+Code) | **10453** |
| davon GitLab | **80** |
| davon Awesome-Lists | **2395** |
| Tools/Libraries vor Eval gefiltert | **1339** |
| davon Hard-Reject (awesome-Liste etc.) | **162** |
| EVAL-Kandidaten (nach Stratifizierung) | **326** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **326** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **325** |
| Neu angenommene Feed-Dateien | **2** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **200** |
| Abgelehnte Repositories (dieser Run) | **325** |
| davon GitLab abgelehnt | **3** |
| Feeds gesamt (aktiv) | **202** |
| IPs in seen_db bestätigt | **3411434** |
| Neue IPs eingetragen | **388582** |
| seen_db gesamt | **12,793,423** |
| HQ-Referenz-IPs (6 Quellen) | **125095** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Repo zu alt (>30d) | **177** |
| Keine IP-Datei im Repo | **117** |
| Falsche Größe (<30 / >2,000,000 IPs) | **15** |
| IP-Datei veraltet (>30d) | **14** |
| Overlap mit HQ-Feeds zu gering (<20%) | **2** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 948 | 45.7% | 0.5% | 0 | 🆕 NEU |
| `zgzyh_malicious_website_detection` | [zgzyh/Malicious-Website-Detection](https://github.com/zgzyh/Malicious-Website-Detection) | GITHUB | 22,490 | 3.1% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `jcastanedacano/cve-sentry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaisero/fireREST` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fortinetdev/terraform-provider-fortios` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Deilis/IOC-validator-deivscan` | GITHUB | Zu alt: 986d |
| `netrunn3r/pytbull-ng` | GITHUB | Zu alt: 1901d |
| `kursadaltan/kemalwaf` | GITHUB | Zu alt: 198d |
| `Zstaigah/HIDS` | GITHUB | Zu alt: 271d |
| `zoobean/heroku-buildpack-caddy` | GITHUB | Zu alt: 318d |
| `AkshPatel14/Log-Analyzer` | GITHUB | Zu alt: 45d |
| `FaustoRosado/aws-lab` | GITHUB | Zu alt: 322d |
| `Vaibhavasri2005/college-network-security-idps` | GITHUB | Zu alt: 226d |
| `Abhracodec/Tools` | GITHUB | Zu alt: 145d |
| `LangerSword/netsieve` | GITHUB | Zu alt: 111d |
| `munisp/farmer-data-collection` | GITHUB | IP-Datei 68d alt |
| `kunw4r/LLM_NIDS` | GITHUB | Zu alt: 117d |
| `johnhogan5/cybersecurity-projects` | GITHUB | Zu alt: 624d |
| `ChristianF88/flokbn` | GITHUB | IP-Datei 262d alt |
| `poudenes/skynet-blacklists` | GITHUB | Zu alt: 509d |
| `jayachandirantv-tech/smart-network-traffic-analyzer` | GITHUB | Zu alt: 41d |
| `Bensaad-Yessine/NetGuard-IDS` | GITHUB | Zu alt: 152d |
| `jakub3137/Email-Phishing-Analyser` | GITHUB | Zu alt: 164d |
| `DPUSEC/DPUSEC-URL-Checker-Browser-Extension` | GITHUB | Zu alt: 437d |
| `TMK-v/Automated-Threat-Detection-and-Log-Analysis-with-Bash-project-` | GITHUB | Zu alt: 454d |
| `shiftbloom-studio/open-hallucination-index` | GITHUB | Zu alt: 41d |
| `Bradford1040/aur-blacklist-scanner` | GITHUB | Größe: 0 IPs |
| `zmike/ecef` | GITHUB | Zu alt: 3456d |
| `ali215haider/Automate-Phishing-Detection-System` | GITHUB | Zu alt: 366d |
| `Jess71902/Lightweight-IDS` | GITHUB | Zu alt: 377d |
| `TechnicallyCoded/Discord-AntiPhishingBot-Public` | GITHUB | Zu alt: 1479d |
| `c-chocolate/bachelor_thesis` | GITHUB | Zu alt: 1545d |
| `facusora01/Pi-Hole` | GITHUB | Zu alt: 224d |
| `stevehartwell/Configs` | GITHUB | Zu alt: 380d |
| `RekitRex21/Dino_Scan` | GITHUB | Zu alt: 174d |
| `Eswar19102005/Scam-Radar` | GITHUB | Zu alt: 125d |
| `mashooquealiamur/blocked-ip-list` | GITHUB | Zu alt: 426d |
| `nextgens/Tor` | GITHUB | Zu alt: 3498d |
| `torproject/torspec` | GITHUB | Zu alt: 145d |
| `ekolis/FrEee` | GITHUB | Zu alt: 76d |
| `securityinabox/siabguide` | GITHUB | Zu alt: 4121d |
| `spurintel/spur-saas-log-enrichment` | GITHUB | Zu alt: 296d |
| `HewlettPackard/foedus_code` | GITHUB | Zu alt: 3337d |
| `ishell/Exploits-Archives` | GITHUB | Zu alt: 4512d |
| `basvandorst/where-is-satoshi` | GITHUB | Zu alt: 854d |
| `zencefilefendi/zencefil-sentinel-soc` | GITHUB | Zu alt: 198d |
| `yao8839836/KGE-LDA` | GITHUB | Zu alt: 2910d |
| `SamPlaysKeys/ip_whois_tool` | GITHUB | Zu alt: 446d |
| `PunamTupe77/security` | GITHUB | Zu alt: 621d |
| `ddagunts/dfirewall` | GITHUB | Zu alt: 303d |
| `slimseidl/NetworkSecurity` | GITHUB | Zu alt: 417d |
| `stratosphereips/Slips-tools` | GITHUB | Zu alt: 67d |
| `rajlivee/End-point-detection-and-Response-` | GITHUB | Zu alt: 48d |
| `rawdela/Week_5_Project` | GITHUB | Zu alt: 152d |
| `sashafrey/topicmod` | GITHUB | Zu alt: 4347d |
| `dimaswahyudi7/IoC-Collections` | GITHUB | Zu alt: 436d |
| `k3nundrum/redteamtips` | GITHUB | Zu alt: 1029d |
| `rawdela/Week_11_Project` | GITHUB | Zu alt: 121d |
| `praisel-ekpenyong/SOC-Automation-Scripts` | GITHUB | Zu alt: 190d |
| `khushalbhasin4488/sih_finals_2025` | GITHUB | Zu alt: 250d |
| `debojit-dev0/ElevateLabs_CS` | GITHUB | Zu alt: 237d |
| `rawdela/Week_10_Project` | GITHUB | Zu alt: 126d |
| `Blackstarproject/Repos` | GITHUB | Zu alt: 620d |
| `zpahuja/EM` | GITHUB | Zu alt: 3413d |
| `real-horizon02/PhishGuard-AI` | GITHUB | Zu alt: 158d |
| `Ununp3ntium115/AbuseBlacklist` | GITHUB | Größe: 0 IPs |
| `naveen-verma18/URL_detector` | GITHUB | Zu alt: 308d |
| `EFI-Demo/Endpoint-Forecasting-and-Interpreting` | GITHUB | Zu alt: 1095d |
| `santhosheyzz/Email-Phishing-Analysis` | GITHUB | Zu alt: 444d |
| `toronto-ai/workshops` | GITHUB | Zu alt: 3217d |
| `aalab/paa` | GITHUB | Zu alt: 4216d |
| `gtriggiano/envoy-authorization-service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sayanghosh/LDA-SCVB0` | GITHUB | Zu alt: 4339d |
| `SilverLineFramework/benchmarks` | GITHUB | Zu alt: 1040d |
| `berez23/canvas` | GITHUB | Zu alt: 1990d |
| `superkeyor/ez` | GITHUB | Zu alt: 2291d |
| `rauhul/cs498` | GITHUB | Zu alt: 3105d |
| `saiharish587/RAG-Research` | GITHUB | Größe: 0 IPs |
| `TommyP702/TanPham` | GITHUB | Zu alt: 508d |
| `twothe/SE4-MoreFunMod` | GITHUB | Zu alt: 2631d |
| `Chandan220698/Ineuron-DataScience` | GITHUB | Zu alt: 1472d |
| `yanggao1119/tfidf_cosine_cpp` | GITHUB | Zu alt: 4492d |
| `alsyundawy/Microsoft-Office-For-MacOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `THORCollective/HEARTH` | GITHUB | Größe: 0 IPs |
| `muchdogesec/obstracts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MalwareSamples/Malware-Feed` | GITHUB | Zu alt: 1947d |
| `RavinduRathnayaka/LiveThreatMap-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `The-Privacy-Commons-Institute/chrome-mal-ids` | GITHUB | Größe: 0 IPs |
| `777genius/social-monitor` | GITHUB | Größe: 0 IPs |
| `fastfire/deepdarkCTI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deeztek/Hermes-Secure-Email-Gateway` | GITHUB | IP-Datei 56d alt |
| `AynOps/AynOps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `panguard-ai/panguard-ai` | GITHUB | IP-Datei 63d alt |
| `abdullahbutt/wordfeather` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chainreactors/malice-network` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iDigitalFlame/ThunderStorm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ElJaviLuki/CobaltStrike_OpenBeacon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `The-Z-Labs/bof-launcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lolc2/lolc2.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maxDcb/C2TeamServer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spellshift/realm` | GITHUB | IP-Datei 901d alt |
| `chainreactors/malefic` | GITHUB | IP-Datei 55d alt |
| `r4ulcl/Mythic-OSEP-CheatSheet` | GITHUB | Zu alt: 59d |
| `wsummerhill/C2_RedTeam_CheatSheets` | GITHUB | Zu alt: 65d |
| `BlackSnufkin/Maverick` | GITHUB | Zu alt: 69d |
| `ZZ0R0/Proteus` | GITHUB | Zu alt: 94d |
| `maxDcb/C2Implant` | GITHUB | Zu alt: 96d |
| `sharsil/favicorn` | GITHUB | Zu alt: 101d |
| `BlackSnufkin/Cheshire` | GITHUB | Zu alt: 103d |
| `dn9uy3n/Modern-Red-Team-Infrastructure` | GITHUB | Zu alt: 104d |
| `mwakidenis/mwakidenis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `efxtv/L3MON` | GITHUB | Zu alt: 38d |
| `drcrypterdotru/warworm-stealer` | GITHUB | Zu alt: 68d |
| `Bialomazur/Brutus` | GITHUB | Zu alt: 97d |
| `bmshifat/TecSpy` | GITHUB | Zu alt: 183d |
| `0x4meliorate/toxnet` | GITHUB | Zu alt: 188d |
| `hackerxphantom/hxp_photo_eye` | GITHUB | Zu alt: 281d |
| `zarkones/OnionC2` | GITHUB | Zu alt: 289d |
| `zarkones/ControlSTUDIO` | GITHUB | Zu alt: 361d |
| `slipperysquid/SquidNet` | GITHUB | Zu alt: 366d |
| `shivaya-dav/DogeRat-Premium` | GITHUB | Zu alt: 453d |
| `zarkones/XENA` | GITHUB | Zu alt: 476d |
| `trackmastersteve/HackServ` | GITHUB | Zu alt: 485d |
| `GoutamHX/MAXXRAT` | GITHUB | Zu alt: 539d |
| `NixWasHere/NebulaC2` | GITHUB | Zu alt: 542d |
| `justcallmekoko/ESP32Marauder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marven11/Fenjing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `greenbone/openvas-scanner` | GITHUB | Größe: 0 IPs |
| `laszlodaniel/ChryslerScanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NodeSecure/scanner` | GITHUB | IP-Datei 733d alt |
| `87owo/PYAS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maurosoria/dirsearch` | GITHUB | IP-Datei 660d alt |
| `ctkqiang/LQZ` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrousavy/react-native-vision-camera` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mondoohq/installer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Samsung/LPVS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mono0926/barcode_scan2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ostorlab/oxo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `immauss/openvas` | GITHUB | Größe: 0 IPs |
| `v-byte-cpu/sx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cyanfish/naps2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AdventDevInc/kudu` | GITHUB | IP-Datei 142d alt |
| `Samsung/CredSweeper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `librats/rats-search` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fabi019/hid-barcode-scanner` | GITHUB | IP-Datei 512d alt |
| `ossappscollective/OSS-DocumentScanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cifertech/ESP32-DIV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `L-codes/MX1014` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manticore-projects/aurscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kristuff/abuseipdb-cli` | GITHUB | Zu alt: 1187d |
| `nyvorin/badwords` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cobaltdisco/Google-Chinese-Results-Blocklist` | GITHUB | Zu alt: 160d |
| `EvotecIT/PSBlackListChecker` | GITHUB | Zu alt: 182d |
| `codeesura/Anti-phishing-extension` | GITHUB | Zu alt: 193d |
| `K3V1991/Passing-SafetyNet-with-Magisk-Zygisk-and-DenyList` | GITHUB | Zu alt: 855d |
| `ThoZed/graylog-cp-watchguard` | GITHUB | Zu alt: 2560d |
| `signalmidwifeboost/sim-unlock-tool-enhancer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Spirecledeliver/network-unlock-pro-edge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bernardladenthin/BitcoinAddressFinder` | GITHUB | IP-Datei 90d alt |
| `x90skysn3k/brutespray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rtulke/AirJack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Touti-Sudo/Touti-Cracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `niyankhadka/crypto-wallet-bruteforce` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xPugal/fuzz4bounty` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vanhauser-thc/thc-hydra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dreddsa5dies/goHackTools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `infinition/Bjorn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `duyet/bruteforce-database` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MorDavid/BruteForceAI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tuhinshubhra/CMSeeK` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chkndrp/OneShot-Extended` | GITHUB | Zu alt: 32d |
| `harkerbyte/linux-monster` | GITHUB | Zu alt: 47d |
| `samsesh/SocialBox-Termux` | GITHUB | Zu alt: 57d |
| `samuelcaldas/Bruteforce-Bootloader-Unlocker` | GITHUB | Zu alt: 57d |
| `X-Stuff/CudaKeeloq` | GITHUB | Zu alt: 60d |
| `aryainjas/Microllect` | GITHUB | Zu alt: 64d |
| `Rem01Gaming/OneShot-Termux` | GITHUB | Zu alt: 65d |
| `animir/node-rate-limiter-flexible` | GITHUB | Zu alt: 68d |
| `ghluka/username-checker` | GITHUB | Zu alt: 86d |
| `jakka351/Ford-ECU-Bruteforcer` | GITHUB | Zu alt: 88d |
| `Antu7/python-bruteForce` | GITHUB | Zu alt: 98d |
| `threat9/routersploit` | GITHUB | Zu alt: 102d |
| `random-robbie/bruteforce-lists` | GITHUB | Zu alt: 107d |
| `ariary/cfuzz` | GITHUB | Zu alt: 116d |
| `marcvincenti/bitp0wn` | GITHUB | Zu alt: 131d |
| `Mr-P4p3r/wordlist-br` | GITHUB | Zu alt: 137d |
| `Cyber-Dioxide/Gmail-Brute` | GITHUB | Zu alt: 139d |
| `r3bo0tbx1/tor-guard-relay` | GITHUB | Größe: 0 IPs |
| `EntySec/Shreder` | GITHUB | Zu alt: 754d |
| `pwnesia/ssb` | GITHUB | Zu alt: 1702d |
| `InfosecMatter/SSH-PuTTY-login-bruteforcer` | GITHUB | Zu alt: 2093d |
| `abusix/xarf` | GITHUB | Zu alt: 60d |
| `Cyb3r-Monk/Threat-Hunting-and-Detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OISF/suricata` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benscha/KQLAdvancedHunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f-bader/DefenderAndSentinelQueries` | GITHUB | IP-Datei 191d alt |
| `kunai-project/kunai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `a2awais/Threat-Hunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SlimKQL/Detections.AI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kdeldycke/meta-package-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typedb/bazel-distribution` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wimpysworld/deb-get` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lbr38/repomanager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sous-chefs/apt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neur0map/glazepkg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AOSC-Dev/oma` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rami3l/pacaptr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aptly-dev/aptly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zbrateam/Zebra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `avaje/avaje-inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheDuffman85/linux-update-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `S3N4T0R-0X0/APTs-Adversary-Simulation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Oefenweb/ansible-apt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CodeXTF2/ScreenshotBOF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shaheeryasirofficial/Red-Team-Rust` | GITHUB | Zu alt: 54d |
| `chainski/AES-Encoder` | GITHUB | Zu alt: 75d |
| `memN0ps/doublepulsar-rs` | GITHUB | Zu alt: 93d |
| `RedSiege/C2concealer` | GITHUB | Zu alt: 124d |
| `memN0ps/armory-rs` | GITHUB | Zu alt: 134d |
| `hakaioffsec/coffee` | GITHUB | Zu alt: 154d |
| `CDipper/Beacon` | GITHUB | Zu alt: 190d |
| `0xsh3llf1r3/ColdWer` | GITHUB | Zu alt: 198d |
| `CodeXTF2/bof_template` | GITHUB | Zu alt: 219d |
| `wwh1004/bof-template-ng` | GITHUB | Zu alt: 254d |
| `andrecrafts/CobaltStrike-YARA-Bypass-f0b627fc` | GITHUB | Zu alt: 317d |
| `tdeerenberg/InlineWhispers3` | GITHUB | Zu alt: 402d |
| `lintstar/SharpHunter` | GITHUB | Zu alt: 487d |
| `CodeXTF2/WebcamBOF` | GITHUB | Zu alt: 507d |
| `CodeXTF2/WindowSpy` | GITHUB | Zu alt: 537d |
| `yqcs/ZheTian` | GITHUB | Zu alt: 554d |
| `fortra/No-Consolation` | GITHUB | Zu alt: 661d |
| `fortra/nanodump` | GITHUB | Zu alt: 697d |
| `001SPARTaN/aggressor_scripts` | GITHUB | Zu alt: 730d |
| `b1tg/cobaltstrike-beacon-rust` | GITHUB | Zu alt: 735d |
| `starnightcyber/Miscellaneous` | GITHUB | Zu alt: 757d |
| `naksyn/DojoLoader` | GITHUB | Zu alt: 774d |
| `Adminisme/ServerScan` | GITHUB | Zu alt: 790d |
| `wangfly-me/LoaderFly` | GITHUB | Zu alt: 850d |
| `m3rcer/Chisel-Strike` | GITHUB | Zu alt: 873d |
| `yutianqaq/CSx3Ldr` | GITHUB | Zu alt: 945d |
| `intbjw/bimg-shellcode-loader` | GITHUB | Zu alt: 1060d |
| `harleyQu1nn/AggressorScripts` | GITHUB | Zu alt: 1142d |
| `baiyies/ScreenshotBOFPlus` | GITHUB | Zu alt: 1165d |
| `CodeXTF2/Burp2Malleable` | GITHUB | Zu alt: 1227d |
| `lintstar/CS-PushPlus` | GITHUB | Zu alt: 1258d |
| `QAX-A-Team/CobaltStrike-Toolset` | GITHUB | Zu alt: 1362d |
| `xx0hcd/Malleable-C2-Profiles` | GITHUB | Zu alt: 1387d |
| `ScriptIdiot/BOF-patchit` | GITHUB | Zu alt: 1414d |
| `burpheart/CVE-2022-39197-patch` | GITHUB | Zu alt: 1419d |
| `CodeXTF2/cobaltstrike-headless` | GITHUB | Zu alt: 1437d |
| `akkuman/EvilEye` | GITHUB | Zu alt: 1439d |
| `burpheart/CS_mock` | GITHUB | Zu alt: 1461d |
| `hrtywhy/BOF-CobaltStrike` | GITHUB | Zu alt: 1538d |
| `S4ntiagoP/freeBokuLoader` | GITHUB | Zu alt: 1539d |
| `guervild/BOFs` | GITHUB | Zu alt: 1566d |
| `RedSiege/MiddleOut` | GITHUB | Zu alt: 1655d |
| `lintstar/LSTAR` | GITHUB | Zu alt: 1658d |
| `Peco602/cobaltstrike-aggressor-scripts` | GITHUB | Zu alt: 1685d |
| `airbus-cert/Invoke-Bof` | GITHUB | Zu alt: 1710d |
| `HKirito/GoogleAuth` | GITHUB | Zu alt: 1769d |
| `z1un/Z1-AggressorScripts` | GITHUB | Zu alt: 1903d |
| `Coalfire-Research/Vampire` | GITHUB | Zu alt: 1957d |
| `EncodeGroup/BOF-RegSave` | GITHUB | Zu alt: 2137d |
| `tomcarver16/BOF-DLL-Inject` | GITHUB | Zu alt: 2172d |
| `alphaSeclab/cobalt-strike` | GITHUB | Zu alt: 2267d |
| `loecho-sec/CobaltStrike_Script_Wechat_Push` | GITHUB | Zu alt: 2307d |
| `Laiteux/Milky` | GITHUB | Zu alt: 1698d |
| `trsi-me/TS-OSINT` | GITHUB | Zu alt: 780d |
| `MahanKenway/Freedom-V2Ray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Barabama/FreeNodes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `whoahaow/rjsxrd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blatteprince2/Void-Engine-GD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mheidari98/.proxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zhuhaiuk/free-nodes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Pawdroid/Free-servers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `peasoft/NoMoreWalls` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2dust/v2rayN` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mahdibland/V2RayAggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MHSanaei/3x-ui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kwisma/Sub-Store-node` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:niclas-zone/ctr/wazuh` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:lalalesha4/ZavetSec-Harden` | GITLAB | Zu alt: 52d |
| `gitlab:TariqJenkins/ansible` | GITLAB | Zu alt: 146d |
| `christiand0797/downpour` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `birdofnofeather/vince-art-showcase` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IHUI-INF-AI/IHUI-AI` | GITHUB | Größe: 0 IPs |
| `nicholasgearinger-code/nicholasgearinger.github.io-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2ndSightLab/ai-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RYRS1/runyourracesolutions-site` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Open-Source-Trader/0dteTrader` | GITHUB | Größe: 0 IPs |
| `groktopus/groktocrawl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lfd-hydrants/lfd-hydrants` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wa-ra-so/sinntenn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zachproffitt/builder-jobs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mcrombie/colony-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jorodriguezpr/sysadminhcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gopalaakkrishna/sports-model` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Xiaobei09/proxyip` | GITHUB | Overlap zu gering: 0.0% |
| `rodlunt/engineering-audit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Su-Sea/youdotcom-dbx-security-center` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qingbo93/telebot-ai-landing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eofficesubhendubarua-hue/sentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hir0chan/VRSP` | GITHUB | Größe: 0 IPs |
| `Alastor-Kaneki/animex-android` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `srmcno/pm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Team-Triada/triada-news` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OAuthSentry/oauthsentry.github.io` | GITHUB | IP-Datei 109d alt |
| `Subhamrbj/Anti-Theft-Locker-Embedded-System` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sahiljangra115/Signoz-hackathon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jiachengw-sf/phishing-detector` | GITHUB | Overlap zu gering: 0.6% |
| `blundersurfer/servermonkey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zoahdev/kinegrant-protocol` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VitaliyIvanov11/Lacupedas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `devganatra/devganatra.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ariffazil/arifFLOW` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ninja-ops-guy/techops-hero` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hades0413/iCode-back` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThyMrMan/cairn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rumahucan-cyber/aeon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `9MidhunPM/thursday-local-assistant` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TonyLegend-77/shieldguard` | GITHUB | Größe: 0 IPs |
| `Avenmoqe/MT5-Telegram-Signal-AutoTrader` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-vue` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Balty1991/BETPREDICT` | GITHUB | Größe: 0 IPs |
| `NeelSavsani/CyberShield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pubgking8874-ux/ShortCap` | GITHUB | Größe: 0 IPs |
| `Moiudev/rule-set` | GITHUB | IP-Datei 80d alt |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 25,713 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 16,423 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,819 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,639 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 550 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 7,211 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 4,418 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,754 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 2,701 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,080 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,418 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,447 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,600 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 829 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 769 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 584 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 300 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 47,108 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 21,730 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 20,552 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,260 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,728 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 5,053 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,330 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 207,752 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,537 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,316 | 2.6% | 116 | 2026-07-05 |
| `breakingtechfr_proxy_free` | GITHUB | 43,636 | 0.6% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_all` | GITHUB | 46,647 | 0.5% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks4` | GITHUB | 16,351 | 1.9% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks5` | GITHUB | 15,547 | 2.2% | 55 | 2026-07-14 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,641 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 119,564 | 0.1% | 1560 | 2026-08-01 |
| `hookzof_socks5_list` | GITHUB | 195 | 22.1% | 1030 | 2026-08-04 |
| `mohammedcha_proxripper` | GITHUB | 53,518 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,297 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,989 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,733 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 96,212 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,694 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 95,114 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 102,862 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,596 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 125,869 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,212 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 102,915 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 551 | 36.7% | 8 | 2026-07-03 |
| `darzanebor_mikroblack` | GITHUB | 41,628 | 26.6% | 13 | 2026-07-05 |
| `ankaboot_source_email_open_data` | GITHUB | 487,165 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,904 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 171,190 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 174,092 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 141,322 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 110,979 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 98,010 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 126,783 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 97,337 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 198,107 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 53,841 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 111,106 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 30,046 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 22,874 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,008 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 18,673 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 15,239 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 33,365 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,466 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,886 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 5,131 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 14,840 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 8,483 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 3,950 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 7,791 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 5,890 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 3,277 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,591 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 5,440 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,742 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 480 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 2,877 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,569 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,713 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 5,539 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 48,718 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 3,373 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 3,117 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 51,470 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 4,391 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,865 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 2,110 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 865 | 17.2% | 9 | 2026-07-08 |
| `sereinfy_adrules` | GITHUB | 1,318 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 83,156 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 316,895 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 5,584 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 4,691 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 5,502 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,579 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 21 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 71,755 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 77,806 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,157 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 107 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 207,800 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,266 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,680 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 188,478 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 29,753 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 7,268 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 3,249 | 34.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_compromised` | GITHUB | 15,527 | 65.9% | 2 | 2026-08-01 |
| `securitylist1568_fortigate` | GITHUB | 220 | 28.1% | 2 | 2026-08-02 |
| `cyberh4ck3r_free_proxy_list` | GITHUB | 3,546 | 1.7% | 2 | 2026-08-12 |
| `cyberh4ck3r_free_proxy_list_socks4_proxies` | GITHUB | 2,868 | 2.6% | 2 | 2026-08-12 |
| `cyberh4ck3r_free_proxy_list_socks5_proxies` | GITHUB | 2,410 | 3.3% | 2 | 2026-08-12 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 10,550 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 10,539 | 76.5% | 3 | 2026-08-09 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,056 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 16,042 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 15,943 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,302 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 54,371 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 54,151 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,415 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 125,557 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 511 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,170 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 193,258 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,527 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 129,253 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 132,738 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 33,953 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 22,581 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 17,356 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,774 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 6,757 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,198 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,674 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,635 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 3,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,536 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,122 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,529 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,056 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,766 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 3,785 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,983 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,722 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,334 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,100 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,048 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,050 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 941 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 889 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,875 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 797 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,460 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 723 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,279 | 6.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_maltrail_scanners` | GITHUB | 16,854 | 14.9% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_iblocklist_cruzit_web_attacks` | GITHUB | 13,871 | 0.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 5,631 | 5.0% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,127 | 24.2% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,427 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,554 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,202 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 12,305 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 93,276 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 91,059 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 91,300 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 90,811 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 91,044 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 87,095 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 87,451 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,345 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 40,596 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 146 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets` | GITHUB | 110,278 | 9.4% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 20,928 | 65.2% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 12,826 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 4,172 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,753 | 5.0% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,898 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,660 | 5.8% | 0 | 2026-08-11 |
| `saidurrahman22_linux_av_edr` | GITHUB | 100 | 62.0% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 39,803 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 16,951 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 12,875 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 3,138 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 69 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 948 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 22,490 | 3.1% | 0 | 2026-08-15 |

---
*Generiert: 2026-08-15 06:35 CEST (Europe/Berlin)*