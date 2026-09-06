# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-06 09:18 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 17 |
| Kandidaten gesamt | **11461** |
| davon GitHub (Topics+Code) | **11378** |
| davon GitLab | **83** |
| davon Awesome-Lists | **2402** |
| Tools/Libraries vor Eval gefiltert | **1550** |
| davon Hard-Reject (awesome-Liste etc.) | **173** |
| EVAL-Kandidaten (nach Stratifizierung) | **287** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **287** |
| davon angenommene Repositories | **0** |
| davon abgelehnte Repositories | **287** |
| Neu angenommene Feed-Dateien | **1** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **190** |
| Abgelehnte Repositories (dieser Run) | **287** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **191** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **161154** |
| SQLite-Refresh-Cache-Hits | **30/190** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Repo zu alt (>30d) | **152** |
| Keine IP-Datei im Repo | **113** |
| IP-Datei veraltet (>30d) | **13** |
| Falsche Größe (<30 / >2,000,000 IPs) | **8** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,345 | 64.6% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `Deilis/IOC-validator-deivscan` | GITHUB | Zu alt: 1008d |
| `netrunn3r/pytbull-ng` | GITHUB | Zu alt: 1923d |
| `kursadaltan/kemalwaf` | GITHUB | Zu alt: 220d |
| `Zstaigah/HIDS` | GITHUB | Zu alt: 293d |
| `zoobean/heroku-buildpack-caddy` | GITHUB | IP-Datei 404d alt |
| `AkshPatel14/Log-Analyzer` | GITHUB | Zu alt: 67d |
| `FaustoRosado/aws-lab` | GITHUB | Zu alt: 344d |
| `Vaibhavasri2005/college-network-security-idps` | GITHUB | Zu alt: 248d |
| `Abhracodec/Tools` | GITHUB | Zu alt: 167d |
| `LangerSword/netsieve` | GITHUB | Zu alt: 133d |
| `munisp/farmer-data-collection` | GITHUB | Zu alt: 34d |
| `kunw4r/LLM_NIDS` | GITHUB | Zu alt: 139d |
| `johnhogan5/cybersecurity-projects` | GITHUB | Zu alt: 646d |
| `ChristianF88/flokbn` | GITHUB | IP-Datei 284d alt |
| `poudenes/skynet-blacklists` | GITHUB | Zu alt: 531d |
| `jayachandirantv-tech/smart-network-traffic-analyzer` | GITHUB | Zu alt: 63d |
| `Bensaad-Yessine/NetGuard-IDS` | GITHUB | Zu alt: 174d |
| `jakub3137/Email-Phishing-Analyser` | GITHUB | Zu alt: 186d |
| `DPUSEC/DPUSEC-URL-Checker-Browser-Extension` | GITHUB | Zu alt: 459d |
| `TMK-v/Automated-Threat-Detection-and-Log-Analysis-with-Bash-project-` | GITHUB | Zu alt: 476d |
| `shiftbloom-studio/open-hallucination-index` | GITHUB | IP-Datei 233d alt |
| `Bradford1040/aur-blacklist-scanner` | GITHUB | Zu alt: 34d |
| `zmike/ecef` | GITHUB | Zu alt: 3478d |
| `ali215haider/Automate-Phishing-Detection-System` | GITHUB | Zu alt: 388d |
| `Jess71902/Lightweight-IDS` | GITHUB | Zu alt: 399d |
| `TechnicallyCoded/Discord-AntiPhishingBot-Public` | GITHUB | Zu alt: 1501d |
| `c-chocolate/bachelor_thesis` | GITHUB | Zu alt: 1567d |
| `facusora01/Pi-Hole` | GITHUB | Zu alt: 246d |
| `stevehartwell/Configs` | GITHUB | Zu alt: 402d |
| `RekitRex21/Dino_Scan` | GITHUB | Zu alt: 196d |
| `Eswar19102005/Scam-Radar` | GITHUB | Zu alt: 147d |
| `mashooquealiamur/blocked-ip-list` | GITHUB | Zu alt: 448d |
| `nextgens/Tor` | GITHUB | Zu alt: 3520d |
| `torproject/torspec` | GITHUB | Zu alt: 167d |
| `ekolis/FrEee` | GITHUB | Zu alt: 98d |
| `securityinabox/siabguide` | GITHUB | Zu alt: 4143d |
| `spurintel/spur-saas-log-enrichment` | GITHUB | Zu alt: 318d |
| `HewlettPackard/foedus_code` | GITHUB | Zu alt: 3359d |
| `ishell/Exploits-Archives` | GITHUB | Zu alt: 4534d |
| `basvandorst/where-is-satoshi` | GITHUB | Zu alt: 876d |
| `zencefilefendi/zencefil-sentinel-soc` | GITHUB | Zu alt: 220d |
| `yao8839836/KGE-LDA` | GITHUB | Zu alt: 2932d |
| `SamPlaysKeys/ip_whois_tool` | GITHUB | Zu alt: 468d |
| `PunamTupe77/security` | GITHUB | Zu alt: 643d |
| `ddagunts/dfirewall` | GITHUB | Zu alt: 325d |
| `slimseidl/NetworkSecurity` | GITHUB | Zu alt: 439d |
| `stratosphereips/Slips-tools` | GITHUB | Zu alt: 89d |
| `rajlivee/End-point-detection-and-Response-` | GITHUB | Zu alt: 70d |
| `rawdela/Week_5_Project` | GITHUB | Zu alt: 174d |
| `sashafrey/topicmod` | GITHUB | Zu alt: 4369d |
| `dimaswahyudi7/IoC-Collections` | GITHUB | Zu alt: 458d |
| `k3nundrum/redteamtips` | GITHUB | Zu alt: 1051d |
| `rawdela/Week_11_Project` | GITHUB | Zu alt: 143d |
| `praisel-ekpenyong/SOC-Automation-Scripts` | GITHUB | Zu alt: 212d |
| `khushalbhasin4488/sih_finals_2025` | GITHUB | Zu alt: 272d |
| `debojit-dev0/ElevateLabs_CS` | GITHUB | Zu alt: 259d |
| `rawdela/Week_10_Project` | GITHUB | Zu alt: 148d |
| `Blackstarproject/Repos` | GITHUB | Zu alt: 642d |
| `zpahuja/EM` | GITHUB | Zu alt: 3435d |
| `real-horizon02/PhishGuard-AI` | GITHUB | Zu alt: 180d |
| `Ununp3ntium115/AbuseBlacklist` | GITHUB | Zu alt: 51d |
| `naveen-verma18/URL_detector` | GITHUB | Zu alt: 330d |
| `gfazzz/kernel-shadows` | GITHUB | IP-Datei 37d alt |
| `EFI-Demo/Endpoint-Forecasting-and-Interpreting` | GITHUB | Zu alt: 1117d |
| `santhosheyzz/Email-Phishing-Analysis` | GITHUB | Zu alt: 466d |
| `toronto-ai/workshops` | GITHUB | Zu alt: 3239d |
| `aalab/paa` | GITHUB | Zu alt: 4238d |
| `gtriggiano/envoy-authorization-service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sayanghosh/LDA-SCVB0` | GITHUB | Zu alt: 4361d |
| `SilverLineFramework/benchmarks` | GITHUB | Zu alt: 1062d |
| `berez23/canvas` | GITHUB | Zu alt: 2012d |
| `superkeyor/ez` | GITHUB | Zu alt: 2313d |
| `rauhul/cs498` | GITHUB | Zu alt: 3127d |
| `saiharish587/RAG-Research` | GITHUB | Größe: 0 IPs |
| `TommyP702/TanPham` | GITHUB | Zu alt: 530d |
| `twothe/SE4-MoreFunMod` | GITHUB | Zu alt: 2653d |
| `Chandan220698/Ineuron-DataScience` | GITHUB | Zu alt: 1494d |
| `yanggao1119/tfidf_cosine_cpp` | GITHUB | Zu alt: 4514d |
| `bobrunner7/Lyndvhar` | GITHUB | Zu alt: 378d |
| `sivapvarma/cse291d-project-topicmodels` | GITHUB | Zu alt: 3728d |
| `Leon406/proxypool` | GITHUB | Zu alt: 1814d |
| `mitchellkrogza/apache-ultimate-bad-bot-blocker` | GITHUB | Overlap zu gering: 0.0% |
| `mitchellkrogza/fail2ban-useful-scripts` | GITHUB | Zu alt: 3000d |
| `mitchellkrogza/linux-server-administration-scripts` | GITHUB | Zu alt: 3442d |
| `GUI-for-Cores/GUI.for.SingBox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beck-8/subs-check` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `asdlokj1qpi233/subconverter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bestnite/sub2clash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bulianglin/demo` | GITHUB | Zu alt: 110d |
| `derhuerst/email-providers` | GITHUB | Zu alt: 320d |
| `tindy2013/stairspeedtest-reborn` | GITHUB | Zu alt: 1186d |
| `firehol/iprange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mohammedcha/gplay-scraper` | GITHUB | Zu alt: 294d |
| `Mohammedcha/UnityReskinGuard` | GITHUB | Zu alt: 1135d |
| `Mohammedcha/ReskinGuard` | GITHUB | Zu alt: 1136d |
| `Mohammedcha/Play-Apps-Sortering` | GITHUB | Zu alt: 2768d |
| `Mohammedcha/Keywords-Highlighter` | GITHUB | Zu alt: 2768d |
| `THORCollective/HEARTH` | GITHUB | IP-Datei 42d alt |
| `muchdogesec/obstracts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MalwareSamples/Malware-Feed` | GITHUB | Zu alt: 1969d |
| `AynOps/AynOps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RavinduRathnayaka/LiveThreatMap-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christinminor459/OnionClaw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `777genius/social-monitor` | GITHUB | IP-Datei 36d alt |
| `kaifcodec/user-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f6-dfir/Ransomware` | GITHUB | Größe: 2 IPs |
| `gl0bal01/malware-analysis-claude-skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `reloading01/certstream-server-rust` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fastfire/deepdarkCTI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `darama22/Malware-Research-Hub` | GITHUB | Größe: 0 IPs |
| `devops-ia/helm-opencti` | GITHUB | IP-Datei 363d alt |
| `Team-intN18-SoybeanSeclab/prtstrike` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chainreactors/malice-network` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abdullahbutt/wordfeather` | GITHUB | Größe: 0 IPs |
| `maxDcb/C2TeamServer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `The-Z-Labs/bof-launcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SquidSec/SquidC5` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dn9uy3n/Modern-Red-Team-Infrastructure` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spellshift/realm` | GITHUB | IP-Datei 923d alt |
| `chainreactors/malefic` | GITHUB | Zu alt: 31d |
| `iDigitalFlame/ThunderStorm` | GITHUB | Zu alt: 37d |
| `ElJaviLuki/CobaltStrike_OpenBeacon` | GITHUB | Zu alt: 40d |
| `lolc2/lolc2.github.io` | GITHUB | Zu alt: 46d |
| `Jieyab89/Loader-and-shell-code-AV-Evasion` | GITHUB | Zu alt: 64d |
| `r4ulcl/Mythic-OSEP-CheatSheet` | GITHUB | Zu alt: 81d |
| `wsummerhill/C2_RedTeam_CheatSheets` | GITHUB | Zu alt: 87d |
| `BlackSnufkin/Maverick` | GITHUB | Zu alt: 91d |
| `ZZ0R0/Proteus` | GITHUB | Zu alt: 116d |
| `mwakidenis/mwakidenis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `infinition/Zombieland` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `efxtv/L3MON` | GITHUB | Zu alt: 60d |
| `Bialomazur/Brutus` | GITHUB | Zu alt: 119d |
| `bmshifat/TecSpy` | GITHUB | Zu alt: 205d |
| `0x4meliorate/toxnet` | GITHUB | Zu alt: 210d |
| `hackerxphantom/hxp_photo_eye` | GITHUB | Zu alt: 303d |
| `zarkones/OnionC2` | GITHUB | Zu alt: 311d |
| `zarkones/ControlSTUDIO` | GITHUB | Zu alt: 383d |
| `slipperysquid/SquidNet` | GITHUB | Zu alt: 388d |
| `shivaya-dav/DogeRat-Premium` | GITHUB | Zu alt: 475d |
| `zarkones/XENA` | GITHUB | Zu alt: 498d |
| `trackmastersteve/HackServ` | GITHUB | Zu alt: 507d |
| `GoutamHX/MAXXRAT` | GITHUB | Zu alt: 561d |
| `NixWasHere/NebulaC2` | GITHUB | Zu alt: 564d |
| `TomVN107080/packet-warden` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maurosoria/dirsearch` | GITHUB | IP-Datei 682d alt |
| `justcallmekoko/ESP32Marauder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ZupIT/horusec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Samsung/CredSweeper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AdventDevInc/kudu` | GITHUB | Größe: 0 IPs |
| `Fabi019/hid-barcode-scanner` | GITHUB | IP-Datei 534d alt |
| `neural75/gqrx-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `87owo/PYAS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ostorlab/oxo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manuc66/node-hp-scan-to` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Shiperoid/YT-DPI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `5rahim/seanime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `defended-net/malwatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Udayraj123/OMRChecker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marven11/Fenjing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mpaymenremora/QuantumSeal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Samsung/LPVS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kristuff/abuseipdb-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nyvorin/badwords` | GITHUB | Zu alt: 39d |
| `cobaltdisco/Google-Chinese-Results-Blocklist` | GITHUB | Zu alt: 182d |
| `EvotecIT/PSBlackListChecker` | GITHUB | Zu alt: 204d |
| `K3V1991/Passing-SafetyNet-with-Magisk-Zygisk-and-DenyList` | GITHUB | Zu alt: 877d |
| `fortinetdev/terraform-provider-fortios` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThoZed/graylog-cp-watchguard` | GITHUB | Zu alt: 2582d |
| `kaisero/fireREST` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xPugal/fuzz4bounty` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mferland/libzc` | GITHUB | Größe: 0 IPs |
| `bernardladenthin/BitcoinAddressFinder` | GITHUB | Größe: 0 IPs |
| `qtc-de/remote-method-guesser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x90skysn3k/brutespray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `napolux/paroleitaliane` | GITHUB | IP-Datei 493d alt |
| `samuelcaldas/Bruteforce-Bootloader-Unlocker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rtulke/AirJack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Touti-Sudo/Touti-Cracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `niyankhadka/crypto-wallet-bruteforce` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vanhauser-thc/thc-hydra` | GITHUB | Zu alt: 38d |
| `dreddsa5dies/goHackTools` | GITHUB | Zu alt: 46d |
| `infinition/Bjorn` | GITHUB | Zu alt: 48d |
| `duyet/bruteforce-database` | GITHUB | Zu alt: 48d |
| `MorDavid/BruteForceAI` | GITHUB | Zu alt: 51d |
| `Tuhinshubhra/CMSeeK` | GITHUB | Zu alt: 51d |
| `chkndrp/OneShot-Extended` | GITHUB | Zu alt: 54d |
| `harkerbyte/linux-monster` | GITHUB | Zu alt: 69d |
| `samsesh/SocialBox-Termux` | GITHUB | Zu alt: 79d |
| `X-Stuff/CudaKeeloq` | GITHUB | Zu alt: 82d |
| `aryainjas/Microllect` | GITHUB | Zu alt: 86d |
| `Rem01Gaming/OneShot-Termux` | GITHUB | Zu alt: 87d |
| `animir/node-rate-limiter-flexible` | GITHUB | Zu alt: 90d |
| `ghluka/username-checker` | GITHUB | Zu alt: 108d |
| `jakka351/Ford-ECU-Bruteforcer` | GITHUB | Zu alt: 110d |
| `Antu7/python-bruteForce` | GITHUB | Zu alt: 120d |
| `threat9/routersploit` | GITHUB | Zu alt: 124d |
| `random-robbie/bruteforce-lists` | GITHUB | Zu alt: 129d |
| `ariary/cfuzz` | GITHUB | Zu alt: 138d |
| `marcvincenti/bitp0wn` | GITHUB | Zu alt: 153d |
| `Mr-P4p3r/wordlist-br` | GITHUB | Zu alt: 159d |
| `Cyber-Dioxide/Gmail-Brute` | GITHUB | Zu alt: 161d |
| `r3bo0tbx1/tor-guard-relay` | GITHUB | IP-Datei 52d alt |
| `EntySec/Shreder` | GITHUB | Zu alt: 776d |
| `pwnesia/ssb` | GITHUB | Zu alt: 1724d |
| `InfosecMatter/SSH-PuTTY-login-bruteforcer` | GITHUB | Zu alt: 2115d |
| `abusix/xarf` | GITHUB | Zu alt: 82d |
| `dgunter/ParseZeekLogs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dgunter/evtxtoelk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SlimKQL/Detections.AI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `calebevans/mulder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OISF/suricata` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yamato-Security/hayabusa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dandye/adk_runbooks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `The-Privacy-Commons-Institute/chrome-mal-ids` | GITHUB | Größe: 0 IPs |
| `f-bader/DefenderAndSentinelQueries` | GITHUB | IP-Datei 213d alt |
| `SecurityClaw/SecurityClaw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rami3l/pacaptr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kdeldycke/meta-package-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wimpysworld/deb-get` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `avaje/avaje-inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AOSC-Dev/oma` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheDuffman85/linux-update-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aptly-dev/aptly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typedb/bazel-distribution` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mexirica/aptui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lbr38/repomanager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neur0map/glazepkg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Oefenweb/ansible-apt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CodeXTF2/ScreenshotBOF` | GITHUB | Zu alt: 40d |
| `shaheeryasirofficial/Red-Team-Rust` | GITHUB | Zu alt: 76d |
| `chainski/AES-Encoder` | GITHUB | Zu alt: 97d |
| `memN0ps/doublepulsar-rs` | GITHUB | Zu alt: 115d |
| `RedSiege/C2concealer` | GITHUB | Zu alt: 146d |
| `memN0ps/armory-rs` | GITHUB | Zu alt: 156d |
| `hakaioffsec/coffee` | GITHUB | Zu alt: 176d |
| `CDipper/Beacon` | GITHUB | Zu alt: 212d |
| `0xsh3llf1r3/ColdWer` | GITHUB | Zu alt: 220d |
| `CodeXTF2/bof_template` | GITHUB | Zu alt: 241d |
| `wwh1004/bof-template-ng` | GITHUB | Zu alt: 276d |
| `andrecrafts/CobaltStrike-YARA-Bypass-f0b627fc` | GITHUB | Zu alt: 339d |
| `tdeerenberg/InlineWhispers3` | GITHUB | Zu alt: 424d |
| `andrewmichaelsmith/flux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JusticeRage/Manalyze` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shadawck/glit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/psn_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FlowingMedia/TimeFlow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaifcodec/user-scanner.git` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cga-harvard/Data_Science_Big_Data_Projects` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ANG13T/SatIntel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s0md3v/Orbit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sundowndev/PhoneInfoga` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s0md3v/Zen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sqren/fb-sleep-stats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aydinnyunus/exiflooter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NovaCode37/Prism-platform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3nock/SpiderSuite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drego85/tosint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spmedia/Crypto-Scam-and-Crypto-Phishing-Threat-Intel-Feed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eth0izzle/the-endorser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hamodywe/telegram-scraper-TeleGraphite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tsale/TeleTracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `milo2012/osintstalker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `narkopolo/fb_friend_list_scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spmedia/Telegram-Channel-Joiner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XD-MHLOO/Osintgraph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bibanon/tubeup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loseys/Oblivion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `proseltd/Telepathy-Community` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jsvine/waybackpack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cybersader/WebsiteTechMiner-py` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Turner-Levey/section-16-deadline-calculator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3nock/sub3suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tejado/telegram-nearby-map` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bevigil/BeVigil-OSINT-CLI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/Wayback-Archive` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `finos/perspective` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/spotify_profile_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `snooppr/shotstars` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/lol_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amnottdevv/atdork` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alaa-abdulridha/SerpScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/spotify_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `matiash26/steam-osint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khashashin/ogi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomnomnom/waybackurls` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vflame6/leaker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Datalux/Osintgram` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 29,049 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,480 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,461 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 11,228 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,835 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,640 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,765 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,747 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,952 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,238 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 2,835 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 1,909 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 995 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 655 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 715 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 597 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 367 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 53,777 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,491 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 17,267 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 8,849 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,310 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,676 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 2,878 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 213,758 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,154 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,643 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,634 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 124,129 | 0.1% | 1560 | 2026-08-01 |
| `hookzof_socks5_list` | GITHUB | 239 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,698 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 5,358 | 64.3% | 938 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 52,828 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,343 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,276 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 116,076 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 93,639 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,552 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,518 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 104,571 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,717 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 125,192 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,394 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 112,724 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 564 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 483,484 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,175 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 171,805 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 181,256 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 147,194 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 129,958 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 104,574 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 128,090 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 101,351 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 215,842 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 58,998 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 152,689 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 34,369 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 24,613 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 25,252 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 21,332 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 19,370 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 36,897 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,375 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,611 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 5,885 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 18,350 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 9,741 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,631 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 9,301 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 6,503 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 1,872 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 11,048 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 4,584 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,787 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 1,363 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,487 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,615 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 9,039 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 3,412 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 82,842 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,785 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,116 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 56,834 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 4,291 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,815 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 2,075 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,241 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 84,893 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 289,938 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,456 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,224 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 6,392 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,542 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 10 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 85,479 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 95,541 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,414 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 107 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 225,591 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,172 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,704 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 186,510 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 31,213 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 6,806 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 2,615 | 34.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_compromised` | GITHUB | 15,544 | 65.9% | 2 | 2026-08-01 |
| `securitylist1568_fortigate` | GITHUB | 186 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 14,764 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 14,878 | 76.5% | 3 | 2026-08-09 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,063 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,923 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 16,467 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,334 | 31.1% | 1 | 2026-07-14 |
| `fwahyui_masifa_ipblacklist` | GITHUB | 126,973 | 91.7% | 1 | 2026-08-16 |
| `idleadmin_threatfeed` | GITHUB | 54,488 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 58,663 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,769 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 134,303 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 421 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 194,291 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,531 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 134,297 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 164,343 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,237 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 34,606 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 20,422 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 16,627 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,734 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 7,234 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 10,099 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,644 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,516 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 5,250 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,953 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,116 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,528 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 3,210 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,903 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 1,617 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,074 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,352 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,338 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,396 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,336 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,277 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 965 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,122 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,256 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,019 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,496 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 655 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,950 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,888 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,470 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 13,627 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 91,589 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 93,588 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 93,552 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 92,346 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 91,362 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 90,416 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 88,624 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,156 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 45,572 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 12,211 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,952 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,065 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,500 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,780 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 43,629 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 21,300 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 13,455 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 5,911 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 51 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 25,474 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 129,795 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 21,615 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,783 | 5.1% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 5,952 | 7.6% | 0 | 2026-09-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,345 | 64.6% | 0 | 2026-09-06 |

---
*Generiert: 2026-09-06 09:18 CEST (Europe/Berlin)*