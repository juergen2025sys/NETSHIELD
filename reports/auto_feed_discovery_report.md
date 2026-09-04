# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-04 22:41 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 16 |
| Kandidaten gesamt | **10399** |
| davon GitHub (Topics+Code) | **10316** |
| davon GitLab | **83** |
| davon Awesome-Lists | **2400** |
| Tools/Libraries vor Eval gefiltert | **1366** |
| davon Hard-Reject (awesome-Liste etc.) | **150** |
| EVAL-Kandidaten (nach Stratifizierung) | **461** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **461** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **459** |
| Neu angenommene Feed-Dateien | **3** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **188** |
| Abgelehnte Repositories (dieser Run) | **459** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **191** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **160430** |
| SQLite-Refresh-Cache-Hits | **188/188** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **328** |
| Repo zu alt (>30d) | **87** |
| IP-Datei veraltet (>30d) | **22** |
| Falsche Größe (<30 / >2,000,000 IPs) | **20** |
| Overlap mit HQ-Feeds zu gering (<20%) | **2** |
| Sonstige | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `hezhidong_scanguard_blocklist` | [hezhidong/scanguard](https://github.com/hezhidong/scanguard) | GITHUB | 317 | 87.7% | 0.0% | 0 | 🆕 NEU |
| `bert_janp_open_source_threat_intel_feeds` | [Bert-JanP/Open-Source-Threat-Intel-Feeds](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds) | GITHUB | 11,097 | 64.3% | 0.0% | 938 | 🆕 NEU |
| `infosec_tr_usom_ioc_sync` | [InfoSEC-TR/usom-ioc-sync](https://github.com/InfoSEC-TR/usom-ioc-sync) | GITHUB | 5,952 | 7.6% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `Leon406/proxypool` | GITHUB | Zu alt: 1812d |
| `mitchellkrogza/apache-ultimate-bad-bot-blocker` | GITHUB | Overlap zu gering: 0.0% |
| `mitchellkrogza/fail2ban-useful-scripts` | GITHUB | Zu alt: 2998d |
| `mitchellkrogza/linux-server-administration-scripts` | GITHUB | Zu alt: 3440d |
| `GUI-for-Cores/GUI.for.SingBox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beck-8/subs-check` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `asdlokj1qpi233/subconverter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bestnite/sub2clash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bulianglin/demo` | GITHUB | Zu alt: 108d |
| `derhuerst/email-providers` | GITHUB | Zu alt: 318d |
| `tindy2013/stairspeedtest-reborn` | GITHUB | Zu alt: 1184d |
| `firehol/iprange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mohammedcha/gplay-scraper` | GITHUB | Zu alt: 292d |
| `Mohammedcha/UnityReskinGuard` | GITHUB | Zu alt: 1133d |
| `Mohammedcha/ReskinGuard` | GITHUB | Zu alt: 1134d |
| `Mohammedcha/Play-Apps-Sortering` | GITHUB | Zu alt: 2766d |
| `Mohammedcha/Keywords-Highlighter` | GITHUB | Zu alt: 2766d |
| `THORCollective/HEARTH` | GITHUB | IP-Datei 40d alt |
| `muchdogesec/obstracts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MalwareSamples/Malware-Feed` | GITHUB | Zu alt: 1967d |
| `RavinduRathnayaka/LiveThreatMap-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `777genius/social-monitor` | GITHUB | IP-Datei 34d alt |
| `abdullahbutt/wordfeather` | GITHUB | Größe: 0 IPs |
| `maxDcb/C2TeamServer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chainreactors/malice-network` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Team-intN18-SoybeanSeclab/prtstrike` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `The-Z-Labs/bof-launcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SquidSec/SquidC5` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dn9uy3n/Modern-Red-Team-Infrastructure` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spellshift/realm` | GITHUB | IP-Datei 921d alt |
| `chainreactors/malefic` | GITHUB | IP-Datei 75d alt |
| `iDigitalFlame/ThunderStorm` | GITHUB | Zu alt: 35d |
| `ElJaviLuki/CobaltStrike_OpenBeacon` | GITHUB | Zu alt: 38d |
| `lolc2/lolc2.github.io` | GITHUB | Zu alt: 44d |
| `Jieyab89/Loader-and-shell-code-AV-Evasion` | GITHUB | Zu alt: 62d |
| `r4ulcl/Mythic-OSEP-CheatSheet` | GITHUB | Zu alt: 79d |
| `wsummerhill/C2_RedTeam_CheatSheets` | GITHUB | Zu alt: 85d |
| `BlackSnufkin/Maverick` | GITHUB | Zu alt: 89d |
| `ZZ0R0/Proteus` | GITHUB | Zu alt: 114d |
| `maxDcb/C2Implant` | GITHUB | Zu alt: 116d |
| `mwakidenis/mwakidenis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
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
| `Shiperoid/YT-DPI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
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
| `justcallmekoko/ESP32Marauder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AdventDevInc/kudu` | GITHUB | IP-Datei 162d alt |
| `ZupIT/horusec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ostorlab/oxo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khoren93/flutter_zxing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `librats/rats-search` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `doo/scanbot-sdk-example-android` | GITHUB | IP-Datei 547d alt |
| `Samsung/CredSweeper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stapelberg/scan2drive` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hounddogai/hounddog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kristuff/abuseipdb-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nyvorin/badwords` | GITHUB | Zu alt: 37d |
| `cobaltdisco/Google-Chinese-Results-Blocklist` | GITHUB | Zu alt: 180d |
| `EvotecIT/PSBlackListChecker` | GITHUB | Zu alt: 202d |
| `K3V1991/Passing-SafetyNet-with-Magisk-Zygisk-and-DenyList` | GITHUB | Zu alt: 875d |
| `fortinetdev/terraform-provider-fortios` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThoZed/graylog-cp-watchguard` | GITHUB | Zu alt: 2580d |
| `kaisero/fireREST` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mferland/libzc` | GITHUB | Größe: 0 IPs |
| `bernardladenthin/BitcoinAddressFinder` | GITHUB | Größe: 0 IPs |
| `qtc-de/remote-method-guesser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
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
| `pwnesia/ssb` | GITHUB | Zu alt: 1722d |
| `InfosecMatter/SSH-PuTTY-login-bruteforcer` | GITHUB | Zu alt: 2113d |
| `abusix/xarf` | GITHUB | Zu alt: 80d |
| `The-Privacy-Commons-Institute/chrome-mal-ids` | GITHUB | Größe: 0 IPs |
| `f-bader/DefenderAndSentinelQueries` | GITHUB | IP-Datei 211d alt |
| `OISF/suricata` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityClaw/SecurityClaw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `calebevans/mulder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `avaje/avaje-inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kdeldycke/meta-package-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wimpysworld/deb-get` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AOSC-Dev/oma` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aptly-dev/aptly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rami3l/pacaptr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typedb/bazel-distribution` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mexirica/aptui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lbr38/repomanager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheDuffman85/linux-update-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neur0map/glazepkg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Oefenweb/ansible-apt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CodeXTF2/ScreenshotBOF` | GITHUB | Zu alt: 38d |
| `shaheeryasirofficial/Red-Team-Rust` | GITHUB | Zu alt: 74d |
| `chainski/AES-Encoder` | GITHUB | Zu alt: 95d |
| `FunnyWolf/Viper` | GITHUB | Zu alt: 96d |
| `memN0ps/doublepulsar-rs` | GITHUB | Zu alt: 113d |
| `memN0ps/armory-rs` | GITHUB | Zu alt: 154d |
| `hakaioffsec/coffee` | GITHUB | Zu alt: 174d |
| `CDipper/Beacon` | GITHUB | Zu alt: 210d |
| `0xsh3llf1r3/ColdWer` | GITHUB | Zu alt: 218d |
| `CodeXTF2/bof_template` | GITHUB | Zu alt: 239d |
| `wwh1004/bof-template-ng` | GITHUB | Zu alt: 274d |
| `andrecrafts/CobaltStrike-YARA-Bypass-f0b627fc` | GITHUB | Zu alt: 337d |
| `tdeerenberg/InlineWhispers3` | GITHUB | Zu alt: 422d |
| `lintstar/SharpHunter` | GITHUB | Zu alt: 507d |
| `CodeXTF2/WebcamBOF` | GITHUB | Zu alt: 527d |
| `CodeXTF2/WindowSpy` | GITHUB | Zu alt: 557d |
| `yqcs/ZheTian` | GITHUB | Zu alt: 574d |
| `fortra/No-Consolation` | GITHUB | Zu alt: 681d |
| `fortra/nanodump` | GITHUB | Zu alt: 717d |
| `001SPARTaN/aggressor_scripts` | GITHUB | Zu alt: 750d |
| `b1tg/cobaltstrike-beacon-rust` | GITHUB | Zu alt: 755d |
| `starnightcyber/Miscellaneous` | GITHUB | Zu alt: 777d |
| `naksyn/DojoLoader` | GITHUB | Zu alt: 794d |
| `Adminisme/ServerScan` | GITHUB | Zu alt: 810d |
| `schmalle/medpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/modpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OWASP/Python-Honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joda32/owa-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IllusiveNetworks-Labs/WebTrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/honeyku` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/tanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CHH/stack-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/honeybits` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `naorlivne/dshp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cypwnpwnsocute/RedisHoneyPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `darkarnium/kako` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sjinks/ssh-honeypotd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/conpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sjinks/mysql-honeypotd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jekil/UDPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/honeydet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christophe77/express-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yvesago/imap-honey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UHH-ISS/honeygrove` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qeeqbox/honeypots` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ashmckenzie/go-sshoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/glutton` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmersonElectricCo/boomerang` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pidydx/PyIOCe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vivisect/vivisect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hugsy/gef` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mateuszk87/PcapViz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/AnalyzePE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/flare-vm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BromiumLabs/PackerAttacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vstinner/hachoir3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `extremecoders-re/pyinstxtractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre/multiscanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbremer/sflock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hurricanelabs/machinae` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `williballenthin/python-evt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hugsy/codebro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HynekPetrak/javascript-malware-collection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rjhansen/nsrllookup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uppusaikiran/yara-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RamadhanAmizudin/python-icap-yara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `quark-engine/quark-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Defense-Cyber-Crime-Center/DC3-MWCP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jnraber/VirtualDeobfuscator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/yarGen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NtQuery/Scylla` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sycurelab/DECAF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `williballenthin/EVTXtract` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `radareorg/cutter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `simsong/bulk_extractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `moyix/panda` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gurnec/HashCheck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brad-accuvant/cuckoo-modified` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tklengyel/drakvuf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/binnavi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `F-Secure/see` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x64dbg/ScyllaHide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmersonElectricCo/fsf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomchop/unxor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KoreLogicSecurity/mastiff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `volatilityfoundation/volatility` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `msuhanov/regf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bwall/bamfdetect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diogo-fernan/malsub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/NoMoreXOR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xd4d/dnSpy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ANSSI-FR/polichombr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tencent/HaboMalHunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Storyyeller/Krakatau` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `angr/angr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kevthehermit/VolUtility` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dynetics/Malfunction` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ShaneK2/inVtero.net` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/iocs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OMENScan/AChoir` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rieck/malheur` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Visgean/Zeus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Karneades/malware-persistence` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AbertayMachineLearningGroup/CryptoKnight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BinaryAnalysisPlatform/bap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vduddu/Malware` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nbeede/BoomBox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keithjjones/fileintel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FGRibreau/mailchecker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/stringsifter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crypto2011/IDR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LordNoteworthy/al-khaser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CyberShadow/RABCDAsm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ytisf/muninn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elceef/dnstwist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aim4r/VolDiff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rocky/python-uncompyle6` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/IPinfo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `phdphuc/mac-a-mal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `504ensicsLabs/DAMM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `season-lab/bluepill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `9b/malpdfobj` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misterch0c/malSploitBase` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpr5/ngrep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/flare-floss` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `robbyFux/Ragpicker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `guelfoweb/peframe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joxeankoret/pyew` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `airbnb/binaryalert` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JamesHabben/evolve` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `devttys0/binwalk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `merces/aleph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corkami/pics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MITRECND/chopshop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ch3k1/squidmagic` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uppusaikiran/generic-parser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jessek/hashdeep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `katjahahn/PortEx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cmu-sei/pharos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `plasma-disassembler/plasma` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sketchymoose/TotalRecall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rurik/Noriben` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keithjjones/hostintel` | GITHUB | IP-Datei 3639d alt |
| `Cisco-Talos/ROPMEMU` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `novawebstudio-HN/Partner2Impact` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vitaleevo/fivaa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `huwhitememes/tollbooth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sandals891joggers/Lethal-Company-God-Mode-Utility` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `efolusi/efolusi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ingram-technologies/nextkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Antdrew07/purenewbuild` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SysAdminDoc/OpenRadar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `szl-holdings/szl-hf-frontier` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `402signalhq/402signal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zedxter/pizdato` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thunderxu7-sketch/paramshield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `seaweed65arraign/Shift-At-Midnight-Desktop-Enhancement-Suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-go` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johalputt/VayuPress` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InfoSEC-TR/usom-ioc-sync` | GITHUB | Identischer Inhalt wie infosec_tr_usom_ioc_sync |
| `AkhileshNagargoje/birthday-email-system` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `decolonial-ist/archive` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `harivansh-afk/builders-uva` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JiRaska/open-bank-oss` | GITHUB | Größe: 0 IPs |
| `enhansome/enhansome-android-root` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Superspyn/grainbidmap-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kaibshshdheueejw/Muchi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mattsimoto/cyber-threat-wall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `possn/Vestra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cyberchef0/Portswigger-labs-Progress-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gmirash-debug/solana-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jamie05351/SiphonDSP_J` | GITHUB | IP-Datei 60d alt |
| `meddadaek/rased` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ShreddedBear/tennis-truth-engine-8ecc1270` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LeilaoMi/cf-proxyip-us` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vlav11818-max/Aviation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elliotwutingfeng/2fas-backup-decryptor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `terminalshipyard-cmd/DeSlop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `builtbygio/chevron` | GITHUB | Größe: 0 IPs |
| `STARTcloud/provisioner-catalog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `policy-as-versioned-feeds/feeds` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `S13RRA-04/70-for-70` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PiercingXX/xx-dialer` | GITHUB | Größe: 0 IPs |
| `eLmincfrLu/T--3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aphilp1/stormwatch-live` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `snipy09/JobMaxxer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AxonOS-BCI/axonos-community-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `h1de0x/nft-threat-firewall` | GITHUB | Größe: 0 IPs |
| `xkef/swe-digest` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `femboypig/Swift` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ss-shiri/kaf-cbrne` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mauryarahul007/trip_tracker_2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AshvernHoldings/ashvern-holdings-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Paulmicha/asc` | GITHUB | Größe: 0 IPs |
| `sanohiro/align-llm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-public-datasets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sendtoosxent-eng/edlink_full` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maximuml/tracker-lp-bits` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Smarth-Bansal/Passport-Detection-System-SIH` | GITHUB | Größe: 0 IPs |
| `maadjiba24-afk/Olympus-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rullst/Rullst` | GITHUB | Größe: 0 IPs |
| `R00ted-82/warera-tools-ireland` | GITHUB | Größe: 0 IPs |
| `RiccardoRomano9/fantasquama-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marto96/Eduapp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ch-kanishk/wovnrugss` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Quad4-Software/ravenguard` | GITHUB | Größe: 0 IPs |
| `Bascht74/videopodcast-magic` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Quad4-Software/forge` | GITHUB | IP-Datei 325d alt |
| `dearbulut/iptv` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `grungies1138/d616-marvel-multiverse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Openclaw-Metis/linkproof-datasets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Power2All/nanotorrent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kisip/kisip-jobpilot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `csd4ni3l/nixos-config` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nickzerze/aws-secure-3-tier-terraform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `acqtom/paidcoaching` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vaultureau/Vaultureau` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GabrielAlbanez/RCL_PROJECT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sayedmadain887-dev/ATHAR-Number` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0-Ghostly-0/Scamsite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dicklesworthstone/frankengit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TreeCityWes/tree_usage_display` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `angela020322-hub/Stock-Portfolio-Analysis-Excel-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `radoslavirha/homelab` | GITHUB | Größe: 0 IPs |
| `simmeh024/tailfinsim` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MohammadAthar786/HRM-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ibrahimaasim77/multi-agent-trading-system` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dawiisss/DzLinux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `721189/SWARMOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NosFabrica/vespa-relay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-` | GITHUB | IP-Datei 32d alt |
| `widniewski-ux/dc-joinery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Moon-Knight13/my_claude_dev` | GITHUB | Größe: 0 IPs |
| `alakshendra-roy/AnimusCore_v1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `moniwise1/Meridian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `huddaiami-rgb/playstation-vault-indexer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hardikneeravsharma/AutoStream` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Etheras/Warframe_Prime_Hunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sparsh101sparsh/netra-deepfake-detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AI-Native-2026-07-29-Intuit/arush-adabala-tax-liability` | GITHUB | Größe: 0 IPs |
| `clambert1974/protectia-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PIXELHIZE/CleanMail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xmpuspus/floodwatch-ph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ruifung/rfhome-infrastructure` | GITHUB | IP-Datei 309d alt |
| `Nicalicious/Panopt-PhishReport` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dilukhin/agent-safe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ekaynac/onprem-ai-adoption-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coderage-labs/spillway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Agrim236/Personal-Finance` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gabrielcosi/home-ops` | GITHUB | IP-Datei 46d alt |
| `rkaya57/triproof-guard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `umbrasecdev/umbrasec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rashidazafer28-tech/layuna` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hheard938/day01-windows-failed-logon-detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `faaththeeman-bit/wardogs-ballistic-solver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `devshrawin/NewsFlick` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sportbega/mind-chess` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thaynes43/haynes-ops` | GITHUB | IP-Datei 42d alt |
| `rvnovaes/simple_ppg_manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `32u-nd/Spamhaus-DROP` | GITHUB | IP-Datei 176d alt |
| `sasafg123/discord-hardened-doh-client` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OneZero-Network/mcp-threat-intel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JulienCr/avolo-shorts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Naureen39/contract-lifecycle-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eermel/SolarTrigger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre-attack/attack-navigator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nunomcpereira/ignite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mirceanton/talswitcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tempest-Solutions-Company/threat-feeds` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `webuildwealth/WBW` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jangidtejendra07-dotcom/mailTrace_Ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `secwexen/security-playbooks` | GITHUB | IP-Datei 60d alt |
| `altarprotocol/altarprotocol` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `larsgrosscom/llmveil` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `clanford06/op-price-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `floppywiggler/directio64-disclosure` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `romanstma-cpu/rom-nova` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `taskrocketai-create/Daryl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `metrictower/funnypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `makathing/globenews` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `legacyboy/tabletop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nexusdolf-rgb/botdev` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aliiexe/Quire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Barni-ux/RAT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nayak16sachin-cloud/Sentinel-Spike` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andy2me/caloundraunited` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dwebserver/dweb-mail-abuse-guard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MrMarble/proxy-list` | GITHUB | Overlap zu gering: 1.3% |
| `redyasar10-web/rigs-registry` | GITHUB | IP-Datei 40d alt |
| `relayglass/free-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yourShika/AetheryteRepo` | GITHUB | Größe: 1 IPs |
| `bsir9011-aew/relapse-guard-blocklist` | GITHUB | Größe: 0 IPs |
| `namanjain221995/personal-LLM-Chabot` | GITHUB | Größe: 0 IPs |
| `tousle-8-sunlamp/Star-Trek-Outposts-Unknown-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tjsdyy/dshplugin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HumerousFi/log-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `karma3-pitchmen/Rayman-Legends-Retold-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pizzazz-41535diviner/SuckerForLove-CrushLanding-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Adolanium/hermes-agent-fuzzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sentinel-Architech/The-Remote-Viewer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zloi-user/hideip.me` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeremydegardeyn/datadinosaur` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arpangroup/pureeats-backend-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tirbase-BaaS/TirBase` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ellebeamazing/crawler-agent-signatures` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Gigiomiccio425/aegis-discord-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `embolden-stricter-1/EVE-Vanguard-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rosined55-allying/MGS4-Master-Collection-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zhuhaiuk/free-nodes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jokeprimmest-1/The-Cabin-Game-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `infield-33223-juncos/The-Adventurers-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ordinals-5-jinns/Fell-Sell-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Omerfishel/Sapir-Cyber-Learn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atuvero123/Rudiments` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0200project/base-tx-explain` | GITHUB | Größe: 0 IPs |
| `AccelGentic/massopen.ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `g-guglielmi/firewall-live-log` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christianm38/Personality-Typing-System` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PontusO/iLabs_Hearth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Eloi-Shema/Eloi-Shema` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Auditbyte25/demo-credit-wallet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VitaliyIvanov11/Lacupedas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alukacs03/packet-empire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

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
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 11,097 | 64.3% | 938 | 2026-09-04 |
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
| `hezhidong_scanguard_blocklist` | GITHUB | 317 | 87.7% | 0 | 2026-09-04 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 5,952 | 7.6% | 0 | 2026-09-04 |

---
*Generiert: 2026-09-04 22:41 CEST (Europe/Berlin)*