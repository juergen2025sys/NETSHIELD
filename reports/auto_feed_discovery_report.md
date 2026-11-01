# Auto Feed Discovery – Report
**Aktualisiert:** 2026-11-01 12:28 CET (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **11985** |
| davon GitHub (Topics+Code) | **11906** |
| davon GitLab | **79** |
| davon Awesome-Lists | **2211** |
| Tools/Libraries vor Eval gefiltert | **1003** |
| davon Hard-Reject (awesome-Liste etc.) | **217** |
| EVAL-Kandidaten (nach Stratifizierung) | **460** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **460** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **458** |
| Neu angenommene Feed-Dateien | **1** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **193** |
| Abgelehnte Repositories (dieser Run) | **458** |
| davon GitLab abgelehnt | **8** |
| Feeds gesamt (aktiv) | **194** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **140731** |
| SQLite-Refresh-Cache-Hits | **0/201** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **258** |
| Repo zu alt (>30d) | **183** |
| Falsche Größe (<30 / >2,000,000 IPs) | **9** |
| IP-Datei veraltet (>30d) | **8** |
| Sonstige | **2** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `blawoblowa_blackened` | [blawoblowa/blackened](https://github.com/blawoblowa/blackened) | GITHUB | 827 | 56.0% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `aixisstudio/Snitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hevnsnt/CVEngine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AgriciDaniel/pya` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `public-apis/public-apis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `analysis-tools-dev/static-analysis` | GITHUB | IP-Datei 1265d alt |
| `elastic/integrations` | GITHUB | IP-Datei 75d alt |
| `BigBodyCobain/Shadowbroker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NullArray/IntRec-Pack` | GITHUB | Zu alt: 2181d |
| `brendadeeznuts1111/fantasy42-ai-enhanced-tools` | GITHUB | Zu alt: 424d |
| `Forescout/eyeExtend-Connect` | GITHUB | IP-Datei 137d alt |
| `iqbalmh18/brave-api` | GITHUB | Zu alt: 72d |
| `ressl/mcp-firewall` | GITHUB | Zu alt: 53d |
| `cloudfieldcz/shieldoo-gate` | GITHUB | IP-Datei 212d alt |
| `osintph/darkweb-observatory` | GITHUB | Zu alt: 230d |
| `Tarrant64/abct` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s333s/ShadowGuard-AI` | GITHUB | Zu alt: 132d |
| `Winter0x11/Cyber-Threat-Intelligence` | GITHUB | Zu alt: 173d |
| `wallacebrf/dns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shreyasreddyb/Bugoff` | GITHUB | Zu alt: 413d |
| `PMSLLC/nexguard` | GITHUB | Zu alt: 51d |
| `MujumdarSahil/Dark-Web-Monitoring-Simulation` | GITHUB | Zu alt: 519d |
| `theabhishekchandra/ZeroDroid` | GITHUB | Zu alt: 39d |
| `OussamaGhribi/sec-npm` | GITHUB | Zu alt: 93d |
| `vigil-agency/vigil` | GITHUB | Zu alt: 161d |
| `BrAmaral/Purple-Team-Resources` | GITHUB | Zu alt: 184d |
| `intuit/bodyguard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Akshu1245/Rakshex-complete-codebase` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `komalgavade504-bot/CloudSentinel-AI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Shri47vidya/Development-of-Interactive-Cyber-Threat-Visualization-Dashboard-` | GITHUB | Zu alt: 244d |
| `mthamil107/prompt-shield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2pidata/openclaw-security-guard` | GITHUB | Zu alt: 198d |
| `janhvi-2403/SecureInbox` | GITHUB | Zu alt: 232d |
| `ReuxM13/prefixopt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `involvex/involvex-bun-scan` | GITHUB | Zu alt: 288d |
| `UmarFarooqueJi/SafeSignal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Familyye/MobileMorph` | GITHUB | Zu alt: 523d |
| `choicenew/yourcallyourrule` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ramsai676/HumanityAI` | GITHUB | Zu alt: 31d |
| `RonitPG19/AI-phishing-detection` | GITHUB | Zu alt: 160d |
| `PrakhidhaChawdhury/threat-radar` | GITHUB | Zu alt: 70d |
| `veddegre/signaltrace` | GITHUB | Zu alt: 140d |
| `utilvo/terraform-cloudflare-edge-shield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KingLinux24/cve-prioritization-agent` | GITHUB | Zu alt: 150d |
| `akshithnallaginnela/shield-insight-labs` | GITHUB | Zu alt: 68d |
| `DanishDhanjal15/Perimetry` | GITHUB | Zu alt: 82d |
| `byteninja01/Q-Guardian` | GITHUB | Zu alt: 187d |
| `Rahul08319/web-scout-ml` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VivekAgarwal31/Spectre-Suite` | GITHUB | Zu alt: 341d |
| `Flash1285/Specter_suite` | GITHUB | Zu alt: 342d |
| `rishabh-tya6i/Argus` | GITHUB | Zu alt: 213d |
| `westackai/glassworm-scanner` | GITHUB | Zu alt: 72d |
| `TFD666/signer` | GITHUB | Zu alt: 142d |
| `minalkharat-cmd/vibeguard-ai` | GITHUB | Zu alt: 262d |
| `vectimus/vectimus` | GITHUB | Zu alt: 31d |
| `shinjadong/security` | GITHUB | Zu alt: 266d |
| `itcmsgr/nftban` | GITHUB | IP-Datei 59d alt |
| `pduggusa/dugganusa-edge-shield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ganesh030106/LIL_FIREWALL` | GITHUB | Größe: 10 IPs |
| `Arnavvs/agentwall` | GITHUB | Zu alt: 170d |
| `spatiumnorth/spatiumddi` | GITHUB | IP-Datei 71d alt |
| `Vampsecure-Labs/vamp-darkweb-intel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `califio/publications` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sanbir/evm-hack-registry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `geftimov/hadoop-map-reduce-patterns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drjeong/cyse501` | GITHUB | Zu alt: 76d |
| `KTRiles55/RATTLE` | GITHUB | Zu alt: 145d |
| `quanhua92/tutorials` | GITHUB | Zu alt: 114d |
| `Fayza42/AtomicRedTeamOrchestrator` | GITHUB | Zu alt: 437d |
| `nevincoco1/goof` | GITHUB | Zu alt: 260d |
| `ArkhamKnightGPC/AHA_Challenge_2026` | GITHUB | Zu alt: 179d |
| `bayufedra/Research-NAIST-SE-2024` | GITHUB | Zu alt: 570d |
| `TeeLaReina/Cloud-Native-Detection-and-Response-Pipeline-Jirrix` | GITHUB | Zu alt: 46d |
| `ghazyachmed/cekbao` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mamont0v/appsec-lowcode-platform` | GITHUB | Zu alt: 610d |
| `DeepSourceCorp/benchmarks` | GITHUB | Zu alt: 194d |
| `ThunderySpoon7/COMP-5700` | GITHUB | Zu alt: 413d |
| `nbaliyan260/VeriCTI-RAG` | GITHUB | Zu alt: 166d |
| `FanetteSaury/dailycti` | GITHUB | Zu alt: 216d |
| `Dante-t0/pair-implementation` | GITHUB | Zu alt: 696d |
| `isamu-isozaki/AI-Pentest-Benchmark` | GITHUB | Zu alt: 737d |
| `CriticalPathSecurity/Zeek-Intelligence-Feeds` | GITHUB | Identischer Inhalt wie kraloveckey_ipsets_blocklist_bds_atif |
| `telekom-security/tpotce` | GITHUB | IP-Datei 143d alt |
| `telekom-security/tpotmobile` | GITHUB | Zu alt: 405d |
| `Check-Risk-WAF/Check-Risk-WAF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JasonLovesDoggo/caddy-defender` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ForbiddenProgrammer/conti-pentester-guide-leak` | GITHUB | Zu alt: 1902d |
| `pedramamini/ThreatIngestor` | GITHUB | Zu alt: 159d |
| `stanfrbd/cyberbro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Patrowl/PatrowlManager` | GITHUB | Zu alt: 236d |
| `pedramamini/iocextract` | GITHUB | Zu alt: 795d |
| `citizenlab/malware-indicators` | GITHUB | Zu alt: 2219d |
| `baidu/CarbonGraph` | GITHUB | Zu alt: 727d |
| `Patrowl/PatrowlEngines` | GITHUB | Zu alt: 100d |
| `GreedyBear-Project/GreedyBear` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `curated-intel/Log4Shell-IOCs` | GITHUB | Zu alt: 1703d |
| `Patrowl/PatrowlDocs` | GITHUB | Zu alt: 1664d |
| `CYB3RMX/MalwareHashDB` | GITHUB | Zu alt: 642d |
| `DavidMoore/ipfilter` | GITHUB | Zu alt: 275d |
| `ipverse/as-ip-blocks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `equk/windows` | GITHUB | Zu alt: 712d |
| `djkurlander/knock-knock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `momenbasel/puresnitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qundao/mirror-softcnkiller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gardenfence/blocklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Paxxs/Google-Blocklist` | GITHUB | Zu alt: 461d |
| `mhxion/pornaway` | GITHUB | Zu alt: 910d |
| `Reginald-Gillespie/Spotify-AI-Band-Blocker` | GITHUB | Zu alt: 95d |
| `blockadeio/chrome_extension` | GITHUB | Zu alt: 2156d |
| `sun-lite/firewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WaGi-Coding/WaGis-Mass-IP-Blacklister-Windows` | GITHUB | Zu alt: 911d |
| `DWW256/distracting-websites` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sundowndev/phoneinfoga` | GITHUB | Zu alt: 68d |
| `VibeTensor/attestix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qcod/laravel-gamify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beyondtahir/beyondseo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trustgraph/trustgraph` | GITHUB | Zu alt: 731d |
| `johannchopin/stackoverflow-readme-profile` | GITHUB | Zu alt: 716d |
| `ansezz/laravel-gamify` | GITHUB | Zu alt: 2000d |
| `e-m3din4/deep-email` | GITHUB | Zu alt: 1320d |
| `givepraise/praise` | GITHUB | Zu alt: 748d |
| `interep-project/reputation-service` | GITHUB | Zu alt: 1283d |
| `rainbowdashlabs/reputation-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenNewsLabs/autoEdit_2` | GITHUB | Zu alt: 973d |
| `linux-msm/qdl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Giovix92/EDLUnlock` | GITHUB | Zu alt: 1979d |
| `thefirefox12537/qctools_tff` | GITHUB | Zu alt: 1533d |
| `strongtz/edl-ng` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alephgsm/SAMSUNG-EDL-Loaders` | GITHUB | Zu alt: 55d |
| `AdaUnlocked/OnePlus-9008-JiuZhuan-Guide` | GITHUB | Zu alt: 288d |
| `Alephgsm/SAM-unbrick-debrick` | GITHUB | Zu alt: 985d |
| `HadiKhoirudin/Qualcomm-Tool` | GITHUB | Zu alt: 1000d |
| `tamm2904/MTFLASH_UBL_SNAPDRAGON` | GITHUB | Zu alt: 152d |
| `HadiKhoirudin/Qualcomm-Tool-GUI` | GITHUB | Zu alt: 1425d |
| `Red5d/edlkit` | GITHUB | Zu alt: 980d |
| `Mrivai/Xiaomi-Service-Tool` | GITHUB | Zu alt: 1505d |
| `CosmicDan-Android/MiA1LowLevelBackupRestoreTool` | GITHUB | Zu alt: 1703d |
| `yuriskinfo/cheat-sheets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `prometheus-community/fortigate_exporter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheTaylorLee/AdminToolbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yuriskinfo/Fortinet-tools` | GITHUB | Zu alt: 76d |
| `fortinet/fortigate-terraform-deploy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FortiPower/PowerFGT` | GITHUB | Zu alt: 305d |
| `fortinet-solutions-cse/fortiosapi` | GITHUB | Zu alt: 1353d |
| `mbdraks/fortinet-zabbix` | GITHUB | Zu alt: 1593d |
| `vladimirs-git/fortigate-api` | GITHUB | Zu alt: 144d |
| `fortinet/4D-Demo` | GITHUB | Zu alt: 114d |
| `40net-cloud/fortinet-azure-solutions` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fortinet-solutions-cse/40ansible` | GITHUB | Zu alt: 2451d |
| `alextibor/wazuh-fortigate-rules-decoders` | GITHUB | Zu alt: 950d |
| `bl4ko/netbox-ssot` | GITHUB | Größe: 0 IPs |
| `mbdraks/gatepy` | GITHUB | Zu alt: 2841d |
| `angela-d/brain-dump` | GITHUB | Zu alt: 190d |
| `AsBuiltReport/AsBuiltReport.Fortinet.FortiGate` | GITHUB | Zu alt: 336d |
| `glennake/DirectFire_Converter` | GITHUB | Zu alt: 1701d |
| `Tufin/pytos` | GITHUB | Zu alt: 717d |
| `ondrejholecek/sniftran` | GITHUB | Zu alt: 249d |
| `N4SOC/fortilogcsv` | GITHUB | Zu alt: 342d |
| `noways-io/fortigate-crypto` | GITHUB | Zu alt: 972d |
| `signorrayan/Splunk-Threat-Hunting` | GITHUB | Zu alt: 1557d |
| `fortinet/fortios-ips-snort` | GITHUB | Zu alt: 661d |
| `gdoornenbal/dehydrated-certificate-installers` | GITHUB | Zu alt: 2330d |
| `akshaymane920/pyFortimanagerAPI` | GITHUB | Zu alt: 218d |
| `fortinet-solutions-cse/fortistacks` | GITHUB | Zu alt: 764d |
| `kljunowsky/CVE-2023-36845` | GITHUB | Zu alt: 1038d |
| `vxunderground/MalwareSourceCode` | GITHUB | Zu alt: 155d |
| `mytechnotalent/Reverse-Engineering` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wifiphisher/wifiphisher` | GITHUB | Zu alt: 163d |
| `screetsec/TheFatRat` | GITHUB | Zu alt: 959d |
| `ayoubfaouzi/al-khaser` | GITHUB | Zu alt: 123d |
| `qilingframework/qiling` | GITHUB | IP-Datei 2048d alt |
| `CalebFenton/simplify` | GITHUB | Zu alt: 1646d |
| `kevoreilly/CAPEv2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lifka/hacking-resources` | GITHUB | Zu alt: 859d |
| `m0nad/Diamorphine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ch0pin/medusa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mattnotmax/cyberchef-recipes` | GITHUB | Zu alt: 870d |
| `CYB3RMX/Qu1cksc0pe` | GITHUB | Zu alt: 44d |
| `vxunderground/VX-API` | GITHUB | Zu alt: 977d |
| `JustasMasiulis/lazy_importer` | GITHUB | Zu alt: 1186d |
| `fabrimagic72/malware-samples` | GITHUB | Zu alt: 1873d |
| `chvancooten/maldev-for-dummies` | GITHUB | Zu alt: 1248d |
| `Da2dalus/The-MALWARE-Repo` | GITHUB | Zu alt: 1043d |
| `zeustrojancode/Zeus` | GITHUB | Zu alt: 2154d |
| `jvoisin/php-malware-finder` | GITHUB | Zu alt: 1108d |
| `openclarity/openclarity` | GITHUB | Zu alt: 160d |
| `vxunderground/VXUG-Papers` | GITHUB | Zu alt: 1790d |
| `emalderson/ThePhish` | GITHUB | Zu alt: 822d |
| `cecio/USBvalve` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `research-virus/stuxnet` | GITHUB | Zu alt: 1527d |
| `mategol/PySilon` | GITHUB | Zu alt: 154d |
| `MinhasKamal/TrojanCockroach` | GITHUB | Zu alt: 377d |
| `NoDataFound/hackGPT` | GITHUB | Zu alt: 81d |
| `alvin-tosh/Malware-Exhibit` | GITHUB | Zu alt: 1024d |
| `JusticeRage/Manalyze` | GITHUB | Zu alt: 64d |
| `AHXR/ghost` | GITHUB | Zu alt: 1977d |
| `SaadAhla/FilelessPELoader` | GITHUB | Zu alt: 1160d |
| `redcode-labs/neurax` | GITHUB | Zu alt: 1074d |
| `redcode-labs/Coldfire` | GITHUB | Zu alt: 688d |
| `mauri870/ransomware` | GITHUB | Zu alt: 2906d |
| `data-prep-kit/data-prep-kit` | GITHUB | Zu alt: 33d |
| `certsocietegenerale/fame` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aaaddress1/RunPE-In-Memory` | GITHUB | Zu alt: 2044d |
| `curated-intel/Ukraine-Cyber-Operations` | GITHUB | Zu alt: 1224d |
| `mrexodia/dumpulator` | GITHUB | Zu alt: 1003d |
| `KiExitDispatcher/GoDefender` | GITHUB | Zu alt: 326d |
| `strazzere/anti-emulator` | GITHUB | Zu alt: 2109d |
| `BushidoUK/Open-source-tools-for-CTI` | GITHUB | Zu alt: 266d |
| `hdks-bug/exploitnotes` | GITHUB | Zu alt: 234d |
| `LimerBoy/Adamantium-Thief` | GITHUB | Zu alt: 658d |
| `dragokas/hijackthis` | GITHUB | Zu alt: 122d |
| `tarcisio-marinho/GonnaCry` | GITHUB | Zu alt: 646d |
| `Print3M/DllShimmer` | GITHUB | Zu alt: 432d |
| `SaturnsVoid/GoBot2` | GITHUB | Zu alt: 1864d |
| `cr-0w/maldev` | GITHUB | Zu alt: 170d |
| `r1cksec/cheatsheets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gen0cide/gscript` | GITHUB | Zu alt: 981d |
| `ossillate-inc/packj` | GITHUB | Zu alt: 45d |
| `MinhasKamal/CuteVirusCollection` | GITHUB | Zu alt: 938d |
| `gwillem/magento-malware-scanner` | GITHUB | Zu alt: 1061d |
| `rek7/fireELF` | GITHUB | Zu alt: 2755d |
| `KiExitDispatcher/GoRedOps` | GITHUB | Zu alt: 553d |
| `guitmz/virii` | GITHUB | Zu alt: 217d |
| `looCiprian/GC2-sheet` | GITHUB | Zu alt: 130d |
| `cryptwareapps/Malware-Database` | GITHUB | Zu alt: 256d |
| `0xIslamTaha/Python-Rootkit` | GITHUB | Zu alt: 733d |
| `ncorbuk/Python-Ransomware` | GITHUB | Zu alt: 606d |
| `Virus-Samples/Malware-Sample-Sources` | GITHUB | Zu alt: 2094d |
| `ThomasThelen/Anti-Debugging` | GITHUB | Zu alt: 1769d |
| `ujjwal-kr/system-programming-roadmap` | GITHUB | Zu alt: 64d |
| `AleksaMCode/WiFi-password-stealer` | GITHUB | Zu alt: 463d |
| `mstfknn/malware-sample-library` | GITHUB | Zu alt: 1076d |
| `scr34m/php-malware-scanner` | GITHUB | Zu alt: 130d |
| `termuxhackers-id/SARA` | GITHUB | Zu alt: 329d |
| `EgeBalci/HERCULES` | GITHUB | Zu alt: 1932d |
| `Sadpainy/Stuxnet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CheckPointSW/InviZzzible` | GITHUB | Zu alt: 215d |
| `rek7/mXtract` | GITHUB | Zu alt: 1818d |
| `CybercentreCanada/assemblyline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dobin/avred` | GITHUB | Zu alt: 127d |
| `richkmeli/Richkware` | GITHUB | Zu alt: 301d |
| `MISP/misp-workbench` | GITHUB | Größe: 2 IPs |
| `csirtgadgets/bearded-avenger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fhightower/ioc-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InQuest/ThreatIngestor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xiaoxiaoleo/HoneyMysql` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sahilm/hived` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marist-Innovation-Lab/DolosHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ls1911/GenAIPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ayrus/afterglow-cloud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/honeyfs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fofapro/fapro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thinkst/canarytokens` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rep/hpfeeds` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hgascon/acapulco` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amv42/sshd-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityTW/delilah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `glaslos/honeyprint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `m4rco-/dorothy2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tnich/honssh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SneakersInc/HoneyMalt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mzweilin/ipv6-attack-detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `traetox/sshForShits` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omererdem/honeything` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mkishere/sshsyrup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `r0hi7/HoneySMB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lnslbrty/potd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Masood-M/yalih` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jesparza/peepdf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marist-Innovation-Lab/PasitheaHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mojachieee/go-HoneyPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fnzv/YAFH` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ciscocsirt/dhp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `msurguy/Honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xme/dshield-docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `threatstream/shockpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexbredo/honeypot-ftp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MalwareTech/CitrixHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PaulMaddox/gohoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xlfe/cowrie2neo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `secureworks/dcept` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WebDecoy/FCaptcha` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magisterquis/sshlowpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `citronneur/rdpy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HoneySat/honeysat-deploy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `run41/honey_ports` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `threatstream/mhn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `freak3dot/smart-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `urule99/jsunpack-n` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/servletpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MartinIngesen/HonnyPotter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hexgolems/schem` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/honeylambda` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpyorre/IntelligentHoneyNet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LogoiLab/honeyup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kingtuna/go-emulators` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gregcmartin/Kippo_JunOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DataSoft/Nova` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeremyfritzen/Ethereum-honey-pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mdp/honeypot.go` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tillmannw/honeytrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ahoernecke/ensnare` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ppacher/honeyssh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gosecure/pyrdp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johestephan/VerySimpleHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magisterquis/sshhipot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/honeypot-setup-script` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fygrave/honeyntp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nsmfoo/antivmdetection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bartnv/portlurker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JustinAzoff/ssh-auth-logger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `huuck/ADBHoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `czardoz/hornet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CanadianJeff/honeywrt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sefcom/honeyplc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ziemeck/bifrozt-ansible` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thomaspatzke/Log4Pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gfoss/phpmyadmin_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrschyte/dockerpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hatching/vmcloak` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `packetflare/amthoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `csirtgadgets/csirtg-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `upa/ofpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WebDecoy/wordpress-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gbrindisi/wordpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexbredo/honeypot-camera` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `androguard/androguard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/glastopf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yuchincheng/HpfeedsHoneyGraph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jordan-wright/elastichoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betheroot/sticky_elephant` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sjhilt/GasPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `phin3has/mailoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/honeyalarmg2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inguardians/toms_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sk4ld/gridpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/apkinspector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betheroot/pghoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kungfuguapo/HoneyPress` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shjalayeri/pwnypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cymmetria/ciscoasa_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Joss-Steward/honeypotDisplay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `securitygeneration/Honeyport` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deroux/longitudinal-analysis-cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `torque59/nosqlpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/bluepot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fzerorubigd/go0r` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cryptix720/HUDINX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `provos/honeyd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `d1str0/drupot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `balte/TelnetHoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/MysqlPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrew-morris/kippo_detect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/canarytokendetector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GetPageSpeed/nginx-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vstinner/hachoir3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Visgean/Zeus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LDO-CERT/orochi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `secretsquirrel/recomposer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/flare-fakenet-ng` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jessek/hashdeep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:PRTG/Device-Templates/Checkpoint` | GITLAB | Zu alt: 1543d |
| `gitlab:yetopen/zabbix-fortinet-template` | GITLAB | Zu alt: 2234d |
| `gitlab:aurelian.cireasa/omarchy-linux-vps-deletion_scheduled-88034583` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:kikinovak/deb_setup_fail2ban` | GITLAB | Zu alt: 32d |
| `gitlab:valtersit/threat-ip-blocklist` | GITLAB | Zu alt: 34d |
| `gitlab:Christopher-K-Long/saveable-objects` | GITLAB | Zu alt: 54d |
| `gitlab:francoisjacquet/Entry_Exit` | GITLAB | Zu alt: 158d |
| `gitlab:fortigate/fortigate_address_create` | GITLAB | Zu alt: 2323d |
| `Correia-jpv/fucking-design-resources-for-developers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thebrazenbeard/aeonith` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rupac4530-creator/battle-of-272-parliament` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NaiemUrRahmanRiyad/allexdesignltd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JamesTRichmond/JamesTRichmond` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ghanimsokaki/survive-in-a-car-for-100-day-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Correia-jpv/fucking-Best-websites-a-programmer-should-visit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xStoic-bit/Synapse_Shield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nickdotname/ugc-factory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tbao4151/DA_CNTT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `edwardbergyolo/Yolo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Villain20000/HealthBridge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `falco81/ISEMon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CryptoDilis/Climboria` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mustafa-Altay75/YazLab1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Susil-commits/Veritas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `1337isnot1337/integer-factoring` | GITHUB | Größe: 0 IPs |
| `StealthCat/MrPatchy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `paulmann/Fail2Ban_AbuseIPDB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rom/rivets_n_ruin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaizenchandra/PRODUCTION-GRADE-ENTERPRIZE-RAG` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ZIOTI/CyberLab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `v0-0x/Aniko` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Asayed36/trading-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `v0-0x/kumobox-movies` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sinlt0/soward` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `giantswarm/beekeeper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RaBYho/DL_SOC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Correia-jpv/fucking-build-your-own-x` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VijayAdithyaBK/casio-price-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Inkesk-Dozing/CodeAtlas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bala-Blockchian/beldexscraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bkkflynnsta/hp10x-macos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RunTimeAdmin/Sigvara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aadamaftabpersonal-boop/FORGEHackathon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Veldora-0/BugBounty-Agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `havando1302/T_Lingua_SYSTEM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blawoblowa/blackened` | GITHUB | Identischer Inhalt wie blawoblowa_blackened |
| `NicoPinguinDEV/Pulse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diosadelaverdad/diosadelaverdad` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SreerajSK990/script-mc-launcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vyntaris/vyntaris` | GITHUB | Größe: 0 IPs |
| `irxfire/unifi-threat-feeds` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KallumS/Reverberator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `111110100/moodle-aws` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenVibers/OpenVibe.MediaHub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lqid/noaware.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dungthtd9126/Dirty-frag-research` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Braedach/ARTEX-MUTANT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JuanenRac/URTC-TESTER` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rachitpatel1208-lgtm/CAEMP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tallpbx/tallpbx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shreyannag/EduERP` | GITHUB | Größe: 0 IPs |
| `zaidqureshi10/casio-deal-watcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mohamed-taha-elmeligy/aadati-full-version` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `radioheavy/omux-linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `msurueg-commits/YAZS-Ultimate-Sandbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tiegertosch/Omsi-Mod-Hub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benjasantu01-dotcom/limpieza-total-omega` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Boredem125/architecture-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `meteoriskitalia-netizen/MeteoRisk-Light-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aitorayussef-sketch/-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ironship/UsefulPlatesAndTooltips` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ferrocite/ferrox` | GITHUB | Größe: 0 IPs |
| `MaxLightner/kitchyar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `adaptivesystemsdev/ai-command-center` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SirOtter0/void-desktop-setup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jtmasters3/nfl-news-hub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vinittailor/open_fashion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UNRLZD/confidential-trenches` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `harshitrajj23/Verdion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Abolfazl-bagheri/Lbank_Bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `almgadmiyaseen-dotcom/dead-cells-overdrive-vault` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `exceev-consulting/server-prep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anycon-ai/anycon` | GITHUB | Größe: 0 IPs |
| `stalkrblond36/Necesse-Full-Version-Unlocked` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `funnybunnyakirisu5/Usb-Network-Gate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `azza0101/rambla-log` | GITHUB | Größe: 0 IPs |
| `ddavidefornelli/prune-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dlacksgud11111-tech/news-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FreyFlyy/Redoubt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ipaliog-a11y/Engine_simulator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sidecharactersofficial/FedLearn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Gegenschuss/kalmido` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jiripeterka-hub/signature-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `greekfetacheese/netshield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SildiCapani/LLM-Paper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `galvarezz09/Grammar-Drill-Yard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `justsomeoneretarded/Top10-Movies` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `afreenkazmi35713-pixel/prompt-injection-detection-bert` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `badhonai/postgen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iheeae/tabula-rasa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 25,349 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,129 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 8,459 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,911 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,809 | 0.2% | 120 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,779 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,676 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,348 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 957 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 563 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 542 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 437 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 258 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,481 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,727 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 20,241 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 12,785 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,971 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,605 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 6,510 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 215,712 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,532 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 6,145 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,636 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 4,329 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 32,722 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 4,815 | 64.3% | 938 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 53,901 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,753 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,542 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 118,269 | 0.2% | 36 | 2026-07-05 |
| `telekom_security_listbot` | GITHUB | 506 | 10.4% | 22 | 2026-10-18 |
| `dinoz0rg_proxy_list` | GITHUB | 91,788 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,120 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 94,438 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 109,063 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,560 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 102,684 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,907 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 103,570 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 542 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 502,059 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,982 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 174,633 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 91,270 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 173,260 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 175,600 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 98,905 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 97,081 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 271,335 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 50,722 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 215,002 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 24,494 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 17,319 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 16,169 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 180,711 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,845 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 9,564 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 9,776 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 25,839 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 15,609 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 13,043 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 21,650 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,599 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,369 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,341 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,619 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 703 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,553 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 3,240 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 9,086 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,956 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 129,156 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,195 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 29,069 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,177 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 4,640 | 79.4% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,627 | 64.3% | 10 | 2026-10-11 |
| `ian_lusule_proxies` | GITHUB | 3,243 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,594 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,365 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 374,173 | 22.0% | 6 | 2026-07-08 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,330 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 101 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 106,397 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 108,395 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 23,327 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 108 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 107,145 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,350 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,750 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 76 | 28.1% | 2 | 2026-08-02 |
| `runtechx_dns_runtech_ao` | GITHUB | 19,725 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 18,096 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 28,537 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,398 | 31.1% | 1 | 2026-07-14 |
| `klonet_it_ip_threat_lists` | GITHUB | 140,994 | 51.5% | 1 | 2026-10-11 |
| `klonet_it_ip_threat_lists_blocklist_apache` | GITHUB | 9,294 | 9.7% | 1 | 2026-10-11 |
| `idleadmin_threatfeed` | GITHUB | 51,850 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 71,186 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,020 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 139,781 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 388 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 197,764 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,537 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 141,829 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 223,420 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,103 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,239 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 35,612 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 18,008 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 18,331 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,708 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 10,054 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 8,186 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,618 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 6,559 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,250 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,011 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,117 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,531 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 4,867 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,848 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 731 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 5,779 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 971 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,228 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,284 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,188 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,277 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,115 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,009 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,560 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,163 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,274 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 555 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,956 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,622 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 967 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 12,370 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,962 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 94,855 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 92,922 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 91,440 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 90,886 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 95,387 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 106,253 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 22,876 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 41,501 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,930 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,637 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,000 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,420 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 50,593 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 29,210 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 11,280 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 16,344 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 23 | 63.9% | 0 | 2026-08-12 |
| `zgzyh_malicious_website_detection` | GITHUB | 33,747 | 3.1% | 0 | 2026-08-15 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,469 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 17,722 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 6,365 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,579 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 1,318 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 489 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 227 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 8,783 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 90,858 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 94,380 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 90,676 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 90,563 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 91,971 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 32,449 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 4,035 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 3,985 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 1,190 | 76.9% | 0 | 2026-09-25 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 2,665 | 5.4% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_all_90d` | GITHUB | 6,583 | 61.9% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_aggressive` | GITHUB | 68 | 80.9% | 0 | 2026-10-11 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 175,899 | 17.9% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 17,086 | 59.1% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 8,654 | 80.7% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_tor_exits` | GITHUB | 1,224 | 69.1% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_sblam` | GITHUB | 1,119 | 30.3% | 0 | 2026-10-18 |
| `helio4k_bad_ip` | GITHUB | 2,030 | 43.3% | 0 | 2026-10-25 |
| `verkombr_block_list_firewalls` | GITHUB | 849 | 46.9% | 0 | 2026-10-25 |
| `blawoblowa_blackened` | GITHUB | 827 | 56.0% | 0 | 2026-11-01 |

---
*Generiert: 2026-11-01 12:28 CET (Europe/Berlin)*