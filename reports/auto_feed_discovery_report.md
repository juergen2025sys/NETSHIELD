# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-13 08:03 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **11846** |
| davon GitHub (Topics+Code) | **11761** |
| davon GitLab | **85** |
| davon Awesome-Lists | **2201** |
| Tools/Libraries vor Eval gefiltert | **932** |
| davon Hard-Reject (awesome-Liste etc.) | **206** |
| EVAL-Kandidaten (nach Stratifizierung) | **440** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **440** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **438** |
| Neu angenommene Feed-Dateien | **1** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **185** |
| Abgelehnte Repositories (dieser Run) | **438** |
| davon GitLab abgelehnt | **3** |
| Feeds gesamt (aktiv) | **186** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **162175** |
| SQLite-Refresh-Cache-Hits | **0/191** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **243** |
| Repo zu alt (>30d) | **177** |
| IP-Datei veraltet (>30d) | **10** |
| Falsche Größe (<30 / >2,000,000 IPs) | **8** |
| Sonstige | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `claudiusdecimius_ics_ip` | [ClaudiusDecimius/ICS_IP](https://github.com/ClaudiusDecimius/ICS_IP) | GITHUB | 16,047 | 9.3% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `FrancescoPaoloL/lockfile-analyzer` | GITHUB | Zu alt: 77d |
| `mimibooma/SPECTER` | GITHUB | Größe: 24 IPs |
| `arkime/arkime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `helsecert/blocklist` | GITHUB | Zu alt: 149d |
| `GhostKellz/arch` | GITHUB | IP-Datei 352d alt |
| `Vu1nT0tal/yarb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KevinGuenay/fortigate-baseline` | GITHUB | Zu alt: 114d |
| `kj299/threat-intel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spatiumddi/spatiumddi` | GITHUB | Größe: 0 IPs |
| `ruohong2018/ruohong2018.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BassilekinJean/Configuration-Inter-VLANS-avec-Fortigate-` | GITHUB | Zu alt: 512d |
| `fortinet/aws-lambda-guardduty` | GITHUB | Zu alt: 1219d |
| `demisto/content-docs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BruceFeIix/picker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `habib-wael/DEPI-Enterprise-Network-Infrastructure` | GITHUB | Zu alt: 280d |
| `nericksen/xsoar-cli` | GITHUB | Zu alt: 1319d |
| `malek-annabi/misp-to-fortigate-ebl` | GITHUB | Zu alt: 445d |
| `cleverg0d/threat-feeds` | GITHUB | IP-Datei 430d alt |
| `GhostKellz/ghostkellz.sh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GhostKellz/ckelley.dev` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OneUptime/blog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MFIRoadMap/Fortinet-Product-Notes` | GITHUB | Zu alt: 448d |
| `expressemotion/kvstore-syncthing` | GITHUB | Zu alt: 212d |
| `yuliussetyawan/network-lab` | GITHUB | Zu alt: 88d |
| `kidrek/VigilIntel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jclee941/blacklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crowdsecurity/crowdsec-skill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MM0x02/RSS-Push` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DASD-Panthers/Fortigate-Threat-Feeds` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `quack7878/Veille_Techno_H25` | GITHUB | Zu alt: 458d |
| `d3ckx1/today-news` | GITHUB | Zu alt: 675d |
| `abrhim1/malicious-ip` | GITHUB | Zu alt: 449d |
| `fabriziosalmi/asn-api` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexlinos/threat-feed-me` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JoeRu/federloom` | GITHUB | Zu alt: 47d |
| `pcardotatgit/XDR_Workflows_and_Stuffs` | GITHUB | Zu alt: 368d |
| `Arpitapaaul/SIEM-Lite` | GITHUB | Zu alt: 73d |
| `SumoLogic/cloud-siem-content-catalog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheLurkas/SOC` | GITHUB | Zu alt: 174d |
| `101zh/FortiGate40FWLANControllerLab` | GITHUB | Zu alt: 119d |
| `GhostKellz/fortigate` | GITHUB | Zu alt: 165d |
| `shellsec/SECDaily` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fortinet/aws-lambda-guardduty-v2` | GITHUB | Zu alt: 305d |
| `domis-corp/huntershield` | GITHUB | Zu alt: 376d |
| `peterreyess123/fortigate7.6-chapter-key-takeaways` | GITHUB | Zu alt: 460d |
| `opnsense/lang` | GITHUB | Zu alt: 150d |
| `yuvalg72/Cyber_Security-Blocklist-Compilation` | GITHUB | Zu alt: 383d |
| `xphox2/Firewall-Monitoring` | GITHUB | IP-Datei 60d alt |
| `pulumiverse/pulumi-fortios` | GITHUB | Zu alt: 796d |
| `Mano-Abdeen/Firewall-Policy-Anomaly-Analyzer` | GITHUB | Zu alt: 72d |
| `jwhitt3r/intel.overresearched.net` | GITHUB | Zu alt: 40d |
| `saiz123/Sift` | GITHUB | Zu alt: 42d |
| `uni-tue-kn/MalFIX` | GITHUB | Zu alt: 538d |
| `mahmoudahmed3132/soar-lite` | GITHUB | Zu alt: 168d |
| `neostar-ja/wazuh_ova` | GITHUB | Zu alt: 65d |
| `LL7Baucarre/ELASLIP` | GITHUB | Zu alt: 222d |
| `simonpainter/www.simonpainter.com` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `poroping/terraform-provider-fortimanagerdvdb` | GITHUB | Zu alt: 839d |
| `jkerai1/SoftwareCertificates` | GITHUB | IP-Datei 709d alt |
| `forticrevs/fmg-profile-comparator` | GITHUB | Zu alt: 37d |
| `Sami9211/ThreatOrbit` | GITHUB | IP-Datei 87d alt |
| `fortinetdev/terraform-provider-fmgdevice` | GITHUB | Zu alt: 136d |
| `javierDAW/detection-diary` | GITHUB | IP-Datei 43d alt |
| `CTI-Buddy/cti-buddy.github.io` | GITHUB | Zu alt: 318d |
| `swyxio/ai-notes` | GITHUB | Zu alt: 209d |
| `daviddao/awful-ai` | GITHUB | Zu alt: 570d |
| `InQuest/yara-rules` | GITHUB | Zu alt: 1586d |
| `nv-tlabs/SCube` | GITHUB | Zu alt: 334d |
| `win4r/ClawTeam-OpenClaw` | GITHUB | Zu alt: 72d |
| `punishell/bbtips` | GITHUB | Zu alt: 409d |
| `TheAlanNix/cisco-security-tools` | GITHUB | Zu alt: 1375d |
| `wesammustafa/Claude-Code-Everything-You-Need-to-Know` | GITHUB | Zu alt: 47d |
| `LycheeMem/LycheeMem` | GITHUB | Zu alt: 38d |
| `HUBioDataLab/DrugGEN` | GITHUB | Zu alt: 33d |
| `trailofbits/claude-code-config` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tmgthb/Autonomous-Agents` | GITHUB | Zu alt: 81d |
| `MontrealAI/AGI-Alpha-Agent-v0` | GITHUB | Zu alt: 136d |
| `cybershujin/Threat-Actors-use-of-Artifical-Intelligence` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CiscoDevNet/foundry-security-spec` | GITHUB | Zu alt: 124d |
| `FlagOpen/FlagData` | GITHUB | Zu alt: 822d |
| `cbuijs/hagezi` | GITHUB | Identischer Inhalt wie configserverapps_service_blocklists_blocklist |
| `OktayAlver/siberkapan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `baidu/CarbonGraph` | GITHUB | Zu alt: 678d |
| `mthcht/Purpleteam` | GITHUB | Zu alt: 632d |
| `realchendahuang/feedsieve` | GITHUB | Größe: 0 IPs |
| `ipverse/as-ip-blocks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `equk/windows` | GITHUB | Zu alt: 663d |
| `djkurlander/knock-knock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qundao/mirror-softcnkiller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gardenfence/blocklist` | GITHUB | Zu alt: 35d |
| `Paxxs/Google-Blocklist` | GITHUB | Zu alt: 412d |
| `momenbasel/puresnitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `greyhat-academy/lists.d` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mhxion/pornaway` | GITHUB | Zu alt: 861d |
| `Reginald-Gillespie/Spotify-AI-Band-Blocker` | GITHUB | Zu alt: 46d |
| `blockadeio/chrome_extension` | GITHUB | Zu alt: 2107d |
| `WaGi-Coding/WaGis-Mass-IP-Blacklister-Windows` | GITHUB | Zu alt: 862d |
| `sun-lite/firewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DWW256/distracting-websites` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qcod/laravel-gamify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trustgraph/trustgraph` | GITHUB | Zu alt: 682d |
| `johannchopin/stackoverflow-readme-profile` | GITHUB | Zu alt: 667d |
| `ansezz/laravel-gamify` | GITHUB | Zu alt: 1951d |
| `e-m3din4/deep-email` | GITHUB | Zu alt: 1271d |
| `givepraise/praise` | GITHUB | Zu alt: 699d |
| `arian-gogani/nobulex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `interep-project/reputation-service` | GITHUB | Zu alt: 1234d |
| `rainbowdashlabs/reputation-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenNewsLabs/autoEdit_2` | GITHUB | Zu alt: 924d |
| `linux-msm/qdl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Giovix92/EDLUnlock` | GITHUB | Zu alt: 1930d |
| `thefirefox12537/qctools_tff` | GITHUB | Zu alt: 1484d |
| `Alephgsm/SAMSUNG-EDL-Loaders` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `strongtz/edl-ng` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alephgsm/SAM-unbrick-debrick` | GITHUB | Zu alt: 936d |
| `AdaUnlocked/OnePlus-9008-JiuZhuan-Guide` | GITHUB | Zu alt: 239d |
| `HadiKhoirudin/Qualcomm-Tool` | GITHUB | Zu alt: 951d |
| `tamm2904/MTFLASH_UBL_SNAPDRAGON` | GITHUB | Zu alt: 103d |
| `HadiKhoirudin/Qualcomm-Tool-GUI` | GITHUB | Zu alt: 1376d |
| `Red5d/edlkit` | GITHUB | Zu alt: 931d |
| `Mrivai/Xiaomi-Service-Tool` | GITHUB | Zu alt: 1456d |
| `CosmicDan-Android/MiA1LowLevelBackupRestoreTool` | GITHUB | Zu alt: 1654d |
| `yuriskinfo/cheat-sheets` | GITHUB | Zu alt: 77d |
| `prometheus-community/fortigate_exporter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheTaylorLee/AdminToolbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yuriskinfo/Fortinet-tools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fortinet/fortigate-terraform-deploy` | GITHUB | Zu alt: 33d |
| `FortiPower/PowerFGT` | GITHUB | Zu alt: 256d |
| `fortinet-solutions-cse/fortiosapi` | GITHUB | Zu alt: 1304d |
| `mbdraks/fortinet-zabbix` | GITHUB | Zu alt: 1544d |
| `fortinet/4D-Demo` | GITHUB | Zu alt: 65d |
| `40net-cloud/fortinet-azure-solutions` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fortinet-solutions-cse/40ansible` | GITHUB | Zu alt: 2402d |
| `alextibor/wazuh-fortigate-rules-decoders` | GITHUB | Zu alt: 901d |
| `mbdraks/gatepy` | GITHUB | Zu alt: 2792d |
| `bl4ko/netbox-ssot` | GITHUB | Größe: 0 IPs |
| `angela-d/brain-dump` | GITHUB | Zu alt: 141d |
| `AsBuiltReport/AsBuiltReport.Fortinet.FortiGate` | GITHUB | Zu alt: 287d |
| `Tufin/pytos` | GITHUB | Zu alt: 668d |
| `ondrejholecek/sniftran` | GITHUB | Zu alt: 200d |
| `N4SOC/fortilogcsv` | GITHUB | Zu alt: 293d |
| `noways-io/fortigate-crypto` | GITHUB | Zu alt: 923d |
| `signorrayan/Splunk-Threat-Hunting` | GITHUB | Zu alt: 1508d |
| `fortinet/fortios-ips-snort` | GITHUB | Zu alt: 612d |
| `gdoornenbal/dehydrated-certificate-installers` | GITHUB | Zu alt: 2281d |
| `akshaymane920/pyFortimanagerAPI` | GITHUB | Zu alt: 169d |
| `fortinet-solutions-cse/fortistacks` | GITHUB | Zu alt: 715d |
| `kljunowsky/CVE-2023-36845` | GITHUB | Zu alt: 989d |
| `mytechnotalent/Reverse-Engineering` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `screetsec/TheFatRat` | GITHUB | Zu alt: 910d |
| `ayoubfaouzi/al-khaser` | GITHUB | Zu alt: 74d |
| `CalebFenton/simplify` | GITHUB | Zu alt: 1597d |
| `kevoreilly/CAPEv2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lifka/hacking-resources` | GITHUB | Zu alt: 810d |
| `Ch0pin/medusa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mattnotmax/cyberchef-recipes` | GITHUB | Zu alt: 821d |
| `JustasMasiulis/lazy_importer` | GITHUB | Zu alt: 1137d |
| `fabrimagic72/malware-samples` | GITHUB | Zu alt: 1824d |
| `zeustrojancode/Zeus` | GITHUB | Zu alt: 2105d |
| `jvoisin/php-malware-finder` | GITHUB | Zu alt: 1059d |
| `openclarity/openclarity` | GITHUB | Zu alt: 111d |
| `cecio/USBvalve` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MinhasKamal/TrojanCockroach` | GITHUB | Zu alt: 328d |
| `NoDataFound/hackGPT` | GITHUB | Zu alt: 32d |
| `alvin-tosh/Malware-Exhibit` | GITHUB | Zu alt: 975d |
| `NYAN-x-CAT/Lime-RAT` | GITHUB | Zu alt: 2638d |
| `AHXR/ghost` | GITHUB | Zu alt: 1928d |
| `SaadAhla/FilelessPELoader` | GITHUB | Zu alt: 1111d |
| `aw-junaid/Hacking-Tools` | GITHUB | IP-Datei 691d alt |
| `mauri870/ransomware` | GITHUB | Zu alt: 2857d |
| `data-prep-kit/data-prep-kit` | GITHUB | IP-Datei 496d alt |
| `certsocietegenerale/fame` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aaaddress1/RunPE-In-Memory` | GITHUB | Zu alt: 1995d |
| `x86byte/RE-MA-Roadmap` | GITHUB | Zu alt: 346d |
| `mrexodia/dumpulator` | GITHUB | Zu alt: 954d |
| `KiExitDispatcher/GoDefender` | GITHUB | Zu alt: 277d |
| `strazzere/anti-emulator` | GITHUB | Zu alt: 2060d |
| `BushidoUK/Open-source-tools-for-CTI` | GITHUB | Zu alt: 217d |
| `LimerBoy/Adamantium-Thief` | GITHUB | Zu alt: 609d |
| `hdks-bug/exploitnotes` | GITHUB | Zu alt: 185d |
| `hasherezade/demos` | GITHUB | Zu alt: 1671d |
| `tarcisio-marinho/GonnaCry` | GITHUB | Zu alt: 597d |
| `SaturnsVoid/GoBot2` | GITHUB | Zu alt: 1815d |
| `cr-0w/maldev` | GITHUB | Zu alt: 121d |
| `r1cksec/cheatsheets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ossillate-inc/packj` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MinhasKamal/CuteVirusCollection` | GITHUB | Zu alt: 889d |
| `KiExitDispatcher/GoRedOps` | GITHUB | Zu alt: 504d |
| `hasherezade/process_doppelganging` | GITHUB | Zu alt: 1475d |
| `tijme/dittobytes` | GITHUB | Zu alt: 223d |
| `0xIslamTaha/Python-Rootkit` | GITHUB | Zu alt: 684d |
| `ncorbuk/Python-Ransomware` | GITHUB | Zu alt: 557d |
| `Cr4sh/SmmBackdoor` | GITHUB | Zu alt: 1070d |
| `Virus-Samples/Malware-Sample-Sources` | GITHUB | Zu alt: 2045d |
| `cryptwareapps/Malware-Database` | GITHUB | Zu alt: 207d |
| `ThomasThelen/Anti-Debugging` | GITHUB | Zu alt: 1720d |
| `Cr4sh/MicroBackdoor` | GITHUB | Zu alt: 1650d |
| `mstfknn/malware-sample-library` | GITHUB | Zu alt: 1027d |
| `scr34m/php-malware-scanner` | GITHUB | Zu alt: 81d |
| `EgeBalci/HERCULES` | GITHUB | Zu alt: 1883d |
| `AleksaMCode/WiFi-password-stealer` | GITHUB | Zu alt: 414d |
| `ujjwal-kr/system-programming-roadmap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CheckPointSW/InviZzzible` | GITHUB | Zu alt: 166d |
| `hasherezade/transacted_hollowing` | GITHUB | Zu alt: 919d |
| `NYAN-x-CAT/Lime-Crypter` | GITHUB | Zu alt: 874d |
| `dobin/avred` | GITHUB | Zu alt: 78d |
| `vysecurity/morphHTA` | GITHUB | Zu alt: 1248d |
| `SaumyajeetDas/GodGenesis` | GITHUB | Zu alt: 951d |
| `D3Ext/Hooka` | GITHUB | Zu alt: 621d |
| `Cr4sh/WindowsRegistryRootkit` | GITHUB | Zu alt: 3262d |
| `CalebFenton/dex-oracle` | GITHUB | Zu alt: 2735d |
| `danielpoliakov/lisa` | GITHUB | Zu alt: 1231d |
| `hackirby/skuld` | GITHUB | Zu alt: 641d |
| `hasherezade/malware_analysis` | GITHUB | Zu alt: 345d |
| `V1D1AN/S1EM` | GITHUB | Zu alt: 662d |
| `rf-peixoto/phishing_pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hagrid29/PELoader` | GITHUB | Zu alt: 1427d |
| `diStyApps/Safe-and-Stable-Ckpt2Safetensors-Conversion-Tool-GUI` | GITHUB | Zu alt: 1279d |
| `Squiblydoo/debloat` | GITHUB | Zu alt: 96d |
| `owasp-dep-scan/blint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CheckPointSW/Evasions` | GITHUB | Zu alt: 166d |
| `cristianzsh/freki` | GITHUB | Zu alt: 958d |
| `JustasMasiulis/nt_wrapper` | GITHUB | Zu alt: 2049d |
| `badchars/darknet-mcp-server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abdulkadir-gungor/JPGtoMalware` | GITHUB | Zu alt: 1549d |
| `ThreatLabz/ransomware_notes` | GITHUB | Zu alt: 31d |
| `EgeBalci/deoptimizer` | GITHUB | Zu alt: 783d |
| `0x25bit/Updated-Carbanak-Source-with-Plugins` | GITHUB | Zu alt: 2692d |
| `d4rksystem/VBoxCloak` | GITHUB | Zu alt: 436d |
| `zeropointdynamics/zelos` | GITHUB | Zu alt: 1321d |
| `aaaddress1/Windows-APT-Warfare` | GITHUB | Zu alt: 1148d |
| `crocodyli/ThreatActors-TTPs` | GITHUB | Zu alt: 227d |
| `D3Ext/maldev` | GITHUB | Zu alt: 662d |
| `ionescu007/Simpleator` | GITHUB | Zu alt: 2834d |
| `htr-tech/zphisher` | GITHUB | Zu alt: 753d |
| `skerkour/black-hat-rust` | GITHUB | Zu alt: 347d |
| `htr-tech/nexphisher` | GITHUB | Zu alt: 1432d |
| `Ignitetch/AdvPhishing` | GITHUB | Zu alt: 251d |
| `jaykali/maskphish` | GITHUB | Zu alt: 362d |
| `CrimsonForge-io/king-phisher` | GITHUB | Zu alt: 40d |
| `xlfe/cowrie2neo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AbdaullahAG/Threat_Intel_Project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `momenbasel/keyFinder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `six2dez/reconftw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AccentuSoft/LinkScope_Client` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nox-project/nox-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tg12/phantomtide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `its0x08/duckduckgo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atiilla/OsintEye` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hstsethi/in-mob-prefix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/xbox_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dgtlmoon/changedetection.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/lastfm_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/BuscaPaginasBlancas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zbetcheckin/Security_list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ElevenPaths/FOCA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rmusser01/Infosec_Reference` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomsec8/IntelHub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mantisfury/ArkhamMirror` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/steam_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sockysec/Telerecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lukeslp/antisocial` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `p1ngul1n0/blackbird` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hmaverickadams/DeHashed-API-Tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OSINTI4L/cupidcr4wl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yt-dlp/yt-dlp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `l4rm4nd/LinkedInDumper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s-rah/onionscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sbousseaden/EVTX-ATTACK-SAMPLES` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rough007/CCF-VM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microsoft/avml` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThreatResponse/margaritashotgun` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ForensicArtifacts/artifacts-kb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CrowdStrike/falcon-orchestrator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ufrisk/MemProcFS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JPCERTCC/LogonTracer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fox-it/acquire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `orlikoski/CyLR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `etsy/morgue` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ForensicArtifacts/artifacts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mkorman90/VolatilityBot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nogoodconfig/pyarascanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kacos2000/MFT_Browser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Invoke-IR/PowerForensics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aws-samples/aws-incident-response-runbooks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `viper-framework/viper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alpine-sec/SPECTR3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/munin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bad-antics/nullsec-linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rizinorg/rizin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `halpomeranz/lmg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cynative/cynative` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `forensicanalysis/artifactcollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uber-common/metta` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `certsocietegenerale/FIR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `504ensicsLabs/LiME` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ralphje/imagemounter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MagnetForensics/dumpit-linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dogoncouch/logdissect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CIRCL/traceroute-circl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `log2timeline/dftimewolf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/CIRTKit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NextronSystems/APTSimulator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/Raccine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DidierStevens/DidierStevensSuite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fox-it/dissect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mwielgoszewski/doorman` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gfoss/PSRecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jipegit/OSXAuditor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SekoiaLab/Fastir_Collector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zdhenard42/SOC-Multitool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spender-sandbox/cuckoo-modified` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `defpoint/threat_note` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frikky/Shuffle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/stenographer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yamato-Security/WELA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/timesketch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jymcheong/AutoTTP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deralexxx/security-apis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wagga40/Zircolite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diogo-fernan/domfind` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swisscom/PowerSponse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SwiftOnSecurity/sysmon-config` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Netflix-Skunkworks/diffy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MutableSecurity/mutablesecurity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mbevilacqua/appcompatprocessor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/RTA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `biggiesmallsAG/nightHawkResponse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mandiant/capa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `obsidianforensics/hindsight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `redhuntlabs/RedHunt-OS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `davehull/Kansa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SekoiaLab/Fastir_Collector_Linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre/caldera` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlmCo/Panorama` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `muteb/Hoarder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yelp/osxcollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PowerShellMafia/CimSweep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rough007/CDQR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TryCatchHCF/DumpsterFire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rizinorg/cutter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keydet89/RegRipper3.0` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `certsocietegenerale/IRM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swisscom/PowerGRR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AJMartel/IRTriage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `infosecn1nja/Red-Teaming-Toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chronicle/detection-rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trailofbits/presentations` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cisco/joy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sans-blue-team/DeepBlueCLI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/varna` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThreatHuntingProject/ThreatHunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splunk/salo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `palantir/alerting-detection-strategy-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corelight/zeek2es` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sysinternals/SysmonForLinux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yahoo/rdfp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zeek/zeek-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `austin-taylor/flare` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MHaggis/hunt-detect-prevent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:ochita/arcferrix-app-releases` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:black-fox-pl/blackfox_blocklist` | GITLAB | IP-Datei 36d alt |
| `gitlab:DanDawson/probeguard-404-firewall-cloudflare` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ClaudiusDecimius/IOCs` | GITHUB | IP-Datei 284d alt |
| `enhansome/enhansome-osint_stuff_tool_collection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nadhirmhdar/amlkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tanu-somani/Threat-Pulse-Frontend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DEEPESH-845/Aetheris` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Komaster12454/sdg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DanielSmith960416/Amryn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lukas-Beike/ai-coach` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mikev-lab/eidolon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `srivastavaayush084/NIDS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CrowdRelay/crowdrelay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maux339-cpu/exploits` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KyojurosBestFan/risk-net-catalog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `as7er/vcfm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dakrkakashi/FoodLine-Campus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ananthuganesh/server-setup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `APKiwiOrg/KhaozEngine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Symbifox/odoo-modules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AdityaSingh910/invoice-processing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mjaksn/nettail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BNIX-VN/bpanel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ruham06/wazuh-soc-home-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jiretaLendingCorp/jireta_loans` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dancan254/log-guard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GlazyKahito/scamshield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thanhtai21/airgeddon-vietnamese` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bestwade22/polymarket-trader` | GITHUB | Größe: 0 IPs |
| `Advay254/Adv-HeartCode` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carlosguzmanfunez/punto-ai-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `justrach/folio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `phantasm-elated8/Usagi-Shima-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aws-samples/sample-multi-agent-procure-to-pay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Maha-Strategies/maha-corp-web` | GITHUB | Größe: 0 IPs |
| `Varad0506/Apex_Guard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bpmcginley/PredictionEdge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Roy1223334444/zamud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mouni-16102006/hiver-sde-ai-support-agent-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carolisengineering/kingdom-keys` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `haomingkoo/puffing-billy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dbrckk/xbow-perso` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ShivrajB17/Crypto_Transaction_Tracker-Terminal-Application-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elmorshedy-del/TrumpNumbers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheVicky1/Pact_OS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wasif-exe/lsm-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yousefjan2007-crypto/solana_screener` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `canopies-jiggered-29/Slotbound-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dxnishG/AWS-Multi-Env-Terraform-Template` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `giuseppemineo685-beep/atlantis-polymarket-screening` | GITHUB | Größe: 0 IPs |
| `notices-barren495/ZWAARD-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abhinavkishor9/sentinel-lab-02-password-spray-detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aryavartsubhammoharana/ZeroBinary_LifeRPG` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `btclib-org/.github` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Liang-techh/OpenAI-NS-Velocity-Field-Reconstruction` | GITHUB | Größe: 0 IPs |
| `payamtaabodiii/Scann` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yousefjan2007-crypto/robinhood-screener` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sandrikkk/real-estate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `huyrick/phish-guardian-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `munavathvijay00-spec/Forgery-Detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aryanpancharya-hub/ganesh-chaturthi-antigravity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joaoarapucas/ice-breaker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `copings648257lasing/Cleaner-Company-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rkclayton/AgentB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sandeepsmile390/CampusOs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shivesh2334-ai/ogacare-competitor-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benabdinadama-hash/mvs-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zapplyjobs/Canada-Jobs-2027` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skimp-vetch-74610/Bennys-Backrooms-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cauldr0nx/flyPaper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nandha3d/kpsta` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mix-Mate/Mix-Mate_web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wizhardhacker1/HIVE-SECURITY` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abdurrehmansajidhafiz1-cell/trading-scanner-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `silent9669/LegalIR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SamantroyAcademy/Website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `krishnatsunku-droid/bangalore-Housing-map` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `athishio/Meikural` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 27,912 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,504 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 8,495 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 11,333 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,842 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,649 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,761 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,897 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,952 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,166 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 2,700 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 1,810 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,171 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 716 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 725 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 586 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 324 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 53,919 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,551 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 17,289 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,209 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,683 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,923 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,195 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 210,842 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,738 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 4,045 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,646 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 124,129 | 0.1% | 1560 | 2026-08-01 |
| `hookzof_socks5_list` | GITHUB | 151 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,698 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 11,379 | 64.3% | 938 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 52,853 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,764 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,835 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 116,467 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 91,296 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,889 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 91,496 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 105,171 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,721 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 120,267 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,468 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 119,002 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 610 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 481,199 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,248 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 172,080 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 168,191 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 138,822 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 136,219 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 101,966 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 120,755 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 95,436 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 220,105 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 59,117 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 162,301 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 34,109 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 24,721 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,360 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 21,182 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 19,249 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 37,750 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 12,606 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,675 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 5,864 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 19,347 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 12,346 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,459 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 10,236 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 6,748 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,218 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 11,042 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 5,116 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,571 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 2,777 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,447 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,144 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,703 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,960 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 90,591 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,529 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 895 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 49,832 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,640 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,989 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 2,190 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,233 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 84,893 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 280,706 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 7,513 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 6,122 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 7,128 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,437 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 30 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 89,175 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 97,925 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,487 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 106 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 228,095 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,474 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,718 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 181 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 15,866 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 15,866 | 76.5% | 3 | 2026-08-09 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,063 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,923 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 18,345 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,340 | 31.1% | 1 | 2026-07-14 |
| `fwahyui_masifa_ipblacklist` | GITHUB | 126,973 | 91.7% | 1 | 2026-08-16 |
| `idleadmin_threatfeed` | GITHUB | 54,999 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 59,963 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,707 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 127,053 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 348 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,168 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 194,533 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,534 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 123,862 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 177,233 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,237 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 32,986 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 20,700 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 16,927 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,731 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 8,679 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,664 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,644 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,510 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 5,000 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,763 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,122 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,533 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 4,059 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,850 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 3,111 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,103 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,304 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,339 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,353 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,295 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,240 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 973 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,131 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,381 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,103 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,385 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 659 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,454 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,846 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,227 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 11,587 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 91,976 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 91,913 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 86,412 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 94,397 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 94,336 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 92,121 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 89,045 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 22,482 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 46,132 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 12,492 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,804 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,382 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,840 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 43,367 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 21,205 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 13,168 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 6,231 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 47 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 26,460 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 134,621 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 21,928 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,615 | 5.1% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,026 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,047 | 9.3% | 0 | 2026-09-13 |

---
*Generiert: 2026-09-13 08:03 CEST (Europe/Berlin)*