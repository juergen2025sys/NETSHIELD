# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-24 23:14 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 6 |
| Kandidaten gesamt | **11753** |
| davon GitHub (Topics+Code) | **11663** |
| davon GitLab | **90** |
| davon Awesome-Lists | **2202** |
| Tools/Libraries vor Eval gefiltert | **902** |
| davon Hard-Reject (awesome-Liste etc.) | **193** |
| EVAL-Kandidaten (nach Stratifizierung) | **456** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **456** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **455** |
| Neu angenommene Feed-Dateien | **2** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **190** |
| Abgelehnte Repositories (dieser Run) | **455** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **192** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **163091** |
| SQLite-Refresh-Cache-Hits | **188/190** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **246** |
| Repo zu alt (>30d) | **196** |
| Falsche Größe (<30 / >2,000,000 IPs) | **10** |
| IP-Datei veraltet (>30d) | **3** |
| Sonstige | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `ziyadnz_threat_intel_ip_feeds_blacklist_full` | [ziyadnz/threat-intel-ip-feeds](https://github.com/ziyadnz/threat-intel-ip-feeds) | GITHUB | 129,811 | 49.1% | 0.0% | 8 | 🆕 NEU |
| `configserverapps_service_blocklists_threat_intelligence` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 61,038 | 41.0% | 0.0% | 10 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `lion-gu/ioc-explorer` | GITHUB | Zu alt: 2401d |
| `cisco-joe/Intel-CoralPalace` | GITHUB | Zu alt: 841d |
| `phl0/MMDVM_HS_Dual_Hat` | GITHUB | Zu alt: 2167d |
| `bwack/KU-14194HB-RevB-KiCad` | GITHUB | Zu alt: 1762d |
| `kf0jvt/sonyhack` | GITHUB | Zu alt: 4116d |
| `zhaoj8333/data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `agkaminski/Pocket265` | GITHUB | Zu alt: 1103d |
| `svaksha/pythonidae` | GITHUB | Zu alt: 1178d |
| `piwko28/smart-home-ebus-adapter` | GITHUB | Zu alt: 717d |
| `spiritLHLS/speedtest.net-CN-ID` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DiscoStarslayer/XOSVP` | GITHUB | Zu alt: 2217d |
| `subpos/subpos_node` | GITHUB | Zu alt: 3884d |
| `Jana-Marie/USB-LED-Otter` | GITHUB | Zu alt: 2469d |
| `staticintlucas/goldfish` | GITHUB | Zu alt: 289d |
| `sarnesjo/nearness` | GITHUB | Zu alt: 2432d |
| `sawaiz/artDecoEarrings` | GITHUB | Zu alt: 2337d |
| `citrus3000psi/Time-Sleuth` | GITHUB | Zu alt: 2019d |
| `rand-tech/GCC_IoT_research` | GITHUB | Zu alt: 1316d |
| `polpo/imagescribbler` | GITHUB | Zu alt: 564d |
| `Rich-Nelson/voron-stealthchanger-cmyk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `isaac879/2.5W-laser-gun` | GITHUB | Zu alt: 2760d |
| `Miceuz/PlantWateringAlarm` | GITHUB | Zu alt: 1206d |
| `oskitone/four-step-octaved-sequencer` | GITHUB | Zu alt: 196d |
| `rnplus/ESP8266-RELAYBOARD-V1` | GITHUB | Zu alt: 3856d |
| `lucedoriente/TI99-4A-internal-TIPI` | GITHUB | Zu alt: 896d |
| `hiddendevj/JDPackage` | GITHUB | Zu alt: 1753d |
| `adamm/starman` | GITHUB | Zu alt: 273d |
| `rishiktiwari/powerbaby-100` | GITHUB | Zu alt: 380d |
| `xiaoli110/kvm_vm_setup` | GITHUB | Zu alt: 4056d |
| `GalaxyGamingBoy/6502-Microcontroller` | GITHUB | Zu alt: 406d |
| `AliRazaLilani/RandomForest-Thesis` | GITHUB | Zu alt: 849d |
| `ChartreuseK/ch375serial` | GITHUB | Zu alt: 799d |
| `geodezjafan/IOCs` | GITHUB | Zu alt: 646d |
| `biomimetics/imageproc_pcb` | GITHUB | Zu alt: 4537d |
| `KipJM/blackmacro-hardware` | GITHUB | Zu alt: 32d |
| `mathisschmieder/MMDVM_RPT_Hat` | GITHUB | Zu alt: 2187d |
| `marshallh/gbpp` | GITHUB | Zu alt: 1306d |
| `aliqut/3xosc` | GITHUB | Zu alt: 430d |
| `Hanz-Tech/midi-adapter-hardware` | GITHUB | Zu alt: 2065d |
| `Astralis1409/VikramSat-RF-subsystem` | GITHUB | Zu alt: 404d |
| `Pegoku/Sunlu-S1-Board` | GITHUB | Zu alt: 228d |
| `briandorey/RaspberryPiBarcodeScanner` | GITHUB | Zu alt: 3328d |
| `woile/aws-cert` | GITHUB | Zu alt: 1991d |
| `rares9301/Proiect-TSC` | GITHUB | Zu alt: 160d |
| `4ryanwalia/Phishing-detection` | GITHUB | Zu alt: 230d |
| `8BitMixtape/mCore_Mixtape` | GITHUB | Zu alt: 2959d |
| `PatrickBaus/LT3045_breakout` | GITHUB | Zu alt: 3087d |
| `felix-myrie/USBean` | GITHUB | Zu alt: 96d |
| `danushk97/my_curl` | GITHUB | Zu alt: 1540d |
| `karandev79/Qein-X1A-Pro` | GITHUB | Zu alt: 140d |
| `jcolag/AutoStory` | GITHUB | Zu alt: 2252d |
| `Nadoooor/SnakeHome` | GITHUB | Zu alt: 78d |
| `TKontu/ltc4368-2s-protector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LtBrain/MuBook` | GITHUB | Zu alt: 407d |
| `NEOgHacking/Keyboadr` | GITHUB | Zu alt: 176d |
| `CubeShifter/flappy-birb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sandgum/Triangulate-SF_01-Speaker-Frame` | GITHUB | Zu alt: 49d |
| `YoussefAymanJo/Hubbly` | GITHUB | Zu alt: 112d |
| `bcancinov/4-channel-adc-module` | GITHUB | Zu alt: 463d |
| `Sadrita404/Hack-Boat` | GITHUB | Zu alt: 52d |
| `AinaSnow/FFXIV-Datamining` | GITHUB | Zu alt: 786d |
| `Mineinjava/ffellowship` | GITHUB | Zu alt: 460d |
| `wenbang24/volt` | GITHUB | Zu alt: 436d |
| `eduardofilo/RG350_auto_ra_installer` | GITHUB | Zu alt: 631d |
| `tharejarehan0-a11y/Fleeboard` | GITHUB | Zu alt: 106d |
| `mayermakes/MyGenWashy` | GITHUB | Zu alt: 257d |
| `Keyaan-07/shen` | GITHUB | Zu alt: 34d |
| `bunnypranav/echoIR` | GITHUB | Zu alt: 128d |
| `sarthakmmishra/macropad` | GITHUB | Zu alt: 76d |
| `dialgorithm/anorith` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `westfoxtrot/cypher_pcb` | GITHUB | Zu alt: 1510d |
| `NeerajR18/version-dongle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cloudglides/apex` | GITHUB | Zu alt: 100d |
| `jnematli/GS3440-Adaptive-cable-equalizer` | GITHUB | Zu alt: 723d |
| `dialgorithm/tilt` | GITHUB | Zu alt: 51d |
| `Roboy/m3` | GITHUB | Zu alt: 2048d |
| `EngThi/Edge-Nexus` | GITHUB | Zu alt: 109d |
| `shashwtd/keystorm-x3` | GITHUB | Zu alt: 75d |
| `enishyseni/pcbdesign` | GITHUB | Zu alt: 193d |
| `NaiveTomcat/8-bitcomputer-from-scratch` | GITHUB | Zu alt: 2324d |
| `adhdproject/spidertrap` | GITHUB | Zu alt: 2283d |
| `cbuijs/hagezi` | GITHUB | Identischer Inhalt wie configserverapps_service_blocklists_blocklist |
| `KnisterPeter/tsdi` | GITHUB | Zu alt: 1032d |
| `phantom0004/morpheus_IOC_scanner` | GITHUB | Zu alt: 589d |
| `OsmanKandemir/web-wordlist-generator` | GITHUB | Zu alt: 851d |
| `assafkip/huntkit` | GITHUB | IP-Datei 162d alt |
| `bdqfork/festival` | GITHUB | Zu alt: 2396d |
| `blacktop/docker-yara` | GITHUB | Zu alt: 1452d |
| `0xDanielLopez/TweetFeed_code` | GITHUB | Zu alt: 1403d |
| `inversiland/inversiland` | GITHUB | Zu alt: 644d |
| `byme8/ZeroIoC` | GITHUB | Zu alt: 492d |
| `sergeysychov/behaviour_inject` | GITHUB | Zu alt: 1103d |
| `aloisdeniel/dioc` | GITHUB | Zu alt: 2347d |
| `Washi1337/cilfi` | GITHUB | Zu alt: 50d |
| `red-gold/ts-ui` | GITHUB | Zu alt: 840d |
| `jacoborus/wiremap` | GITHUB | Zu alt: 263d |
| `wenbo2018/mini-springframework` | GITHUB | Zu alt: 3182d |
| `FarseerNet/Farseer.Net` | GITHUB | Zu alt: 1301d |
| `imnbwd/FriendEditor` | GITHUB | Zu alt: 3478d |
| `iorate/ublacklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ruddernation-Designs/Adobe-URL-Block-List` | GITHUB | Zu alt: 105d |
| `marteinn/The-Big-Username-Blocklist` | GITHUB | Zu alt: 1807d |
| `DavidMoore/ipfilter` | GITHUB | Zu alt: 237d |
| `ipverse/as-ip-blocks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `equk/windows` | GITHUB | Zu alt: 674d |
| `djkurlander/knock-knock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qundao/mirror-softcnkiller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `momenbasel/puresnitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gardenfence/blocklist` | GITHUB | Zu alt: 46d |
| `Paxxs/Google-Blocklist` | GITHUB | Zu alt: 423d |
| `greyhat-academy/lists.d` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mhxion/pornaway` | GITHUB | Zu alt: 872d |
| `Reginald-Gillespie/Spotify-AI-Band-Blocker` | GITHUB | Zu alt: 57d |
| `blockadeio/chrome_extension` | GITHUB | Zu alt: 2118d |
| `WaGi-Coding/WaGis-Mass-IP-Blacklister-Windows` | GITHUB | Zu alt: 873d |
| `sun-lite/firewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DWW256/distracting-websites` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sundowndev/phoneinfoga` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qcod/laravel-gamify` | GITHUB | Zu alt: 38d |
| `trustgraph/trustgraph` | GITHUB | Zu alt: 693d |
| `beyondtahir/beyondseo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johannchopin/stackoverflow-readme-profile` | GITHUB | Zu alt: 678d |
| `ansezz/laravel-gamify` | GITHUB | Zu alt: 1962d |
| `e-m3din4/deep-email` | GITHUB | Zu alt: 1282d |
| `givepraise/praise` | GITHUB | Zu alt: 710d |
| `arian-gogani/nobulex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `interep-project/reputation-service` | GITHUB | Zu alt: 1245d |
| `rainbowdashlabs/reputation-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenNewsLabs/autoEdit_2` | GITHUB | Zu alt: 935d |
| `linux-msm/qdl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Giovix92/EDLUnlock` | GITHUB | Zu alt: 1941d |
| `thefirefox12537/qctools_tff` | GITHUB | Zu alt: 1495d |
| `Alephgsm/SAMSUNG-EDL-Loaders` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `strongtz/edl-ng` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alephgsm/SAM-unbrick-debrick` | GITHUB | Zu alt: 947d |
| `AdaUnlocked/OnePlus-9008-JiuZhuan-Guide` | GITHUB | Zu alt: 250d |
| `HadiKhoirudin/Qualcomm-Tool` | GITHUB | Zu alt: 962d |
| `tamm2904/MTFLASH_UBL_SNAPDRAGON` | GITHUB | Zu alt: 114d |
| `HadiKhoirudin/Qualcomm-Tool-GUI` | GITHUB | Zu alt: 1387d |
| `Red5d/edlkit` | GITHUB | Zu alt: 942d |
| `Mrivai/Xiaomi-Service-Tool` | GITHUB | Zu alt: 1467d |
| `CosmicDan-Android/MiA1LowLevelBackupRestoreTool` | GITHUB | Zu alt: 1665d |
| `yuriskinfo/cheat-sheets` | GITHUB | Zu alt: 88d |
| `prometheus-community/fortigate_exporter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheTaylorLee/AdminToolbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yuriskinfo/Fortinet-tools` | GITHUB | Zu alt: 38d |
| `FortiPower/PowerFGT` | GITHUB | Zu alt: 267d |
| `fortinet/fortigate-terraform-deploy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fortinet-solutions-cse/fortiosapi` | GITHUB | Zu alt: 1315d |
| `mbdraks/fortinet-zabbix` | GITHUB | Zu alt: 1555d |
| `fortinet/4D-Demo` | GITHUB | Zu alt: 76d |
| `40net-cloud/fortinet-azure-solutions` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fortinet-solutions-cse/40ansible` | GITHUB | Zu alt: 2413d |
| `alextibor/wazuh-fortigate-rules-decoders` | GITHUB | Zu alt: 912d |
| `mbdraks/gatepy` | GITHUB | Zu alt: 2803d |
| `bl4ko/netbox-ssot` | GITHUB | Größe: 0 IPs |
| `angela-d/brain-dump` | GITHUB | Zu alt: 152d |
| `AsBuiltReport/AsBuiltReport.Fortinet.FortiGate` | GITHUB | Zu alt: 298d |
| `Tufin/pytos` | GITHUB | Zu alt: 679d |
| `ondrejholecek/sniftran` | GITHUB | Zu alt: 211d |
| `N4SOC/fortilogcsv` | GITHUB | Zu alt: 304d |
| `noways-io/fortigate-crypto` | GITHUB | Zu alt: 934d |
| `signorrayan/Splunk-Threat-Hunting` | GITHUB | Zu alt: 1519d |
| `fortinet/fortios-ips-snort` | GITHUB | Zu alt: 623d |
| `gdoornenbal/dehydrated-certificate-installers` | GITHUB | Zu alt: 2292d |
| `akshaymane920/pyFortimanagerAPI` | GITHUB | Zu alt: 180d |
| `fortinet-solutions-cse/fortistacks` | GITHUB | Zu alt: 726d |
| `kljunowsky/CVE-2023-36845` | GITHUB | Zu alt: 1000d |
| `mytechnotalent/Reverse-Engineering` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `screetsec/TheFatRat` | GITHUB | Zu alt: 921d |
| `volatilityfoundation/volatility` | GITHUB | Zu alt: 496d |
| `ayoubfaouzi/al-khaser` | GITHUB | Zu alt: 85d |
| `CalebFenton/simplify` | GITHUB | Zu alt: 1608d |
| `volatilityfoundation/volatility3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kevoreilly/CAPEv2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lifka/hacking-resources` | GITHUB | Zu alt: 821d |
| `Ch0pin/medusa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mattnotmax/cyberchef-recipes` | GITHUB | Zu alt: 832d |
| `JustasMasiulis/lazy_importer` | GITHUB | Zu alt: 1148d |
| `fabrimagic72/malware-samples` | GITHUB | Zu alt: 1835d |
| `zeustrojancode/Zeus` | GITHUB | Zu alt: 2116d |
| `jvoisin/php-malware-finder` | GITHUB | Zu alt: 1070d |
| `openclarity/openclarity` | GITHUB | Zu alt: 122d |
| `cecio/USBvalve` | GITHUB | Zu alt: 36d |
| `MinhasKamal/TrojanCockroach` | GITHUB | Zu alt: 339d |
| `NoDataFound/hackGPT` | GITHUB | Zu alt: 43d |
| `alvin-tosh/Malware-Exhibit` | GITHUB | Zu alt: 986d |
| `JusticeRage/Manalyze` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NYAN-x-CAT/Lime-RAT` | GITHUB | Zu alt: 2649d |
| `AHXR/ghost` | GITHUB | Zu alt: 1939d |
| `SaadAhla/FilelessPELoader` | GITHUB | Zu alt: 1122d |
| `0x6rss/matkap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aw-junaid/Hacking-Tools` | GITHUB | Zu alt: 36d |
| `mauri870/ransomware` | GITHUB | Zu alt: 2868d |
| `data-prep-kit/data-prep-kit` | GITHUB | IP-Datei 507d alt |
| `certsocietegenerale/fame` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aaaddress1/RunPE-In-Memory` | GITHUB | Zu alt: 2006d |
| `x86byte/RE-MA-Roadmap` | GITHUB | Zu alt: 357d |
| `mrexodia/dumpulator` | GITHUB | Zu alt: 965d |
| `KiExitDispatcher/GoDefender` | GITHUB | Zu alt: 288d |
| `strazzere/anti-emulator` | GITHUB | Zu alt: 2071d |
| `BushidoUK/Open-source-tools-for-CTI` | GITHUB | Zu alt: 228d |
| `hdks-bug/exploitnotes` | GITHUB | Zu alt: 196d |
| `LimerBoy/Adamantium-Thief` | GITHUB | Zu alt: 620d |
| `marcocesarato/PHP-Antimalware-Scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tarcisio-marinho/GonnaCry` | GITHUB | Zu alt: 608d |
| `SaturnsVoid/GoBot2` | GITHUB | Zu alt: 1826d |
| `cr-0w/maldev` | GITHUB | Zu alt: 132d |
| `r1cksec/cheatsheets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ossillate-inc/packj` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MinhasKamal/CuteVirusCollection` | GITHUB | Zu alt: 900d |
| `KiExitDispatcher/GoRedOps` | GITHUB | Zu alt: 515d |
| `0xIslamTaha/Python-Rootkit` | GITHUB | Zu alt: 695d |
| `ncorbuk/Python-Ransomware` | GITHUB | Zu alt: 568d |
| `Cr4sh/SmmBackdoor` | GITHUB | Zu alt: 1081d |
| `Virus-Samples/Malware-Sample-Sources` | GITHUB | Zu alt: 2056d |
| `cryptwareapps/Malware-Database` | GITHUB | Zu alt: 218d |
| `ThomasThelen/Anti-Debugging` | GITHUB | Zu alt: 1731d |
| `Cr4sh/MicroBackdoor` | GITHUB | Zu alt: 1661d |
| `mstfknn/malware-sample-library` | GITHUB | Zu alt: 1038d |
| `scr34m/php-malware-scanner` | GITHUB | Zu alt: 92d |
| `AleksaMCode/WiFi-password-stealer` | GITHUB | Zu alt: 425d |
| `EgeBalci/HERCULES` | GITHUB | Zu alt: 1894d |
| `ujjwal-kr/system-programming-roadmap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CheckPointSW/InviZzzible` | GITHUB | Zu alt: 177d |
| `NYAN-x-CAT/Lime-Crypter` | GITHUB | Zu alt: 885d |
| `dobin/avred` | GITHUB | Zu alt: 89d |
| `CybercentreCanada/assemblyline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SaumyajeetDas/GodGenesis` | GITHUB | Zu alt: 962d |
| `vysecurity/morphHTA` | GITHUB | Zu alt: 1259d |
| `D3Ext/Hooka` | GITHUB | Zu alt: 632d |
| `CalebFenton/dex-oracle` | GITHUB | Zu alt: 2746d |
| `Cr4sh/WindowsRegistryRootkit` | GITHUB | Zu alt: 3273d |
| `diogo-fernan/ir-rescue` | GITHUB | Zu alt: 2041d |
| `danielpoliakov/lisa` | GITHUB | Zu alt: 1242d |
| `hackirby/skuld` | GITHUB | Zu alt: 652d |
| `rf-peixoto/phishing_pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `V1D1AN/S1EM` | GITHUB | Zu alt: 673d |
| `badchars/darknet-mcp-server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diStyApps/Safe-and-Stable-Ckpt2Safetensors-Conversion-Tool-GUI` | GITHUB | Zu alt: 1290d |
| `andrew-morris/kippo_detect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERT-Polska/hsn2-bundle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ziemeck/bifrozt-ansible` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `upa/ofpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/manuka` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ncouture/MockSSH` | GITHUB | Größe: 0 IPs |
| `madirish/kojoney2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sjhilt/GasPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christophe77/node-ftp-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `traetox/sshForShits` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeremyfritzen/Ethereum-honey-pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shbhmsingh72/Honeypot-Research-Papers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MattCarothers/mhn-core-docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magisterquis/vnclowpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jedie/django-kippo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corkami/pics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aol/moloch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kevthehermit/VolUtility` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jnraber/VirtualDeobfuscator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `malwaremusings/unpacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `katjahahn/PortEx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/AnalyzePDF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tklengyel/drakvuf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/NoMoreXOR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `williballenthin/EVTXtract` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joxeankoret/pyew` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `guelfoweb/peframe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omriher/CapTipper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nbeede/BoomBox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/flare-vm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BinaryAnalysisPlatform/bap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `9b/pdfxray_lite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/IPinfo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/AnalyzePE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `extremecoders-re/pyinstxtractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NtQuery/Scylla` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gurnec/HashCheck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `detuxsandbox/detux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ANSSI-FR/polichombr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rurik/Java_IDX_Parser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vmt/udis86` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tencent/HaboMalHunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diogo-fernan/malsub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomchop/unxor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bwall/bamfdetect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keydet89/RegRipper2.8` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rocky/python-uncompyle6` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uppusaikiran/yara-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `9b/malpdfobj` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/malwarehouse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OMENScan/AChoir` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hempnall/broyara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `micheloosterhof/cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `unipacker/unipacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `merces/aleph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sooshie/packerid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uppusaikiran/generic-parser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BromiumLabs/PackerAttacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vduddu/Malware` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `michael-yip/MaltegoVT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `longld/peda` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keithjjones/fileintel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crypto2011/IDR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `radareorg/cutter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uppusaikiran/malware-organiser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `airbnb/binaryalert` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbremer/httpreplay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sleuthkit/scalpel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LordNoteworthy/al-khaser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ch3k1/squidmagic` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `504ensicsLabs/DAMM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/capa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmersonElectricCo/boomerang` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KoreLogicSecurity/mastiff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `horsicq/Detect-It-Easy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lmco/laikaboss` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbremer/sflock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ShaneK2/inVtero.net` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johnnykv/mnemosyne` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `simsong/bulk_extractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sketchymoose/TotalRecall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `moyix/panda` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rieck/malheur` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/binnavi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rjhansen/nsrllookup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pidydx/SMRT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Visgean/Zeus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `angr/angr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sycurelab/DECAF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `robbyFux/Ragpicker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `monnappa22/Limon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xd4d/dnSpy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vstinner/hachoir3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x64dbg/ScyllaHide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `plasma-disassembler/plasma` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `F-Secure/see` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RamadhanAmizudin/python-icap-yara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aim4r/VolDiff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pidydx/PyIOCe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Defense-Cyber-Crime-Center/DC3-MWCP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mateuszk87/PcapViz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keithjjones/visualize_logs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `season-lab/bluepill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Storyyeller/Krakatau` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RPISEC/Malware` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Konloch/bytecode-viewer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/flare-fakenet-ng` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FGRibreau/mailchecker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `williballenthin/python-evt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hurricanelabs/machinae` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Karneades/malware-persistence` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keithjjones/cuckoo-modified-api` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/stringsifter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cmu-sei/pharos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brad-accuvant/cuckoo-modified` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `programa-stic/barf-project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HynekPetrak/javascript-malware-collection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `secretsquirrel/recomposer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellman/xortool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmersonElectricCo/fsf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `medissaoui711/AegisVerify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `whsiano/whsiano` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cloudisoft/ShivanshConnect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shanemcd/headroom-helm` | GITHUB | Größe: 0 IPs |
| `PS12007/LazyKV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GoalIQ/football-prediction` | GITHUB | Größe: 0 IPs |
| `Merlin1A/resecta` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ericksonlopezf/dotnet-idempotency` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `danny-hines/sparkade` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shahnazesha/Datasets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jerzy99jerzy/air-alert-early-warning` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `logiqed/LogiQED` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `werriesjacob1-cmyk/Full-Count` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MattJColes/lgtmaybe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DhanuJay4/Phishing-Email-Analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Abdirashid-Fahiye/LogSentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `natantadeu58-alt/live-host-triage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TiloBuechsenschuss/userscripts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mroconnell/rtr-deeplink` | GITHUB | Größe: 0 IPs |
| `elliotwutingfeng/aegis-backup-decryptor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Conscious-Repository/manifest` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TegarTheGreat/Agentium` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `isixmartins-hub/MobaXterm-Portable` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manou-crypto/Librairie-Numerique` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tag1consulting/jesse-app` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `francescomucio/hermes-deploy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sundries-634galling/INTERNS-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `a11ign/a11ign` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `propound294936-wanders/Secret-Glory-Hole-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Achmed06/Frontline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rufat325/heldfast` | GITHUB | Größe: 0 IPs |
| `autobleem2/autobleem` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ponnala6435/Burp-Suite-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fidokuba/Go-Invoicing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shahbazimasoud/Net-Management` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HPTarkk/Tark` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spcl/HPCAgent-Bench` | GITHUB | Größe: 0 IPs |
| `adamliq/catscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `piraci26/iq-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `adankhalid0/network-security-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Stuey3D/VibeSDR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bromenie2026-commits/Cointracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `openclaw/openclaw-windows-packaging` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SairamBhargav/CareerDeck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benxy031/Gap_miner_v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hostelry-50-bristled/Abyss-Hunter-Lust-Awakening-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aguttedar/lbj-punchlist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `glazeenjoy65170/Elven-Watcher-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tuns-4579-wapitis/ASCENDANT-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carlosguzmanfunez/punto-ai-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yauneyz/snorlax` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rahanahu/wgft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `edorfanini00/revivex-launch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kqbmvx/iptables-blocklist` | GITHUB | Größe: 0 IPs |
| `TheMarco/liminal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ppfenning/coxswain-graphs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jamie05351/SiphonDSP_J` | GITHUB | IP-Datei 80d alt |
| `avers2604/Gup-2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `duelingquillsmedia/browser-game` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `postmillennium-MTB/MTB-PATENT-ATLAS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `youcangetjules/geofooter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `harrison-chinonso/realx8-core` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `heydrsubha-del/SMART-INDIA-HACKATHON-PROJECT-26106` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ErudaRobiu/numbered-accordion-elementor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benjaminbayerpriv-cmd/jarvis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `juhwan7/stock-autoresearch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `liberals-alga-164610/DDoD-Beta-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dhruvv1402/penumbra-nids` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Felipecostaa95/Pauta` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `99epep/dada-engine-solver` | GITHUB | Größe: 0 IPs |
| `Dtwosam/Shreks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `YorenZZZ/obsidian-reminders` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-microbit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `perfidy-joke8633/Goon-Bar-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bankroll10/Somali-marriage-app` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gigolajulian/juliangigola-com` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RTPMai/alliteration` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JadeSure/bargain-hunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eventosento-creator/ENPASS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `colonels7juncoes/Gundam-Rogue-Orbit-Prototype-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jb155/music-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cryptocomiks/KBC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WZCasper/NeuroBoost` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `toma86hawk/technocore-flop-japan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2bulldawg14/token-watch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `r3sbarra/ec-dt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PropertyServices/Fair-property-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SPOTLESS1998/ejentic-agents` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nickspiker/photon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `weix112233/sub2api-r3-duokai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `getknit/knit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexharper24/blessyourpaws-website-repo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `youngwolf2077-a11y/gmail-postmaster-tools-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yookiop/SteamDataOfficial` | GITHUB | Größe: 0 IPs |
| `DopestT/Let-Me-Teach-You-AI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mahmoud-Hashim-pro/cognify-production` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

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
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 11,664 | 64.3% | 938 | 2026-09-04 |
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

---
*Generiert: 2026-09-24 23:14 CEST (Europe/Berlin)*