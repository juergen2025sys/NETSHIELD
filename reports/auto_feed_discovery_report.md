# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-25 12:04 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **11804** |
| davon GitHub (Topics+Code) | **11714** |
| davon GitLab | **90** |
| davon Awesome-Lists | **2195** |
| Tools/Libraries vor Eval gefiltert | **934** |
| davon Hard-Reject (awesome-Liste etc.) | **205** |
| EVAL-Kandidaten (nach Stratifizierung) | **399** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **399** |
| davon angenommene Repositories | **3** |
| davon abgelehnte Repositories | **396** |
| Neu angenommene Feed-Dateien | **6** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **193** |
| Abgelehnte Repositories (dieser Run) | **396** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **199** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **161266** |
| SQLite-Refresh-Cache-Hits | **34/203** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **195** |
| Repo zu alt (>30d) | **181** |
| IP-Datei veraltet (>30d) | **12** |
| Falsche Größe (<30 / >2,000,000 IPs) | **8** |
| Sonstige | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `claudiusdecimius_threatfox` | [ClaudiusDecimius/ThreatFox](https://github.com/ClaudiusDecimius/ThreatFox) | GITHUB | 26,397 | 1.5% | 0.0% | 0 | 🆕 NEU |
| `zikmadol_trapline_ioc` | [Zikmadol/trapline-ioc](https://github.com/Zikmadol/trapline-ioc) | GITHUB | 838 | 84.6% | 0.0% | 0 | 🆕 NEU |
| `zikmadol_trapline_ioc_indicators` | [Zikmadol/trapline-ioc](https://github.com/Zikmadol/trapline-ioc) | GITHUB | 829 | 84.4% | 0.0% | 0 | 🆕 NEU |
| `zikmadol_trapline_ioc_2026_09_20` | [Zikmadol/trapline-ioc](https://github.com/Zikmadol/trapline-ioc) | GITHUB | 183 | 92.3% | 0.0% | 0 | 🆕 NEU |
| `zikmadol_trapline_ioc_ai_infra` | [Zikmadol/trapline-ioc](https://github.com/Zikmadol/trapline-ioc) | GITHUB | 182 | 76.9% | 0.0% | 0 | 🆕 NEU |
| `zikmadol_trapline_ioc_2026_09_24` | [Zikmadol/trapline-ioc](https://github.com/Zikmadol/trapline-ioc) | GITHUB | 157 | 90.4% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `yasirhamza/AndroDR` | GITHUB | IP-Datei 51d alt |
| `iss4cf0ng/OpenPetya` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `A-poc/BlueTeam-Tools` | GITHUB | Zu alt: 33d |
| `HalilDeniz/RansomwareSim` | GITHUB | Zu alt: 847d |
| `demisto/content` | GITHUB | IP-Datei 204d alt |
| `openwrt/packages` | GITHUB | IP-Datei 897d alt |
| `blaCCkHatHacEEkr/PENTESTING-BIBLE` | GITHUB | Zu alt: 1271d |
| `A-poc/RedTeam-Tools` | GITHUB | Zu alt: 160d |
| `carbonblack/cbfeeds` | GITHUB | Zu alt: 1270d |
| `OpenCTI-Platform/connectors` | GITHUB | IP-Datei 308d alt |
| `alexandreborges/malwoverview` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SpecterOps/at-ps` | GITHUB | Zu alt: 2438d |
| `cporter202/API-mega-list` | GITHUB | Zu alt: 64d |
| `dreadl0ck/netcap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `immortalwrt/packages` | GITHUB | IP-Datei 897d alt |
| `iagox86/dnscat2` | GITHUB | Zu alt: 925d |
| `NethServer/nethsecurity` | GITHUB | Größe: 0 IPs |
| `Owlinkai/redroom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `011-sam-110/Provenance` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pe3zx/my-infosec-awesome` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XORCISM-AI/XORCISM` | GITHUB | IP-Datei 98d alt |
| `pbscybsec/Threat-Intelligence` | GITHUB | Zu alt: 1093d |
| `isms-core-project/isms-core-platform` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rookiestar28/ComfyUI-OpenClaw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iamrajivd/pentest` | GITHUB | Zu alt: 2134d |
| `amayer1983/docksentry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neatlabs-ai/packet-capture-analyzer` | GITHUB | Zu alt: 217d |
| `Ignitetechnologies/Command-Control` | GITHUB | Zu alt: 2148d |
| `valITino/OSINToolKit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dev-Lahrani/Thor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GChristensen/enso-portable` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `helixmap/sigwood` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ropensci/googleLanguageR` | GITHUB | Zu alt: 234d |
| `CTI-Driven/Advanced-Threat-Hunting-Ransomware-Groups-Affiliates` | GITHUB | Zu alt: 443d |
| `danielgottt/CyberBodega` | GITHUB | Zu alt: 225d |
| `Lucent-Grid/the-open-osint-board` | GITHUB | Zu alt: 129d |
| `SARATOGAMarine/WP-Cybersecurity-Assorted-Tools` | GITHUB | Zu alt: 1695d |
| `fwerkor/CapOS` | GITHUB | IP-Datei 189d alt |
| `AgentiaPT/agentia-research` | GITHUB | Zu alt: 144d |
| `TheEddMan/osint-ioc-collector` | GITHUB | Größe: 0 IPs |
| `bitdefender/Bitdefender-Threat-Connect-integration-app` | GITHUB | Zu alt: 2432d |
| `timetology/NetWitness` | GITHUB | Zu alt: 1488d |
| `oasis-tcs/openc2-usecases` | GITHUB | Zu alt: 1619d |
| `HackTricks-wiki/hacktricks-cloud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cognis-digital/c2detect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yusufsaka007/stierlitz` | GITHUB | Zu alt: 488d |
| `rickkdev/worldwatcher` | GITHUB | Zu alt: 128d |
| `Azure/Industrial-IoT` | GITHUB | IP-Datei 829d alt |
| `tncsharetool/worldmonitor` | GITHUB | Zu alt: 204d |
| `MBCProject/mbc-markdown` | GITHUB | Zu alt: 470d |
| `kimd155/QuickResponseC2` | GITHUB | Zu alt: 137d |
| `lambdaclass/lambdaclass_hacking_learning_path` | GITHUB | Zu alt: 256d |
| `Cludes/botnet-live-maps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mevaibhavpandey/Maritime-Situational-Awareness` | GITHUB | Zu alt: 178d |
| `rajmahadevan/kql-lab` | GITHUB | Zu alt: 1041d |
| `HadessCS/Red-team-Interview-Questions` | GITHUB | Zu alt: 532d |
| `blueteamvillage/Project-Obsidian-DC30` | GITHUB | Zu alt: 856d |
| `Mosalah992/PlagueMonitor` | GITHUB | Zu alt: 173d |
| `cybershujin/Threat-Actors-use-of-Artifical-Intelligence` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HanuTyagi/Malware-Scanner` | GITHUB | Zu alt: 159d |
| `andyweaves/databricks-network-policy-helper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chengjia2016/her_os` | GITHUB | Zu alt: 198d |
| `cbuijs/hagezi` | GITHUB | Identischer Inhalt wie configserverapps_service_blocklists_blocklist |
| `owasp-dep-scan/blint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hagrid29/PELoader` | GITHUB | Zu alt: 1439d |
| `cristianzsh/freki` | GITHUB | Zu alt: 970d |
| `abdulkadir-gungor/JPGtoMalware` | GITHUB | Zu alt: 1561d |
| `ThreatLabz/ransomware_notes` | GITHUB | Zu alt: 43d |
| `0x25bit/Updated-Carbanak-Source-with-Plugins` | GITHUB | Zu alt: 2704d |
| `zeropointdynamics/zelos` | GITHUB | Zu alt: 1333d |
| `d4rksystem/VBoxCloak` | GITHUB | Zu alt: 448d |
| `crocodyli/ThreatActors-TTPs` | GITHUB | Zu alt: 239d |
| `secrary/SSMA` | GITHUB | Zu alt: 2348d |
| `htr-tech/zphisher` | GITHUB | Zu alt: 765d |
| `skerkour/black-hat-rust` | GITHUB | Zu alt: 359d |
| `htr-tech/nexphisher` | GITHUB | Zu alt: 1444d |
| `Ignitetch/AdvPhishing` | GITHUB | Zu alt: 263d |
| `jaykali/maskphish` | GITHUB | Zu alt: 374d |
| `CrimsonForge-io/king-phisher` | GITHUB | Zu alt: 52d |
| `AdrMXR/KitHack` | GITHUB | Zu alt: 583d |
| `chenjj/espoofer` | GITHUB | Zu alt: 1596d |
| `xiecat/goblin` | GITHUB | Zu alt: 1214d |
| `Raikia/FiercePhish` | GITHUB | Zu alt: 990d |
| `BiZken/PhishMailer` | GITHUB | Zu alt: 512d |
| `AbirHasan2005/ShellPhish` | GITHUB | Zu alt: 1737d |
| `m4n3dw0lf/pythem` | GITHUB | Zu alt: 2773d |
| `JoelGMSec/EvilnoVNC` | GITHUB | Zu alt: 507d |
| `Bhaviktutorials/shark` | GITHUB | Zu alt: 1440d |
| `hasanfirnas/symbiote` | GITHUB | Zu alt: 567d |
| `adamff-dev/ESP8266-Captive-Portal` | GITHUB | Zu alt: 1590d |
| `darkarp/chromepass` | GITHUB | Zu alt: 1003d |
| `simplerhacking/Evilginx3-Phishlets` | GITHUB | Zu alt: 486d |
| `MyEtherWallet/ethereum-lists` | GITHUB | Zu alt: 72d |
| `0n1cOn3/FluxER` | GITHUB | Zu alt: 117d |
| `t4d/StalkPhish` | GITHUB | Zu alt: 928d |
| `Euronymou5/Doxxer-Toolkit` | GITHUB | Zu alt: 116d |
| `Err0r-ICA/Phishbait` | GITHUB | Zu alt: 486d |
| `EricksonAtHome/blackeye` | GITHUB | Zu alt: 50d |
| `AlteredSecurity/365-Stealer` | GITHUB | Zu alt: 203d |
| `spyboy-productions/Facad1ng` | GITHUB | Zu alt: 262d |
| `CanIPhish/Phishious` | GITHUB | Zu alt: 1259d |
| `Akshay-Arjun/69phisher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kl0ibi/esp32_hackingtool` | GITHUB | Zu alt: 820d |
| `Optane002/ZPhisher` | GITHUB | Zu alt: 1059d |
| `SwiftOnSecurity/SwiftFilter` | GITHUB | Zu alt: 2330d |
| `curtbraz/PhishAPI` | GITHUB | Zu alt: 561d |
| `Cyber-Anonymous/Dark-Phish` | GITHUB | Zu alt: 732d |
| `cyberboyplas/WhPhisher` | GITHUB | Zu alt: 1456d |
| `taielab/Taie-AutoPhishing` | GITHUB | Zu alt: 2006d |
| `DRACULA-HACK/C-hacks` | GITHUB | Zu alt: 94d |
| `duo-labs/isthislegit` | GITHUB | Zu alt: 1151d |
| `4w4k3/Umbrella` | GITHUB | Zu alt: 3420d |
| `sneakerhax/PyPhisher` | GITHUB | Zu alt: 895d |
| `ineesdv/Tangled` | GITHUB | Zu alt: 281d |
| `evildevill/EmptyPhish` | GITHUB | Zu alt: 1169d |
| `alexbieber/SocioPhish` | GITHUB | Zu alt: 932d |
| `atexio/mercure` | GITHUB | Zu alt: 2028d |
| `phishingclub/phishingclub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `philomathic-guy/Malicious-Web-Content-Detection-Using-Machine-Learning` | GITHUB | Zu alt: 2184d |
| `cldrn/macphish` | GITHUB | Zu alt: 365d |
| `JoasASantos/ShadowPhish` | GITHUB | Zu alt: 525d |
| `t4d/PhishingKitHunter` | GITHUB | Zu alt: 2804d |
| `t4d/PhishingKit-Yara-Rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cybercdh/kitphishr` | GITHUB | Zu alt: 85d |
| `d-Rickyy-b/certstream-server-go` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ninoseki/miteru` | GITHUB | Zu alt: 104d |
| `mschwager/gitem` | GITHUB | Zu alt: 1222d |
| `Toxic-Noob/Link-X` | GITHUB | Zu alt: 1309d |
| `FreeZeroDays/GoPhish-Templates` | GITHUB | Zu alt: 833d |
| `hxrofo/hotspotphisher` | GITHUB | Zu alt: 896d |
| `denniskniep/DeviceCodePhishing` | GITHUB | Zu alt: 371d |
| `polkadot-js/phishing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `R3LI4NT/articulos` | GITHUB | Zu alt: 61d |
| `DevVj-1/Hacking-Social_Media-Accounts` | GITHUB | Zu alt: 60d |
| `Yezz123-Archive/Phisher` | GITHUB | Zu alt: 1883d |
| `Discord-AntiScam/scam-links` | GITHUB | Zu alt: 265d |
| `phish-report/IOK` | GITHUB | Zu alt: 519d |
| `salihpy/TgaHacking` | GITHUB | Zu alt: 1895d |
| `tevora-threat/Dragnet` | GITHUB | Zu alt: 1355d |
| `OspreyProject/Osprey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IAmBlackHacker/Facebook-phishing` | GITHUB | Zu alt: 1668d |
| `rsmusllp/king-phisher-templates` | GITHUB | Zu alt: 2564d |
| `MrLuit/EtherScamDB` | GITHUB | Zu alt: 1388d |
| `LiveGray/OPENORCHID` | GITHUB | Zu alt: 1228d |
| `martinsohn/Office-phish-templates` | GITHUB | Zu alt: 562d |
| `mamba-9mm/phishing` | GITHUB | Zu alt: 1009d |
| `wariv/DarkLnk` | GITHUB | Zu alt: 436d |
| `Altify-Developing/Altify-Developing-Main` | GITHUB | Zu alt: 50d |
| `Arcanum-Sec/wraith` | GITHUB | Zu alt: 55d |
| `mgeeky/VisualBasicObfuscator` | GITHUB | Zu alt: 1747d |
| `HiDe-Techno-Tips/Blackeye-for-Windows` | GITHUB | Zu alt: 1308d |
| `M4xSec/K-OTP-X` | GITHUB | Zu alt: 214d |
| `TYehan/SocialPhish` | GITHUB | Zu alt: 392d |
| `duo-labs/phish-collect` | GITHUB | Zu alt: 1158d |
| `surajr/URL-Classification` | GITHUB | Zu alt: 1930d |
| `jackmichalak/phishim` | GITHUB | Zu alt: 1327d |
| `dsnezhkov/deepsea` | GITHUB | Zu alt: 2258d |
| `dmdhrumilmistry/GooglePhish` | GITHUB | Zu alt: 128d |
| `rubikproxy/rubikphish` | GITHUB | Zu alt: 701d |
| `bhikandeshmukh/Blackeye-v2.0` | GITHUB | Zu alt: 1545d |
| `Tanmay-Tiwaricyber/tphisher` | GITHUB | Zu alt: 1433d |
| `SiddhantOffl/cam-virus` | GITHUB | Zu alt: 1836d |
| `GSRHaX/NGL-Phish` | GITHUB | Zu alt: 94d |
| `manashma/BlackManPhishing` | GITHUB | Zu alt: 550d |
| `idfp/masquerade` | GITHUB | Zu alt: 1233d |
| `Schillings/SwordPhish` | GITHUB | Zu alt: 3164d |
| `Bitwise-01/ApeX` | GITHUB | Zu alt: 3178d |
| `HackWeiser360/MaxPhisher` | GITHUB | Zu alt: 871d |
| `EwyBoy/Counter-Phishing-Tool` | GITHUB | Zu alt: 839d |
| `t4d/StalkPhish-OSS` | GITHUB | Zu alt: 454d |
| `Abhijeetbyte/Insta-login` | GITHUB | Zu alt: 827d |
| `jaykali/shellphish` | GITHUB | Zu alt: 2273d |
| `ariashirazi/InstaBrowser` | GITHUB | Zu alt: 2010d |
| `Mixore/Phishing-Discord-Servers-List` | GITHUB | Zu alt: 685d |
| `yogeshwaran01/maskurl` | GITHUB | Zu alt: 2062d |
| `Garrettiscool101/zphisher` | GITHUB | Zu alt: 72d |
| `cipheras/cipherginx` | GITHUB | Zu alt: 1429d |
| `sexettin78/sexettintool` | GITHUB | Zu alt: 498d |
| `CodingRanjith/autophisher` | GITHUB | Zu alt: 1502d |
| `LetsDefend/Phishing-Email-Analysis` | GITHUB | Zu alt: 602d |
| `LinkSec/phishing-templates` | GITHUB | Zu alt: 808d |
| `rsmusllp/king-phisher-plugins` | GITHUB | Zu alt: 2042d |
| `sky9262/phishEye` | GITHUB | Zu alt: 1722d |
| `Shlucus/FlipperZero-GooglePortal` | GITHUB | Zu alt: 391d |
| `P0cL4bs/flexphish` | GITHUB | Zu alt: 133d |
| `XiphosResearch/smsisher` | GITHUB | Zu alt: 3355d |
| `SamueleAmato/exaPhisher` | GITHUB | Zu alt: 279d |
| `hoangminh5210119/deauther` | GITHUB | Zu alt: 1552d |
| `PHPAuth/PHPAuth` | GITHUB | Zu alt: 250d |
| `kulkansecurity/gitxray` | GITHUB | Zu alt: 259d |
| `cowrie/cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hacklcx/HFish` | GITHUB | Zu alt: 196d |
| `Webeoidentify/Honeypot-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beelzebub-labs/beelzebub` | GITHUB | Größe: 0 IPs |
| `seccome/Ehoney` | GITHUB | Zu alt: 1074d |
| `markets/invisible_captcha` | GITHUB | Zu alt: 72d |
| `p1r06u3/opencanary_web` | GITHUB | Zu alt: 2045d |
| `aress31/wirespy` | GITHUB | Zu alt: 1441d |
| `DevSwanson/smart-contract-honeypot` | GITHUB | Zu alt: 263d |
| `DevSwanson/create-honeypot-token` | GITHUB | Zu alt: 263d |
| `DevSwanson/how-to-create-honeypot-token` | GITHUB | Zu alt: 263d |
| `tamimibrahim17/List-of-user-agents` | GITHUB | Zu alt: 1024d |
| `C4o/Juggler` | GITHUB | Zu alt: 309d |
| `utkusen/baitroute` | GITHUB | Zu alt: 619d |
| `bhdresh/Dejavu` | GITHUB | Zu alt: 419d |
| `TrisenYu/b0gus` | GITHUB | Zu alt: 86d |
| `formr/formr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jamesturk/django-honeypot` | GITHUB | Zu alt: 465d |
| `fffaraz/fakessh` | GITHUB | Zu alt: 76d |
| `Shmakov/Honeypot` | GITHUB | Zu alt: 271d |
| `spacesiren/spacesiren` | GITHUB | Zu alt: 1741d |
| `RiskyMH/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheKingOfDuck/Loki` | GITHUB | Zu alt: 1716d |
| `jayus0821/Armor` | GITHUB | Zu alt: 1915d |
| `0xsha/sweetie-data` | GITHUB | Zu alt: 2402d |
| `Nirusu/how-to-setup-a-honeypot` | GITHUB | Zu alt: 1537d |
| `Fausto-404/AlterHive` | GITHUB | Zu alt: 72d |
| `bediger4000/php-malware-analysis` | GITHUB | Zu alt: 1925d |
| `technicaldada/pentbox` | GITHUB | Zu alt: 359d |
| `lockness-Ko/xz-vulnerable-honeypot` | GITHUB | Zu alt: 906d |
| `ginger51011/pandoras_pot` | GITHUB | Zu alt: 53d |
| `leeberg/BlueHive` | GITHUB | Zu alt: 2648d |
| `nox-project/nox-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ArthurHeitmann/arctic_shift` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zbetcheckin/Security_list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AccentuSoft/LinkScope_Client` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/BuscaPaginasBlancas` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `juandresrodca/DorkCraft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `its0x08/duckduckgo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amnottdevv/atdork` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alaa-abdulridha/SerpScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `snooppr/shotstars` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `momenbasel/keyFinder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tg12/phantomtide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ElevenPaths/FOCA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atiilla/geospy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/psn_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/Website-Diff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JMarchiori13/osint-recon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XD-MHLOO/Osintgraph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/steam_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `projectdiscovery/dnsx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/xbox_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rough007/CDQR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/timesketch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ForensicArtifacts/artifacts-kb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DidierStevens/DidierStevensSuite` | GITHUB | IP-Datei 1380d alt |
| `fox-it/dissect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ralphje/imagemounter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mwielgoszewski/doorman` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SekoiaLab/Fastir_Collector_Linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jipegit/OSXAuditor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/stenographer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `certsocietegenerale/FIR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sbousseaden/EVTX-ATTACK-SAMPLES` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fox-it/acquire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yamato-Security/WELA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mbevilacqua/appcompatprocessor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frikky/Shuffle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `viper-framework/viper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `obsidianforensics/hindsight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rizinorg/cutter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zdhenard42/SOC-Multitool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CIRCL/traceroute-circl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swisscom/PowerSponse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre/caldera` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `certsocietegenerale/IRM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deralexxx/security-apis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JPCERTCC/LogonTracer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PowerShellMafia/CimSweep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CrowdStrike/falcon-orchestrator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/Raccine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlmCo/Panorama` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MutableSecurity/mutablesecurity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uber-common/metta` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rough007/CCF-VM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `muteb/Hoarder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/CIRTKit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spender-sandbox/cuckoo-modified` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/munin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ForensicArtifacts/artifacts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TryCatchHCF/DumpsterFire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jymcheong/AutoTTP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wagga40/Zircolite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gfoss/PSRecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Invoke-IR/PowerForensics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keydet89/RegRipper3.0` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `halpomeranz/lmg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `forensicanalysis/artifactcollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `etsy/morgue` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NextronSystems/APTSimulator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swisscom/PowerGRR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `defpoint/threat_note` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/RTA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Netflix-Skunkworks/diffy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bad-antics/nullsec-linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microsoft/avml` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rizinorg/rizin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ridgelinecyberdefence/vanguard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `log2timeline/dftimewolf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MagnetForensics/dumpit-linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AJMartel/IRTriage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `orlikoski/CyLR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aws-samples/aws-incident-response-runbooks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `redcanaryco/atomic-red-team` | GITHUB | IP-Datei 43d alt |
| `alpine-sec/SPECTR3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `davehull/Kansa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yelp/osxcollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dogoncouch/logdissect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `504ensicsLabs/LiME` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `biggiesmallsAG/nightHawkResponse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ufrisk/MemProcFS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `redhuntlabs/RedHunt-OS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kacos2000/MFT_Browser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SwiftOnSecurity/sysmon-config` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nogoodconfig/pyarascanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mandiant/capa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThreatResponse/margaritashotgun` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SekoiaLab/Fastir_Collector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mkorman90/VolatilityBot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diogo-fernan/domfind` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splunk/botsv2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `danielbohannon/Revoke-Obfuscation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brexhq/substation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `draios/sysdig` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre-attack/bzar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salesforce/jarm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cisco/joy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rapid7/recog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PowerShellMafia/PowerSploit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cyb3rWard0g/Invoke-ATTACKAPI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `palantir/alerting-detection-strategy-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LeeBrotherston/tls-fingerprinting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cisco/mercury` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `StrackVibes/NRD-db` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/detection-and-response-pipeline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hunters-forge/OSSEM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `infosecn1nja/Red-Teaming-Toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chronicle/detection-rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benjeems/Presentations` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trailofbits/presentations` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `austin-taylor/flare` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oxlaboratory/oxis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RanaYashIDK-2006/PS-14-Fraud-Detection-software` | GITHUB | Größe: 0 IPs |
| `profullstack/advis0r.com` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `invinby/XIDER` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zevo-enterprise/zevo-enterprise` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coolloic/brighte` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `harryclancy/Fpl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vladgermanyuk/prompt-injection-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WebGeeSolutions/Signoz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `smhasan94/django-tolap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpow18/indexscout` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `convenientlymike/convenientlymike` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Buddhacoin/NIR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `theabhinaw/Naviolabs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `srixram08/srixram08` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-molt-ecosystem` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rblmarrero-sketch/Condition-Monitoring` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `adarsh09856/agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ysamaila/worknoon-refund-system` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PersonalClaw/PersonalClaw` | GITHUB | IP-Datei 42d alt |
| `AnjelaGit-26/chainsleuth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mbadali25/useful-claude-add-ons` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AsiBackbone/Learning` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sid0153/cloudsentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `strmt7/VulnerabilityScreener` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arnoldfeenstra-hub/crypto-screener` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f-leroux/ephemeral` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `darreal44/riemann-weil-phenomenology` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yasindu-Sasmitha/Aegis-LK` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Latnook/voteball` | GITHUB | IP-Datei 38d alt |
| `stSoftwareAU/VibeCoder` | GITHUB | Größe: 0 IPs |
| `tpurtell/dots-note-sm12x-2x` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-datascience` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codebyshubhamm/THERMOS-REWAP1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HKLabStudio/Portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `conct/legal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sakshamchitkara-dotcom/newsbrief` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-game-file-format-reversing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Shaun-max-code/cybersecurity-learning` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Glitch-WRLD/goldfx-github` | GITHUB | Größe: 0 IPs |
| `coopvestafrica-ops/coopvest-website-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `muthu2085/anasupport` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VV5456/chompify-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `harminrana1455-cell/SecureTask` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mohamed-DN/neronet-proxy` | GITHUB | Größe: 0 IPs |
| `kratos45/exowatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `surjit10/LectureMIND.` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Roman-Cuisset/miccamwatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Argonyx-26/T14_Lordofpings` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mike-echo-oscar-whiskey/media-stack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DevCloudOps1/claude-auto-accept` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bisand/kvad` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EeryFrank/QiZhangVerdict` | GITHUB | Größe: 0 IPs |
| `ellyj3rain/zao` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dehyzzayd/securenet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 31,351 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,935 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,549 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 11,566 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,844 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,786 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,755 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 3,039 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,951 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,017 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,504 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,416 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,015 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 716 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 658 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 622 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 426 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,171 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,689 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 18,115 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 10,186 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,731 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,612 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 4,076 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 212,794 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,586 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 4,720 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,638 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 2,086 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,713 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 5,048 | 64.3% | 938 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 53,330 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,480 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,717 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 117,069 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 91,506 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,867 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,287 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 106,265 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,718 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 123,658 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,579 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 125,216 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 679 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 475,351 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,449 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 172,463 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 167,416 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 137,794 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 153,958 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 96,625 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 113,157 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 95,771 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 234,426 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 53,161 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 178,003 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 27,631 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 21,723 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 25,251 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 24,219 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 15,345 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 177,775 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,572 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 11,681 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 6,879 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 21,253 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 13,707 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,512 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 11,255 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 7,252 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,816 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,829 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,928 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,878 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 4,808 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,420 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 3,301 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,737 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,839 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 103,327 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,792 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,263 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 61,038 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,670 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 3,395 | 79.4% | 10 | 2026-09-24 |
| `ian_lusule_proxies` | GITHUB | 3,580 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,728 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,385 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 272,879 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 7,922 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 6,787 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 7,396 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,498 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 77 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 95,766 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 95,845 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,564 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 99 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 96,214 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,862 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,708 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 151 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 17,491 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 17,260 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 21,331 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,360 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 61,318 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 62,699 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,753 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 129,408 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 353 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 195,409 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,533 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 130,055 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 203,021 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,237 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 36,253 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 496 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 17,570 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 19,549 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,728 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 9,969 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,223 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,638 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 5,268 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,555 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,116 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,526 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 4,859 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,789 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 5,974 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 3,888 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,215 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,380 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,375 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,313 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,324 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,120 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,218 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,846 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,134 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,446 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 688 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,963 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,687 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 983 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 11,951 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,412 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 91,613 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 87,825 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 94,984 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 93,286 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 91,850 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 89,744 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,087 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 51,391 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 11,668 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,822 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,692 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,000 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,800 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 42,119 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 20,240 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 11,990 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 6,182 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 41 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 28,739 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 154,005 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 24,635 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 2,929 | 5.1% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,141 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,366 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 3,780 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,381 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 798 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 249 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 82 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 5,916 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 98,889 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 91,188 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 92,459 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 93,463 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 90,356 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 26,397 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 838 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 829 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_20` | GITHUB | 183 | 92.3% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 182 | 76.9% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_24` | GITHUB | 157 | 90.4% | 0 | 2026-09-25 |

---
*Generiert: 2026-09-25 12:04 CEST (Europe/Berlin)*