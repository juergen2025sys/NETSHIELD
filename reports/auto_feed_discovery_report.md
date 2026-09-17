# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-17 22:13 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **11889** |
| davon GitHub (Topics+Code) | **11800** |
| davon GitLab | **89** |
| davon Awesome-Lists | **2199** |
| Tools/Libraries vor Eval gefiltert | **953** |
| davon Hard-Reject (awesome-Liste etc.) | **198** |
| EVAL-Kandidaten (nach Stratifizierung) | **362** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **362** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **361** |
| Neu angenommene Feed-Dateien | **1** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **185** |
| Abgelehnte Repositories (dieser Run) | **361** |
| davon GitLab abgelehnt | **2** |
| Feeds gesamt (aktiv) | **186** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **165254** |
| SQLite-Refresh-Cache-Hits | **7/186** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Repo zu alt (>30d) | **200** |
| Keine IP-Datei im Repo | **146** |
| IP-Datei veraltet (>30d) | **12** |
| Falsche Größe (<30 / >2,000,000 IPs) | **3** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `cbuijs_hagezi` | [cbuijs/hagezi](https://github.com/cbuijs/hagezi) | GITHUB | 50,589 | 40.7% | 0.0% | 123 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `hove-io/m365-edl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trickest/cve` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bb1nfosec/Information-Security-Tasks` | GITHUB | IP-Datei 118d alt |
| `netcanon/netcanon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mthcht/ThreatIntel-Reports` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fastrevmd-lab/firewallintentconverter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Deipedra34/NetSentry` | GITHUB | Größe: 0 IPs |
| `mikeroyal/Parrot-Security-Guide` | GITHUB | Zu alt: 1864d |
| `iusztinpaul/designing-real-world-ai-agents-workshop` | GITHUB | Zu alt: 106d |
| `Abhinavbwj/Claude-skills-for-Computational-Designers` | GITHUB | Zu alt: 175d |
| `mikeroyal/Fedora-Guide` | GITHUB | Zu alt: 987d |
| `guy032/InfraQuery` | GITHUB | Zu alt: 317d |
| `joshuaswarren/remnic` | GITHUB | Größe: 0 IPs |
| `sheawinkler/hermes-agent-ultra` | GITHUB | Zu alt: 53d |
| `arstgit/high-frequency-vocabulary` | GITHUB | Zu alt: 2445d |
| `tradle/why-hypercore` | GITHUB | Zu alt: 758d |
| `sookinoby/sentiment-analysis2` | GITHUB | Zu alt: 3278d |
| `CES-Ltd/TitanX` | GITHUB | Zu alt: 149d |
| `costinEEST/almanacs` | GITHUB | Zu alt: 32d |
| `stepfun-ai/Step-3.7-Flash` | GITHUB | Zu alt: 108d |
| `arthurpanhku/DocSentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dkyazzentwatwa/osint-ai` | GITHUB | Zu alt: 194d |
| `VilledeMontreal/urban-detection` | GITHUB | Zu alt: 1842d |
| `zydou/high-frequency-words` | GITHUB | Zu alt: 1624d |
| `qomplx/arkscrape` | GITHUB | Zu alt: 1910d |
| `whiteknight7/wordlist` | GITHUB | Zu alt: 1846d |
| `davidgasquez/handbook` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hwk0809/RGBench` | GITHUB | Zu alt: 49d |
| `harikrish2727/BetterGPT` | GITHUB | Zu alt: 50d |
| `vektort13/antiOS_batch` | GITHUB | Zu alt: 2707d |
| `Rune-kit/rune` | GITHUB | Zu alt: 32d |
| `AirtightSecurity/Cyber-Security-Resources` | GITHUB | Zu alt: 1474d |
| `MAGIC-AI4Med/Deep-DxSearch` | GITHUB | Zu alt: 202d |
| `MattBlack85/goscanner` | GITHUB | Zu alt: 3516d |
| `LeadGrowGTM/research-process-builder` | GITHUB | IP-Datei 127d alt |
| `Nexround/LoKI` | GITHUB | Zu alt: 159d |
| `0x0Trace/ReconDuctor` | GITHUB | Zu alt: 262d |
| `hoangsonww/EstateWise-Chapel-Hill-Chatbot` | GITHUB | IP-Datei 246d alt |
| `daveshap/weekly_arxiv` | GITHUB | Zu alt: 1078d |
| `CBIIT/NCI-DOE-Collab-Pilot2-MuMMI` | GITHUB | Zu alt: 87d |
| `Forexgod21/YVYC-Claude-Skills` | GITHUB | Zu alt: 43d |
| `clawic/skills` | GITHUB | Zu alt: 52d |
| `smartshark/seBERT` | GITHUB | Zu alt: 1343d |
| `BinaryMeadow/gridwatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nineninesix-ai/KaniTTS-Finetune-pipeline` | GITHUB | Zu alt: 318d |
| `Radargoger/azure-collectionbased-threatfeed` | GITHUB | Zu alt: 186d |
| `qu-gg/torch-neural-ssm` | GITHUB | Zu alt: 642d |
| `mladimatija/cldt-map` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yujia2/PathSim` | GITHUB | Zu alt: 3842d |
| `NSlothuus/agent-bench` | GITHUB | Zu alt: 162d |
| `cool-japan/voirs` | GITHUB | IP-Datei 361d alt |
| `ChristopherKahler/aegis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `visgym/VisGym` | GITHUB | Zu alt: 137d |
| `intutic/turing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `leizerowicz/bitnet-mlx.rs` | GITHUB | Zu alt: 329d |
| `mr-wolf-gb/hybrid-dns-server` | GITHUB | Zu alt: 384d |
| `safety-quotient-lab/psychology-agent` | GITHUB | Zu alt: 139d |
| `akha-security/akha-xss` | GITHUB | Zu alt: 99d |
| `Arnabh-M/Veridex` | GITHUB | Zu alt: 144d |
| `mdbabumiamssm/LLMs-Universal-Life-Science-and-Clinical-Skills-` | GITHUB | Zu alt: 91d |
| `hterzia/voice-agent` | GITHUB | Zu alt: 70d |
| `GetAnima/anima` | GITHUB | Zu alt: 206d |
| `yang/notes` | GITHUB | Zu alt: 3333d |
| `radustefandumitru/overdrive` | GITHUB | Zu alt: 70d |
| `xinhuagu/AceClaw` | GITHUB | Zu alt: 73d |
| `iklobato/PythonRequestTor` | GITHUB | Zu alt: 1317d |
| `nshiab/journalism` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Utkarsh-X/TRACE-AML` | GITHUB | Zu alt: 52d |
| `HayyanFaisal/SafeCity-prototype-models` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HassanAbdullahHere/pitchforge` | GITHUB | Zu alt: 81d |
| `nirholas/bnbchain-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nirholas/github-to-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nirholas/mcp-notify` | GITHUB | IP-Datei 255d alt |
| `Afawfaq/bug-free-octo-pancake` | GITHUB | Zu alt: 282d |
| `jgwill/storytelling` | GITHUB | Zu alt: 163d |
| `galorr/claude-code-starter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3D-Components/open-robin` | GITHUB | Zu alt: 78d |
| `ssasso/stefano.dscnet.org` | GITHUB | Zu alt: 755d |
| `kitnil/notes` | GITHUB | Zu alt: 41d |
| `bellistech/vor` | GITHUB | Zu alt: 34d |
| `alsyundawy/Microsoft-Office-For-MacOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenFilters/internet-scanners` | GITHUB | IP-Datei 97d alt |
| `beyondtahir/beyondseo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AdrMXR/KitHack` | GITHUB | Zu alt: 575d |
| `chenjj/espoofer` | GITHUB | Zu alt: 1588d |
| `xiecat/goblin` | GITHUB | Zu alt: 1206d |
| `Raikia/FiercePhish` | GITHUB | Zu alt: 982d |
| `BiZken/PhishMailer` | GITHUB | Zu alt: 504d |
| `AbirHasan2005/ShellPhish` | GITHUB | Zu alt: 1729d |
| `m4n3dw0lf/pythem` | GITHUB | Zu alt: 2765d |
| `JoelGMSec/EvilnoVNC` | GITHUB | Zu alt: 499d |
| `Bhaviktutorials/shark` | GITHUB | Zu alt: 1432d |
| `hasanfirnas/symbiote` | GITHUB | Zu alt: 559d |
| `adamff-dev/ESP8266-Captive-Portal` | GITHUB | Zu alt: 1582d |
| `darkarp/chromepass` | GITHUB | Zu alt: 995d |
| `simplerhacking/Evilginx3-Phishlets` | GITHUB | Zu alt: 478d |
| `MyEtherWallet/ethereum-lists` | GITHUB | Zu alt: 64d |
| `0n1cOn3/FluxER` | GITHUB | Zu alt: 109d |
| `t4d/StalkPhish` | GITHUB | Zu alt: 920d |
| `S3N4T0R-0X0/BEAR-C2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Euronymou5/Doxxer-Toolkit` | GITHUB | Zu alt: 108d |
| `Err0r-ICA/Phishbait` | GITHUB | Zu alt: 478d |
| `EricksonAtHome/blackeye` | GITHUB | Zu alt: 42d |
| `AlteredSecurity/365-Stealer` | GITHUB | Zu alt: 195d |
| `spyboy-productions/Facad1ng` | GITHUB | Zu alt: 254d |
| `CanIPhish/Phishious` | GITHUB | Zu alt: 1251d |
| `Akshay-Arjun/69phisher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kl0ibi/esp32_hackingtool` | GITHUB | Zu alt: 812d |
| `Optane002/ZPhisher` | GITHUB | Zu alt: 1051d |
| `curtbraz/PhishAPI` | GITHUB | Zu alt: 553d |
| `Cyber-Anonymous/Dark-Phish` | GITHUB | Zu alt: 724d |
| `cyberboyplas/WhPhisher` | GITHUB | Zu alt: 1448d |
| `taielab/Taie-AutoPhishing` | GITHUB | Zu alt: 1998d |
| `DRACULA-HACK/C-hacks` | GITHUB | Zu alt: 86d |
| `duo-labs/isthislegit` | GITHUB | Zu alt: 1143d |
| `4w4k3/Umbrella` | GITHUB | Zu alt: 3412d |
| `sneakerhax/PyPhisher` | GITHUB | Zu alt: 887d |
| `ineesdv/Tangled` | GITHUB | Zu alt: 273d |
| `evildevill/EmptyPhish` | GITHUB | Zu alt: 1161d |
| `atexio/mercure` | GITHUB | Zu alt: 2020d |
| `alexbieber/SocioPhish` | GITHUB | Zu alt: 924d |
| `phishingclub/phishingclub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `philomathic-guy/Malicious-Web-Content-Detection-Using-Machine-Learning` | GITHUB | Zu alt: 2176d |
| `cldrn/macphish` | GITHUB | Zu alt: 357d |
| `JoasASantos/ShadowPhish` | GITHUB | Zu alt: 517d |
| `t4d/PhishingKitHunter` | GITHUB | Zu alt: 2796d |
| `t4d/PhishingKit-Yara-Rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cybercdh/kitphishr` | GITHUB | Zu alt: 77d |
| `d-Rickyy-b/certstream-server-go` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ninoseki/miteru` | GITHUB | Zu alt: 96d |
| `mschwager/gitem` | GITHUB | Zu alt: 1214d |
| `Toxic-Noob/Link-X` | GITHUB | Zu alt: 1301d |
| `FreeZeroDays/GoPhish-Templates` | GITHUB | Zu alt: 825d |
| `hxrofo/hotspotphisher` | GITHUB | Zu alt: 888d |
| `denniskniep/DeviceCodePhishing` | GITHUB | Zu alt: 363d |
| `polkadot-js/phishing` | GITHUB | Zu alt: 47d |
| `Yezz123-Archive/Phisher` | GITHUB | Zu alt: 1875d |
| `Discord-AntiScam/scam-links` | GITHUB | Zu alt: 257d |
| `R3LI4NT/articulos` | GITHUB | Zu alt: 53d |
| `DevVj-1/Hacking-Social_Media-Accounts` | GITHUB | Zu alt: 52d |
| `phish-report/IOK` | GITHUB | Zu alt: 511d |
| `salihpy/TgaHacking` | GITHUB | Zu alt: 1887d |
| `tevora-threat/Dragnet` | GITHUB | Zu alt: 1347d |
| `OspreyProject/Osprey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IAmBlackHacker/Facebook-phishing` | GITHUB | Zu alt: 1660d |
| `rsmusllp/king-phisher-templates` | GITHUB | Zu alt: 2556d |
| `LiveGray/OPENORCHID` | GITHUB | Zu alt: 1220d |
| `MrLuit/EtherScamDB` | GITHUB | Zu alt: 1380d |
| `martinsohn/Office-phish-templates` | GITHUB | Zu alt: 554d |
| `mamba-9mm/phishing` | GITHUB | Zu alt: 1001d |
| `wariv/DarkLnk` | GITHUB | Zu alt: 428d |
| `Altify-Developing/Altify-Developing-Main` | GITHUB | Zu alt: 42d |
| `mgeeky/VisualBasicObfuscator` | GITHUB | Zu alt: 1739d |
| `Arcanum-Sec/wraith` | GITHUB | Zu alt: 47d |
| `HiDe-Techno-Tips/Blackeye-for-Windows` | GITHUB | Zu alt: 1300d |
| `TYehan/SocialPhish` | GITHUB | Zu alt: 384d |
| `M4xSec/K-OTP-X` | GITHUB | Zu alt: 206d |
| `duo-labs/phish-collect` | GITHUB | Zu alt: 1150d |
| `surajr/URL-Classification` | GITHUB | Zu alt: 1922d |
| `jackmichalak/phishim` | GITHUB | Zu alt: 1319d |
| `dsnezhkov/deepsea` | GITHUB | Zu alt: 2250d |
| `dmdhrumilmistry/GooglePhish` | GITHUB | Zu alt: 120d |
| `rubikproxy/rubikphish` | GITHUB | Zu alt: 693d |
| `SiddhantOffl/cam-virus` | GITHUB | Zu alt: 1828d |
| `Tanmay-Tiwaricyber/tphisher` | GITHUB | Zu alt: 1425d |
| `bhikandeshmukh/Blackeye-v2.0` | GITHUB | Zu alt: 1537d |
| `GSRHaX/NGL-Phish` | GITHUB | Zu alt: 86d |
| `idfp/masquerade` | GITHUB | Zu alt: 1225d |
| `manashma/BlackManPhishing` | GITHUB | Zu alt: 542d |
| `Schillings/SwordPhish` | GITHUB | Zu alt: 3156d |
| `Bitwise-01/ApeX` | GITHUB | Zu alt: 3170d |
| `HackWeiser360/MaxPhisher` | GITHUB | Zu alt: 863d |
| `EwyBoy/Counter-Phishing-Tool` | GITHUB | Zu alt: 831d |
| `t4d/StalkPhish-OSS` | GITHUB | Zu alt: 446d |
| `Abhijeetbyte/Insta-login` | GITHUB | Zu alt: 819d |
| `ariashirazi/InstaBrowser` | GITHUB | Zu alt: 2002d |
| `Mixore/Phishing-Discord-Servers-List` | GITHUB | Zu alt: 677d |
| `yogeshwaran01/maskurl` | GITHUB | Zu alt: 2054d |
| `Garrettiscool101/zphisher` | GITHUB | Zu alt: 64d |
| `cipheras/cipherginx` | GITHUB | Zu alt: 1421d |
| `sexettin78/sexettintool` | GITHUB | Zu alt: 490d |
| `CodingRanjith/autophisher` | GITHUB | Zu alt: 1494d |
| `LetsDefend/Phishing-Email-Analysis` | GITHUB | Zu alt: 594d |
| `LinkSec/phishing-templates` | GITHUB | Zu alt: 800d |
| `rsmusllp/king-phisher-plugins` | GITHUB | Zu alt: 2034d |
| `sky9262/phishEye` | GITHUB | Zu alt: 1714d |
| `Shlucus/FlipperZero-GooglePortal` | GITHUB | Zu alt: 383d |
| `P0cL4bs/flexphish` | GITHUB | Zu alt: 125d |
| `SamueleAmato/exaPhisher` | GITHUB | Zu alt: 271d |
| `hoangminh5210119/deauther` | GITHUB | Zu alt: 1544d |
| `PHPAuth/PHPAuth` | GITHUB | Zu alt: 242d |
| `kulkansecurity/gitxray` | GITHUB | Zu alt: 251d |
| `hacklcx/HFish` | GITHUB | Zu alt: 188d |
| `Webeoidentify/Honeypot-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beelzebub-labs/beelzebub` | GITHUB | Größe: 0 IPs |
| `seccome/Ehoney` | GITHUB | Zu alt: 1066d |
| `markets/invisible_captcha` | GITHUB | Zu alt: 64d |
| `p1r06u3/opencanary_web` | GITHUB | Zu alt: 2037d |
| `aress31/wirespy` | GITHUB | Zu alt: 1433d |
| `DevSwanson/smart-contract-honeypot` | GITHUB | Zu alt: 255d |
| `DevSwanson/create-honeypot-token` | GITHUB | Zu alt: 255d |
| `DevSwanson/how-to-create-honeypot-token` | GITHUB | Zu alt: 255d |
| `tamimibrahim17/List-of-user-agents` | GITHUB | Zu alt: 1016d |
| `C4o/Juggler` | GITHUB | Zu alt: 301d |
| `utkusen/baitroute` | GITHUB | Zu alt: 611d |
| `bhdresh/Dejavu` | GITHUB | Zu alt: 411d |
| `TrisenYu/b0gus` | GITHUB | Zu alt: 78d |
| `formr/formr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jamesturk/django-honeypot` | GITHUB | Zu alt: 457d |
| `fffaraz/fakessh` | GITHUB | Zu alt: 68d |
| `Shmakov/Honeypot` | GITHUB | Zu alt: 263d |
| `spacesiren/spacesiren` | GITHUB | Zu alt: 1733d |
| `RiskyMH/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheKingOfDuck/Loki` | GITHUB | Zu alt: 1708d |
| `burpheart/hachimi` | GITHUB | Zu alt: 601d |
| `jayus0821/Armor` | GITHUB | Zu alt: 1907d |
| `0xsha/sweetie-data` | GITHUB | Zu alt: 2394d |
| `Nirusu/how-to-setup-a-honeypot` | GITHUB | Zu alt: 1529d |
| `bediger4000/php-malware-analysis` | GITHUB | Zu alt: 1917d |
| `technicaldada/pentbox` | GITHUB | Zu alt: 351d |
| `Fausto-404/AlterHive` | GITHUB | Zu alt: 64d |
| `lockness-Ko/xz-vulnerable-honeypot` | GITHUB | Zu alt: 898d |
| `ginger51011/pandoras_pot` | GITHUB | Zu alt: 45d |
| `leeberg/BlueHive` | GITHUB | Zu alt: 2640d |
| `valamidev/web3-defi-honeypot-and-slippage-checker` | GITHUB | Zu alt: 905d |
| `slowmist/blockchain-threat-intelligence` | GITHUB | Zu alt: 1740d |
| `Tcotl/AgentCapture` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andreicscs/HoneyWire` | GITHUB | IP-Datei 68d alt |
| `aau-network-security/HosTaGe` | GITHUB | Zu alt: 455d |
| `victpork/sshsyrup` | GITHUB | Zu alt: 2761d |
| `Turing-Space/Smart-Contract-Modular-Template` | GITHUB | Zu alt: 2355d |
| `dynatrace-oss/koney` | GITHUB | IP-Datei 262d alt |
| `dweinstein/canary` | GITHUB | Zu alt: 174d |
| `adityashrm21/RaspberryPi-Packet-Sniffer` | GITHUB | Zu alt: 2838d |
| `shantoroy/intro-2-cybersecurity-in-python` | GITHUB | Zu alt: 548d |
| `3CORESec/Trapdoor` | GITHUB | Zu alt: 1346d |
| `raspgot/Contact-Form-PHP` | GITHUB | Zu alt: 220d |
| `anouarbensaad/honeypot-iot` | GITHUB | Zu alt: 2688d |
| `malvaphe/Crypto_Honeypot_Detector` | GITHUB | Zu alt: 1207d |
| `ridgelinecyberdefence/vanguard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/eql` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splunk/botsv2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brimsec/brim` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `slackhq/go-audit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Foundstone/ExpertInvestigationGuides` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MHaggis/sysmon-dfir` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LeeBrotherston/tls-fingerprinting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/auditd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salesforce/ja3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sooshie/secrepo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benjeems/Presentations` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmpireProject/Empire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `unfetter-analytic/unfetter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hasherezade/hollows_hunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mdsecactivebreach/CACTUSTORCH` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Netflix/dispatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre-attack/bzar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brexhq/substation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ssllabs/sslhaf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rapid7/recog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splunk/botsv3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salesforce/jarm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splunk/botsv1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cisco/mercury` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GoogleCloudPlatform/security-analytics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `virustotal/yara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salesforce/GQUIC_Protocol_Analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sysinternals/ProcMon-for-Linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bro/bro-osquery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sbousseaden/PCAP-ATTACK` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mdsecactivebreach/SharpShooter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `danielbohannon/Revoke-Obfuscation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/detection-and-response-pipeline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `guardicore/monkey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dreadl0ck/netcap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cyb3rWard0g/Invoke-ATTACKAPI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tenzir/threatbus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Shuffle/Shuffle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PowerShellMafia/PowerSploit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERT-Polska/hfinger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FoxIO-LLC/LogSlash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cyb3rWard0g/mordor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BlueTeamLabs/sentinel-attack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `StrackVibes/NRD-db` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jandre/brosquery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hunters-forge/OSSEM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `op7ic/BlueTeam.Lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beahunt3r/Windows-Hunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salesforce/hassh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `draios/sysdig` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `segmentio/chamber` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zaproxy/zaproxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `retracedhq/retraced` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RustScan/RustScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zigrin-Security/CakeFuzzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Storyyeller/enjarify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `StackExchange/blackbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amocrenco/owasp-testing-checklist-v4-markdown` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GoVanguard/legion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `curiefense/curiefense` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trustedsec/ptf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `baidu/openrasp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `99designs/aws-vault` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ptswarm/reFlutter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rspamd/rspamd` | GITHUB | IP-Datei 187d alt |
| `KishanBagaria/padding-oracle-attacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `apache/incubator-spot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `51j0/Android-Storage-Extractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tfsec/tfsec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SpectralOps/keyscope` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iBotPeaches/Apktool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `504ensicsLabs/LiME.git` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marshyski/sshwatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UDcide/udcide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/rekall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rapid7/metasploit-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `USArmyResearchLab/Dshell` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deepfence/SecretScanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ironbee/ironbee` | GITHUB | IP-Datei 4941d alt |
| `GrapheneOS/hardened_malloc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dev-sec/ansible-os-hardening` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cider-security-research/cicd-goat` | GITHUB | IP-Datei 1620d alt |
| `zaproxy/zap-api-nodejs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Checkmarx/kics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OWASP/owasp-mstg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `selefra/selefra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `starkandwayne/safe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spectralops/teller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RedTeamPentesting/monsoon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nbs-system/naxsi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jery0843/torforge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `padok-team/cognito-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaplanelad/shellfirm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `apache/incubator-metron` | GITHUB | IP-Datei 2582d alt |
| `rfunix/Pompem` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frida/frida` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cloudflare/redoctober` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jnv/lists` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Khadinxc/Sigma2SPL` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jtpereyda/boofuzz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tijme/angularjs-csti-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lirantal/is-website-vulnerable` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `apps/guardrails` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evilsocket/opensnitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skylot/jadx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dtag-dev-sec/t-pot-autoinstall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spectralops/preflight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rusty-ferris-club/recon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `baalmor/cve-ape` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rusty-ferris-club/shellclear` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nxgn-kd01/shai-hulud-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kurolabs/stegcloak` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RIPE-NCC/hadoop-pcap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cloudsecurelab/security-acronyms` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenSOC/opensoc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gamelinux/passivedns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cossacklabs/themis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khast3x/Redcloud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `simsong/tcpflow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:oceaniagov-minitrue/minitrue-unpersons` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:kikinovak/rh_setup_fail2ban` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 27,020 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,827 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 8,848 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,719 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,840 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,741 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,713 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,933 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,952 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,166 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 2,700 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 1,810 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 761 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 547 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 599 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 493 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 321 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 53,905 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,536 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 17,617 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,097 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,072 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,185 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,235 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 214,611 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 3,963 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 2,934 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,641 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 124,129 | 0.1% | 1560 | 2026-08-01 |
| `hookzof_socks5_list` | GITHUB | 1,461 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,698 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 4,693 | 64.3% | 938 | 2026-09-04 |
| `cbuijs_hagezi` | GITHUB | 50,589 | 40.7% | 123 | 2026-09-17 |
| `mohammedcha_proxripper` | GITHUB | 52,807 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,933 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 116,534 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,219 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 93,620 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 646 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,778 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 105,515 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,698 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 119,693 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,529 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 128,876 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 588 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 480,066 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,295 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 172,260 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 169,685 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 138,372 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 151,249 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 96,540 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 117,161 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 91,856 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 226,855 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 62,589 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 168,906 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 31,549 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 23,745 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 25,256 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 18,861 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 16,462 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 140,096 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,951 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 12,373 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 10,472 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 20,208 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 13,171 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,413 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 10,689 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 6,943 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 4,176 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,502 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 4,674 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,382 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 3,549 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,155 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 4,018 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,367 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,973 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 96,025 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 2,333 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,574 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 53,434 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,820 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,848 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,392 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,261 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 84,893 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 271,205 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 7,396 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 6,232 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 7,690 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,451 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 9 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 91,755 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 98,377 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,523 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 86 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 228,556 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,199 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,709 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 176 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 16,567 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 16,516 | 76.5% | 3 | 2026-08-09 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,063 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,923 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 19,162 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,344 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 56,916 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 61,049 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,700 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 124,054 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 370 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,168 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 194,708 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,538 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 122,565 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 199,106 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,103 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 33,458 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 494 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 21,931 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 16,772 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,731 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 8,261 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,700 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,641 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,624 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 5,000 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,782 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,115 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,533 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 4,117 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,787 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 4,355 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,099 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,273 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,345 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,351 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,291 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,260 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,019 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,127 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,233 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,141 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,397 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 682 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,451 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,814 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,228 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 12,254 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 91,370 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 91,794 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 92,072 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 93,224 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 93,785 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 94,007 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 89,283 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,538 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 46,194 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 11,933 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,773 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,213 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,820 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 43,127 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 21,033 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 12,706 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 6,359 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 44 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 27,294 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 151,252 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 20,043 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,383 | 5.1% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,090 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,127 | 9.3% | 0 | 2026-09-13 |

---
*Generiert: 2026-09-17 22:13 CEST (Europe/Berlin)*