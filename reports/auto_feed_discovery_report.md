# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-24 19:54 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **11362** |
| davon GitHub (Topics+Code) | **11272** |
| davon GitLab | **90** |
| davon Awesome-Lists | **2399** |
| Tools/Libraries vor Eval gefiltert | **1560** |
| davon Hard-Reject (awesome-Liste etc.) | **166** |
| EVAL-Kandidaten (nach Stratifizierung) | **424** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **424** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **422** |
| Neu angenommene Feed-Dateien | **1** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **1** |
| Bestehende Feed-Dateien aktualisiert | **189** |
| Abgelehnte Repositories (dieser Run) | **422** |
| davon GitLab abgelehnt | **1** |
| Feeds gesamt (aktiv) | **190** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **162964** |
| SQLite-Refresh-Cache-Hits | **169/192** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **319** |
| Repo zu alt (>30d) | **67** |
| Falsche Größe (<30 / >2,000,000 IPs) | **24** |
| IP-Datei veraltet (>30d) | **11** |
| Sonstige | **1** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `blessedrebus_krawl` | [BlessedRebuS/Krawl](https://github.com/BlessedRebuS/Krawl) | GITHUB | 5,916 | 20.6% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `Tayanithaa/Multiagent_Cybersecurity_Intelligent_system` | GITHUB | Zu alt: 123d |
| `umbrae/reddit-top-2.5-million` | GITHUB | Zu alt: 2357d |
| `uiuc-ischool-scanr/WikiCSSH` | GITHUB | Zu alt: 2221d |
| `mthcht/ThreatHunting-Keywords` | GITHUB | Zu alt: 416d |
| `ge-high-assurance/VERDICT` | GITHUB | Zu alt: 763d |
| `kallyaleksiev/quantum-gaps` | GITHUB | Zu alt: 492d |
| `swam92/datasetsProject` | GITHUB | Zu alt: 4296d |
| `nmit-1NT23CS267/Generative-AI-for-Automated-Cyber-threat-prediction-and-response` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bdkaoutar/SOC-AI` | GITHUB | Zu alt: 261d |
| `cyberytti/ToolHunt` | GITHUB | Zu alt: 104d |
| `gladiopeace/Files-Indexer` | GITHUB | Zu alt: 1552d |
| `osirislab/LeakyPastes-V2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ansari-in/iri-shield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Digant07/OBLIVIONX-AI` | GITHUB | Zu alt: 377d |
| `lioravigdor/Password-Authentication-Server` | GITHUB | Zu alt: 254d |
| `cyc3o/Cyvora` | GITHUB | Zu alt: 58d |
| `muralikrish9/CS5542` | GITHUB | Zu alt: 149d |
| `NitinTheGreat/Enigma` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bughunter-mano/kaust-llm-injection-resilience` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Staxxiepooh/IoT-Threat-Attribution` | GITHUB | Zu alt: 324d |
| `krodalabs/coding-agent-research-artifact` | GITHUB | Zu alt: 75d |
| `Montimage/ai4soar` | GITHUB | Zu alt: 49d |
| `ks-exe/AI-Powered-Security-Incident-Analytics-Platform` | GITHUB | Zu alt: 38d |
| `ate47/bocw-source` | GITHUB | Zu alt: 411d |
| `ps491/cyberlab-2026-datasets` | GITHUB | Zu alt: 44d |
| `tehilare111/mmn16` | GITHUB | Zu alt: 261d |
| `AnujPatel089/sentinel-ai-soc-platform` | GITHUB | Zu alt: 35d |
| `m1ndvortex/jewely` | GITHUB | Zu alt: 282d |
| `vardhan2907/bth-thesis-static-analysis-tool` | GITHUB | Zu alt: 109d |
| `ge-high-assurance/OYSTER` | GITHUB | Zu alt: 1106d |
| `AneyShravani/Insider-Threat-Detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arminhaller/LinksInLOD` | GITHUB | Zu alt: 1648d |
| `neoboii23/NISec-Firewall` | GITHUB | Größe: 0 IPs |
| `andrehora/file-history` | GITHUB | Größe: 0 IPs |
| `nottobeaproblem/github-trend-monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zuquim/Identifying-Logging-Practices-in-Open-Source-Python-Containerized-Application-Projects` | GITHUB | Zu alt: 1634d |
| `DanielRichardson1/ECE1155-Demo` | GITHUB | Zu alt: 518d |
| `iamyuthan/VulDB` | GITHUB | Zu alt: 1326d |
| `TurtleEngr/my-bib` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RahulModak74/working_agents` | GITHUB | Zu alt: 322d |
| `LakumiBoltn/HSE-Homeworks-VerstovR` | GITHUB | Zu alt: 197d |
| `h0ffy/discoveryworld_agent` | GITHUB | Zu alt: 591d |
| `kinasant/ctf-scoreboards` | GITHUB | Zu alt: 456d |
| `ate47/cod-source` | GITHUB | IP-Datei 320d alt |
| `voidful/taiwan-agent-bench` | GITHUB | Zu alt: 92d |
| `LayerDynamics/poisoned_os` | GITHUB | Zu alt: 32d |
| `Software-Engineering-2026-Class/Kel9-LLM-Chatbot-SEPSESCSKG` | GITHUB | Zu alt: 101d |
| `mallapalligagana/cyberchatbot` | GITHUB | Größe: 0 IPs |
| `ifsheldon/Stab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shahp7575/reddit_coffee_scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hadhemii/ClonesInDLCode` | GITHUB | Zu alt: 1896d |
| `giridhar30/SPL-To-PQL-BE` | GITHUB | Zu alt: 727d |
| `SMART-Dal/testability` | GITHUB | Zu alt: 1059d |
| `headwinds/mapdrops` | GITHUB | Zu alt: 3044d |
| `anonymous-ijcai/dsw-ont-ijcai` | GITHUB | Zu alt: 4245d |
| `sueyumm/BCBT` | GITHUB | Zu alt: 86d |
| `anupyadav27/lab` | GITHUB | Zu alt: 136d |
| `tullyhansen/botally-toolkit` | GITHUB | Zu alt: 4007d |
| `MaryNankya/Guardrail-Under-Fire` | GITHUB | Zu alt: 40d |
| `mudbri/LLM-Network-Eval` | GITHUB | Zu alt: 384d |
| `UrbanGoodz/UrbanGoodz-Backend-Admin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aglinxinyuan/KnimeParser` | GITHUB | Zu alt: 889d |
| `DAINTINESS-Group/MUSES` | GITHUB | Zu alt: 4002d |
| `Derv6464/ComicSearch` | GITHUB | Zu alt: 768d |
| `leighklotz/lustre` | GITHUB | Zu alt: 223d |
| `evidencebp/pylint-intervention` | GITHUB | Zu alt: 362d |
| `AAAGUAI31/stats401-labs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ziadoz/til` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ricco555/SHAP-GSD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cbuijs/hagezi` | GITHUB | Identischer Inhalt wie configserverapps_service_blocklists_blocklist |
| `muchdogesec/obstracts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JMousqueton/CTI-MSTeams-Bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beenuar/AiSOC` | GITHUB | Größe: 0 IPs |
| `0xMarcio/pocindex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RavinduRathnayaka/LiveThreatMap-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaifcodec/user-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nebulock-Inc/agentic-threat-hunting-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `777genius/social-monitor` | GITHUB | IP-Datei 54d alt |
| `a2awais/Threat-Hunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vmkspv/lenspect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EndlessFractal/Threat-Intel-Feed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crowdsecurity/crowdsec` | GITHUB | IP-Datei 85d alt |
| `deeztek/Hermes-Secure-Email-Gateway` | GITHUB | IP-Datei 96d alt |
| `fastfire/deepdarkCTI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christinminor459/OnionClaw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SquidSec/SquidC5` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `K4N3CO/Lab-RATS` | GITHUB | Größe: 0 IPs |
| `The-Z-Labs/bof-launcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jm33-m0/emp3r0r` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abdullahbutt/wordfeather` | GITHUB | Größe: 0 IPs |
| `not-sekiun/Consortium` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VoidSecSoftwares/voidsyscall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rubby2001/Rshell-client` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ilynyne/discord-bot-ddos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kxiandaoyan/github-C2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LAME-Projects/stratum-c2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `b23r0/Heroinn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Team-intN18-SoybeanSeclab/prtstrike` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maxDcb/C2TeamServer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dn9uy3n/Modern-Red-Team-Infrastructure` | GITHUB | Zu alt: 36d |
| `mwakidenis/mwakidenis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CyberCoreAccess/BMHacker-Botnet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TomVN107080/packet-warden` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Samsung/CredSweeper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `87owo/PYAS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mondoohq/installer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tencent/AI-Infra-Guard` | GITHUB | IP-Datei 283d alt |
| `hahwul/smugglex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marven11/Fenjing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ostorlab/oxo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `awslabs/automated-security-helper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `akha-security/akca` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Samsung/LPVS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hounddogai/hounddog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frontendnetwork/veganify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `owenrumney/lazytrivy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tegos/travian-elephant-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AdventDevInc/kudu` | GITHUB | Größe: 0 IPs |
| `cifertech/ESP32-DIV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Atomburstofficial/geiger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Shiperoid/YT-DPI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khoren93/flutter_zxing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bitscoper/bitscoper_cyberkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yogeshojha/rengine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manticore-projects/aurscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `allanpk716/go-protocol-detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RetireJS/retire.js` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sefinek/Cloudflare-WAF-To-AbuseIPDB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sefinek/UFW-AbuseIPDB-Reporter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kristuff/abuseipdb-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fuko-php/masked` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splorp/wordpress-comment-blocklist` | GITHUB | Größe: 0 IPs |
| `popcar2/BadWebsiteBlocklist` | GITHUB | Größe: 0 IPs |
| `fortinetdev/terraform-provider-fortios` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaisero/fireREST` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x90skysn3k/brutespray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chaitin/SafeLine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bernardladenthin/BitcoinAddressFinder` | GITHUB | Größe: 0 IPs |
| `0xPugal/fuzz4bounty` | GITHUB | IP-Datei 251d alt |
| `mferland/libzc` | GITHUB | Größe: 0 IPs |
| `d4t4s3c/RSAcrack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qtc-de/remote-method-guesser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rtulke/AirJack` | GITHUB | Zu alt: 36d |
| `Touti-Sudo/Touti-Cracker` | GITHUB | Zu alt: 43d |
| `niyankhadka/crypto-wallet-bruteforce` | GITHUB | Zu alt: 44d |
| `theaog/spirit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `divinelabio/Kraken` | GITHUB | Zu alt: 726d |
| `jm33-m0/mec` | GITHUB | Zu alt: 1533d |
| `cynative/cynative` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benscha/KQLAdvancedHunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WithSecureOpenSource/chainsaw` | GITHUB | IP-Datei 683d alt |
| `TonyPhipps/SIEM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kunai-project/kunai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SlimKQL/Detections.AI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `The-Privacy-Commons-Institute/chrome-mal-ids` | GITHUB | Größe: 0 IPs |
| `spmedia/Threat-Actor-Usernames-Scrape` | GITHUB | Größe: 0 IPs |
| `OISF/suricata` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `okba14/FastScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rhacknarok/hacksguard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f-bader/DefenderAndSentinelQueries` | GITHUB | IP-Datei 231d alt |
| `backbay-labs/clawdstrike` | GITHUB | IP-Datei 31d alt |
| `calebevans/mulder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DeepTempo/socbench` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kdeldycke/meta-package-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lbr38/repomanager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arduino/go-apt-client` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AOSC-Dev/oma` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neur0map/glazepkg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rami3l/pacaptr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `S3N4T0R-0X0/APTs-Adversary-Simulation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `avaje/avaje-inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wimpysworld/deb-get` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aptly-dev/aptly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sous-chefs/apt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mexirica/aptui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cybozu-go/aptutil` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheDuffman85/linux-update-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `D7EAD/mkPIVM` | GITHUB | Zu alt: 41d |
| `bluscreenofjeff/Red-Team-Infrastructure-Wiki` | GITHUB | Zu alt: 358d |
| `tijme/kernel-mii` | GITHUB | Zu alt: 1236d |
| `tijme/amd-ryzen-master-driver-v17-exploit` | GITHUB | Zu alt: 1342d |
| `tijme/cmstplua-uac-bypass` | GITHUB | Zu alt: 1446d |
| `burpheart/CVE-2022-39197-patch` | GITHUB | Zu alt: 1459d |
| `bluscreenofjeff/MalleableC2Profiles` | GITHUB | Zu alt: 1476d |
| `bluscreenofjeff/AggressorScripts` | GITHUB | Zu alt: 1476d |
| `burpheart/CS_mock` | GITHUB | Zu alt: 1501d |
| `kpcyrd/authoscope` | GITHUB | Zu alt: 1010d |
| `zhuhaiuk/free-nodes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NiREvil/vless` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mahdibland/V2RayAggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `whoahaow/rjsxrd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Pawdroid/Free-servers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `peasoft/NoMoreWalls` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mahdi0024/ProxyCollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jichangtuijian-cheap/cheap-airports` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MahanKenway/Freedom-V2Ray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shenaba/2s-ui` | GITHUB | Größe: 1 IPs |
| `mheidari98/.proxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sub-store-org/Sub-Store` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Leon406/SubCrawler` | GITHUB | Größe: 0 IPs |
| `imatixofficel/Matix-edg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MHSanaei/3x-ui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Barabama/FreeNodes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `v2rayA/v2rayA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddify/Hiddify-Manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kwisma/Sub-Store-node` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2dust/v2rayN` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iss4cf0ng/Alien` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Abao130/xingjiabijichang` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mhyrzt/xrat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trickest/resolvers` | GITHUB | Overlap zu gering: 0.0% |
| `skjolber/3d-bin-container-packing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `praetorian-inc/brutus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `agourlay/zip-password-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spmedia/PhishingSecLists` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `daturadev/snapcrack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s-kachroo/SamsungPractice` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RozhakDev/Facemash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tp7309/TTPassGen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Coding-Enthusiast/FinderOuter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `acepanel/panel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `docker-mailserver/docker-mailserver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `robertdebock/ansible-role-fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomMoulard/fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crazy-max/docker-fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sous-chefs/fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yahuisme/vps-setup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mariusdjen/vpskit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `defense-cr/defense` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `foospidy/HoneyPy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheHive-Project/Cortex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `desaster/kippo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hgascon/acapulco` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jekil/UDPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `threatstream/shockpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/tanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `naorlivne/dshp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xme/dshield-docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ls1911/GenAIPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fw42/honeymap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERT-Polska/HSN-Capture-HPC-NG` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mfontani/kippo-stats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Masood-M/yalih` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SneakersInc/HoneyMalt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/glutton` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/StrutsHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marist-Innovation-Lab/DolosHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inguardians/toms_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thinkst/opencanary` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magisterquis/sshhipot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/conpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yvesago/imap-honey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrschyte/dockerpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `m4rco-/dorothy2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bartnv/portlurker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kungfuguapo/HoneyPress` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/bluepot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IllusiveNetworks-Labs/WebTrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kingtuna/go-emulators` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `androguard/androguard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `csirtgadgets/csirtg-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rep/hpfeeds` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `msurguy/Honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bjeborn/basic-auth-pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `graneed/bwpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ayrus/afterglow-cloud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OWASP/Python-Honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SentryPeer/SentryPeer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zeerg/helix-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mzweilin/ipv6-attack-detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jordan-wright/elastichoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `buffer/libemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/snare` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shjalayeri/pwnypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/honeypot-setup-script` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dmpayton/django-admin-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xiaoxiaoleo/HoneyMysql` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ahoernecke/ensnare` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qeeqbox/honeypots` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UHH-ISS/honeygrove` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `miguelraulb/spamhat` | GITHUB | IP-Datei 4528d alt |
| `cymmetria/ciscoasa_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `antonsatt/ssh-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gbrindisi/wordpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cryptix720/HUDINX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amv42/sshd-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WebDecoy/wordpress-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nsmfoo/antivmdetection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hexgolems/pint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `provos/honeyd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `knalli/honeypot-for-tcp-32764` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mojachieee/go-HoneyPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CanadianJeff/honeywrt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/MysqlPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aplura/Tango` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lnslbrty/potd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ashmckenzie/go-sshoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kryptoslogic/rdppot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joda32/owa-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/honeycomb_plugins` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mycert/ESPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/galah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gregcmartin/Kippo_JunOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fzerorubigd/go0r` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/apkinspector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shiva-spampot/shiva` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jadb/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LogoiLab/honeyup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betheroot/sticky_elephant` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cypwnpwnsocute/RedisHoneyPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/honeydet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MartinIngesen/HonnyPotter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/honeyku` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Joss-Steward/honeypotDisplay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CHH/stack-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johestephan/VerySimpleHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xBallpoint/trapster-community` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JustinAzoff/ssh-auth-logger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/honeylambda` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tnich/honssh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mkishere/sshsyrup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oguzy/ovizart` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `r0hi7/HoneySMB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `securitygeneration/Honeyport` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ciscocsirt/dhp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `darkarnium/kako` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DataSoft/Nova` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/micros_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magisterquis/sshlowpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pjlantz/Hale` | GITHUB | IP-Datei 5895d alt |
| `czardoz/hornet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Novetta/delilah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `d1str0/drupot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `batchmcnulty/Malbait` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sjinks/mysql-honeypotd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `citronneur/rdpy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `buffer/pylibemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thomaspatzke/Log4Pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrheinen/lophiid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpyorre/IntelligentHoneyNet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/honeyfs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/flux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `freak3dot/wp-smart-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/medpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `freak3dot/smart-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christophe77/express-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lcashdol/WAPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f0rw4rd/potsnitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:devhops/fail2banreports-deletion_scheduled-44190` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `borestad/firehol-mirror` | GITHUB | Größe: 2620661 IPs |
| `delphisecurity/xaidr` | GITHUB | Größe: 0 IPs |
| `leonardoprimero/bruriah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CW-lucky/fuse-audio-labs-ocelot-clipper-edition` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ShehabRady223/e-commerceNest.js` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kudakwashechanda-byte/Bee-Swarm-Task-Automation-Suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `juncaj93/Fantasy-Analyst` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DanieleS/ratatoskr-telemetry-views` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mzi06/rag-security-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ericferrazp/Veto` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Chain305/chainsaw-core` | GITHUB | Größe: 1 IPs |
| `Hercigs/sandbox-forge-gateway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Har497/panda-security-generator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elroynbenjamins/RisingGuildmaster` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vegaleonele/github-polls-voter-auth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mnsky-tyan/mnvoice` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brian-kane/dnd-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `screem500/prompt-injection-auditor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `georgiosxristianidis-a11y/athlete-pro-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `clutesd/Godbot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bgm6335/Stark-Hub-Forge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Blackdemon200/BlackDemonAV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dicklesworthstone/frankengit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `scriptzteam/TorRelayWatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s4mstruthers/Lucidfish` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `testaolivier10-del/testaolivier10-del.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jmd8590-source/hilorojo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nuku/Emberhold-Automation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `libincoding/ADVANCED-SOC-LAB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pharanyx-labs/Horus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Buja-OS/buja` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `niceyayale/opentrojan-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jcfenuchi/K8S-traefik-gateway-routes-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bhuvana141107/AQUA-SHIELD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PRADHUMAN-SINGH-1/h1-bounty-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abhishekdhautre/Private-Coded-Chat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ivankovic/stop-bots` | GITHUB | Größe: 0 IPs |
| `dittisronterry3/Emsisoft-Emergency-Kit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Consoder/SKIT-CS-2023-2027-28` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Pedroxious/Sentinel-SecOps` | GITHUB | Größe: 4 IPs |
| `L-jh40/gomoku-vs-go` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `riddler/encryptor_ecto` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `santosaganyrepo/Ego-lines-Automotive` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chaudharyaltaf2000/nayab-lms-0.9` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `messi116/SentinelX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mathewsPR/pageplain` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hkthsnb100/Algorius-Net-Viewer-2-Optimized-Release` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `projectmentor/hive-mind` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lukstafi/ludics-lite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bas1231/onderzoek` | GITHUB | Größe: 0 IPs |
| `kskr2571-cell/Elden-Ring-Live-Editor-Overlay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ChristoAnsek/audited-change-gate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JYOTIRMAY25/HHGOA-Agentic-Fraud-Investigation-System` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vimtra/Vimtra_Chennai_Lions_GC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rubentalstra/FerroEHR` | GITHUB | Größe: 0 IPs |
| `hitch-628083obscurer/Escape-Immersion-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FaizanAbbas512/Sentrix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tstone-1/tpdf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kokosro/factory-driver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `apreciojusto26/hotmart-recetas-diabeticos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gilandeya/trendnews` | GITHUB | Größe: 0 IPs |
| `yared2016/chess-game` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JunXieX/MikuHAProxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `petrkrock/crmvsemzapchasti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alimtvnetwork/gitmap-v28` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BAder82t/Veil` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vinitmishraaa/RAKSHASETU` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ardaninsaturnu/biinsaat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kritika-Panwar-151/kognivera2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rebizzz/aur-sentry` | GITHUB | Größe: 0 IPs |
| `memduhkutulu-design/Smart-DNS-Proxy-For-Streaming` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maxwellpajaro-dot/McAfee-Stinger-13.0.0.110` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schancel/scrubbed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `electrocrem/gits` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

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
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 11,656 | 64.3% | 938 | 2026-09-04 |
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
*Generiert: 2026-09-24 19:54 CEST (Europe/Berlin)*