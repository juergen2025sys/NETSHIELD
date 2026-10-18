# Auto Feed Discovery – Report
**Aktualisiert:** 2026-10-18 11:03 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 14 |
| Kandidaten gesamt | **12463** |
| davon GitHub (Topics+Code) | **12368** |
| davon GitLab | **95** |
| davon Awesome-Lists | **2200** |
| Tools/Libraries vor Eval gefiltert | **977** |
| davon Hard-Reject (awesome-Liste etc.) | **230** |
| EVAL-Kandidaten (nach Stratifizierung) | **268** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **268** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **267** |
| Neu angenommene Feed-Dateien | **6** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **194** |
| Abgelehnte Repositories (dieser Run) | **267** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **200** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **138163** |
| SQLite-Refresh-Cache-Hits | **8/207** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Repo zu alt (>30d) | **188** |
| Keine IP-Datei im Repo | **66** |
| IP-Datei veraltet (>30d) | **12** |
| Falsche Größe (<30 / >2,000,000 IPs) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `claudiusdecimius_ioc_ipsets_firehol_level4` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 175,298 | 17.9% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 16,846 | 59.1% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 9,628 | 80.7% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_tor_exits` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 1,209 | 69.1% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_sblam` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 1,159 | 30.3% | 0.0% | 0 | 🆕 NEU |
| `telekom_security_listbot` | [telekom-security/listbot](https://github.com/telekom-security/listbot) | GITHUB | 482 | 10.4% | 0.0% | 22 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `SHAdd0WTAka/Zen-Ai-Pentest` | GITHUB | IP-Datei 225d alt |
| `Johnng007/Live-Forensicator` | GITHUB | IP-Datei 54d alt |
| `SEKOIA-IO/documentation` | GITHUB | Größe: 0 IPs |
| `gebalamariusz/cloud-audit` | GITHUB | IP-Datei 110d alt |
| `computablefacts/cywise` | GITHUB | IP-Datei 73d alt |
| `aaravshah1311/Agent-2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aw-junaid/Hacking-Tools` | GITHUB | Zu alt: 60d |
| `leos565/clawedr` | GITHUB | Zu alt: 222d |
| `DaRuudii/qradar-utils` | GITHUB | Zu alt: 261d |
| `mthcht/ThreatHunting-Keywords` | GITHUB | Zu alt: 440d |
| `mikeroyal/Open-Source-Security-Guide` | GITHUB | Zu alt: 478d |
| `demisto/content` | GITHUB | IP-Datei 227d alt |
| `specterjwg/ipfeeds` | GITHUB | Zu alt: 63d |
| `jixserver/free-for-dev` | GITHUB | Zu alt: 794d |
| `gerryguy311/Free_CyberSecurity_Professional_Development_Resources` | GITHUB | Zu alt: 249d |
| `moloch--/RootTheBox` | GITHUB | Zu alt: 45d |
| `onegayunicorn/invisible-pressure-platform` | GITHUB | Zu alt: 65d |
| `1c7/Crash-Course-Computer-Science-Chinese` | GITHUB | Zu alt: 51d |
| `VortexisTV/Android-Proxy-Botnet-IOC-Scanner` | GITHUB | Zu alt: 105d |
| `mitre/advmlthreatmatrix` | GITHUB | Zu alt: 1270d |
| `MindfulLearner/dimaNet-homeLabServer` | GITHUB | Zu alt: 113d |
| `ramimac/aws-customer-security-incidents` | GITHUB | Zu alt: 39d |
| `malsearchs/Pure-Malware-Development` | GITHUB | Zu alt: 658d |
| `trackawesomelist/trackawesomelist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zeyad-Azima/Offensive-Resources` | GITHUB | Zu alt: 313d |
| `BR-IDL/PaddleViT` | GITHUB | Zu alt: 1502d |
| `xzcrpw/blackwall` | GITHUB | Zu alt: 184d |
| `AlaBouali/bane` | GITHUB | Zu alt: 503d |
| `Dyakonov/DL` | GITHUB | Zu alt: 1223d |
| `spac3gh0st00/Cybersecurity-Threat-Intelligence-Dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AfterPacket/war-room` | GITHUB | Zu alt: 228d |
| `decrypto-org/blockchain-papers` | GITHUB | Zu alt: 1267d |
| `equalitie/BotHound` | GITHUB | Zu alt: 3568d |
| `harshilpatel1799/Iot-Cyber-Security-with-Machine-Learning-Research-Project` | GITHUB | Zu alt: 2024d |
| `pooblic/pooplace` | GITHUB | Zu alt: 1219d |
| `harvard-itsecurity/qradar-seculert-push` | GITHUB | Zu alt: 4730d |
| `paulveillard/cybersecurity-malware-analysis` | GITHUB | Zu alt: 1324d |
| `alphaSeclab/injection-stuff` | GITHUB | Zu alt: 2337d |
| `hmaccelerate/DGA_Detection` | GITHUB | Zu alt: 2596d |
| `Yamuna-97/EmailThreatDetector` | GITHUB | Zu alt: 40d |
| `Fs00/Win10BloatRemover` | GITHUB | Zu alt: 271d |
| `Jatinkumar78/PacketIQ` | GITHUB | Zu alt: 52d |
| `lminy/BotnetDetectionThesis` | GITHUB | Zu alt: 2837d |
| `alexandergrgIA/spectrax-ai` | GITHUB | Zu alt: 138d |
| `Smaash/quasibot` | GITHUB | Zu alt: 4276d |
| `pbscybsec/Threat-Intelligence` | GITHUB | Zu alt: 1116d |
| `tunnckoCore/resources` | GITHUB | Zu alt: 2385d |
| `cybershujin/Threat-Actors-use-of-Artifical-Intelligence` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lobsec/BlocklistTracker` | GITHUB | Zu alt: 1166d |
| `digitalarche/OnlineToolsForBlueTeam` | GITHUB | Zu alt: 2420d |
| `naev/naev` | GITHUB | IP-Datei 95d alt |
| `NorthOfNull/BotnetDetectionEngine` | GITHUB | Zu alt: 2009d |
| `matchylabs/matchy-wireshark-plugin` | GITHUB | Zu alt: 98d |
| `Lucent-Grid/the-open-osint-board` | GITHUB | Zu alt: 152d |
| `ISorokos/SafeML` | GITHUB | Zu alt: 45d |
| `Condor2026/Nebula_AntiScan2` | GITHUB | Zu alt: 85d |
| `NethServer/nethsecurity` | GITHUB | IP-Datei 32d alt |
| `renisac/CIF3-pwsh` | GITHUB | Zu alt: 1299d |
| `JMousqueton/C2-Tracker` | GITHUB | Zu alt: 603d |
| `szizzo522/my-personal-website` | GITHUB | Zu alt: 183d |
| `alexverboon/SentinelTIUploadToolkit` | GITHUB | Zu alt: 825d |
| `alsk1992/instagram-ai-agent` | GITHUB | Zu alt: 180d |
| `hoardcti/c2-infrastructure` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `moimran/blacklist-IP` | GITHUB | Zu alt: 4003d |
| `spamhaus/spamassassin-dqs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Laibacodes/threat-intel-llm-summarizer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jaytaylor/unix-fortune-archive` | GITHUB | Zu alt: 2581d |
| `technicaldada/BEST-HACKING-TOOLS` | GITHUB | Zu alt: 379d |
| `adulau/dcu-tools` | GITHUB | Zu alt: 2867d |
| `Tayanithaa/Multiagent_Cybersecurity_Intelligent_system` | GITHUB | Zu alt: 147d |
| `umbrae/reddit-top-2.5-million` | GITHUB | Zu alt: 2381d |
| `uiuc-ischool-scanr/WikiCSSH` | GITHUB | Zu alt: 2245d |
| `ge-high-assurance/VERDICT` | GITHUB | Zu alt: 787d |
| `kallyaleksiev/quantum-gaps` | GITHUB | Zu alt: 516d |
| `RageAlpha/AgentNIDS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swam92/datasetsProject` | GITHUB | Zu alt: 4320d |
| `nmit-1NT23CS267/Generative-AI-for-Automated-Cyber-threat-prediction-and-response` | GITHUB | Zu alt: 52d |
| `gladiopeace/Files-Indexer` | GITHUB | Zu alt: 1576d |
| `bdkaoutar/SOC-AI` | GITHUB | Zu alt: 285d |
| `mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites` | GITHUB | Zu alt: 1098d |
| `mitchellkrogza/fail2ban-useful-scripts` | GITHUB | Zu alt: 3042d |
| `mitchellkrogza/linux-server-administration-scripts` | GITHUB | Zu alt: 3484d |
| `derhuerst/email-providers` | GITHUB | Zu alt: 362d |
| `ThreatMon/ThreatMon-Daily-C2-Feeds` | GITHUB | Zu alt: 1026d |
| `adhdproject/spidertrap` | GITHUB | Zu alt: 2307d |
| `firehol/iprange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `firehol/firehol` | GITHUB | Zu alt: 201d |
| `carbonblack/active_c2_ioc_public` | GITHUB | Zu alt: 1420d |
| `OktayAlver/siberkapan` | GITHUB | Zu alt: 55d |
| `noctiro/stormin` | GITHUB | Zu alt: 161d |
| `Bert-JanP/Incident-Response-Powershell` | GITHUB | Zu alt: 145d |
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2229d |
| `inversify/InversifyJS` | GITHUB | Zu alt: 333d |
| `midwayjs/midway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anjoy8/Blog.Core` | GITHUB | Zu alt: 185d |
| `ets-labs/python-dependency-injector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typestack/typedi` | GITHUB | Zu alt: 354d |
| `jeffijoe/awilix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oblac/jodd` | GITHUB | Zu alt: 916d |
| `w3tecch/express-typescript-boilerplate` | GITHUB | Zu alt: 1260d |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellokaton/java-bible` | GITHUB | Zu alt: 1709d |
| `samber/do` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PHP-DI/PHP-DI` | GITHUB | Zu alt: 291d |
| `appsquickly/typhoon` | GITHUB | Zu alt: 2128d |
| `nutzam/nutz` | GITHUB | Zu alt: 75d |
| `unitycontainer/unity` | GITHUB | Zu alt: 1001d |
| `gustavopsantos/Reflex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zycgit/hasor-old` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `reactiveui/splat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ntxinh/AspNetCore-DDD` | GITHUB | Zu alt: 294d |
| `danielpalme/IocPerformance` | GITHUB | Zu alt: 1186d |
| `YairHalberstadt/stronginject` | GITHUB | Zu alt: 475d |
| `forrest-orr/moneta` | GITHUB | Zu alt: 946d |
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VictorTzeng/Zxw.Framework.NetCore` | GITHUB | Zu alt: 48d |
| `exilon/QuickLib` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anakic/Jot` | GITHUB | Zu alt: 373d |
| `golobby/container` | GITHUB | Zu alt: 416d |
| `yoyofx/yoyogo` | GITHUB | Zu alt: 912d |
| `0x27/linux.mirai` | GITHUB | Zu alt: 3530d |
| `SwingFrog/Summer` | GITHUB | Zu alt: 549d |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `suites-dev/suites-unit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `farseer-go/fs` | GITHUB | Zu alt: 119d |
| `EcsRx/ecsrx` | GITHUB | Zu alt: 485d |
| `roadwy/DefenderYara` | GITHUB | Zu alt: 157d |
| `Savory/Danet` | GITHUB | Zu alt: 62d |
| `thiagobustamante/typescript-ioc` | GITHUB | Zu alt: 829d |
| `bingcool/swoolefy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafaelfgx/DotNetCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gendigitalinc/ioc` | GITHUB | IP-Datei 1599d alt |
| `ivlevAstef/DITranquillity` | GITHUB | Zu alt: 164d |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pengweiqhca/Xunit.DependencyInjection` | GITHUB | Zu alt: 54d |
| `binghe001/BingheGuide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brianway/spring-learning` | GITHUB | Zu alt: 3702d |
| `midwayjs/midway-faas` | GITHUB | Zu alt: 2299d |
| `yinguangyao/blog` | GITHUB | Zu alt: 99d |
| `mwemuorg/mwemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `urfnet/URF.Core` | GITHUB | Zu alt: 760d |
| `owja/ioc` | GITHUB | Zu alt: 775d |
| `zazoomauro/node-dependency-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inversify/monorepo` | GITHUB | IP-Datei 359d alt |
| `tshemsedinov/Patterns-JavaScript` | GITHUB | Zu alt: 252d |
| `d1mnewz/interviews` | GITHUB | Zu alt: 1929d |
| `eggjs/tegg` | GITHUB | Zu alt: 41d |
| `ditekshen/detection` | GITHUB | Zu alt: 716d |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loresoft/Injectio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zheksoon/dioma` | GITHUB | Zu alt: 905d |
| `d3fvxl/di` | GITHUB | Zu alt: 1037d |
| `testdeck/testdeck` | GITHUB | Zu alt: 634d |
| `gnaeus/react-ioc` | GITHUB | Zu alt: 1081d |
| `intentor/adic` | GITHUB | Zu alt: 1896d |
| `urfnet/URF.NET` | GITHUB | Zu alt: 3070d |
| `Go-To-Byte/DouSheng` | GITHUB | Zu alt: 1238d |
| `molszanski/iti` | GITHUB | Zu alt: 46d |
| `hidevopsio/hiboot` | GITHUB | Zu alt: 132d |
| `dry-rb/dry-auto_inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wzhudev/redi` | GITHUB | Zu alt: 36d |
| `agileago/vue3-oop` | GITHUB | Zu alt: 485d |
| `assafmo/xioc` | GITHUB | Zu alt: 2373d |
| `aalex954/evilginx2-TTPs` | GITHUB | Zu alt: 550d |
| `artberri/diod` | GITHUB | Zu alt: 744d |
| `wix-incubator/obsidian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `z4kn4fein/stashbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Puresharper/Puresharp` | GITHUB | Zu alt: 2817d |
| `xpleemoon/XModulable` | GITHUB | Zu alt: 3179d |
| `MySixGod/SpringImpl_v2.0` | GITHUB | Zu alt: 3393d |
| `exuanbo/di-wise` | GITHUB | Zu alt: 613d |
| `TAKETODAY/today-infrastructure` | GITHUB | IP-Datei 281d alt |
| `Koatty/koatty` | GITHUB | IP-Datei 688d alt |
| `jbreckmckye/node-typescript-architecture` | GITHUB | Zu alt: 1053d |
| `100nm/python-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zovajs/zova` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zzzzbw/doodle` | GITHUB | Zu alt: 1584d |
| `jsuarezruiz/xamarin-forms-perf-playground` | GITHUB | Zu alt: 1410d |
| `shihabmridha/nodejs-repository-pattern-and-ioc` | GITHUB | Zu alt: 589d |
| `401trg/detections` | GITHUB | Zu alt: 2013d |
| `roo-oliv/injectable` | GITHUB | Zu alt: 409d |
| `NullArray/Mimir` | GITHUB | Zu alt: 2805d |
| `vuldb/cyber_threat_intelligence` | GITHUB | Zu alt: 76d |
| `ecomfe/uioc` | GITHUB | Zu alt: 3292d |
| `vercube/vercube` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nikku/didi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AsenaJs/Asena` | GITHUB | Zu alt: 46d |
| `mnasyrov/ditox` | GITHUB | Zu alt: 84d |
| `typesoft/container-ioc` | GITHUB | Zu alt: 2458d |
| `ZihanType/rudi` | GITHUB | Zu alt: 656d |
| `scanurag/FoodFrenzy` | GITHUB | Zu alt: 305d |
| `nicolascotton/nject` | GITHUB | Zu alt: 111d |
| `wessberg/DI-compiler` | GITHUB | Zu alt: 717d |
| `dmitryb-dev/waiter` | GITHUB | Zu alt: 978d |
| `uditalias/injex` | GITHUB | Zu alt: 362d |
| `go-spring-rip/spring-core` | GITHUB | Zu alt: 129d |
| `bootsrc/containerx` | GITHUB | Zu alt: 2835d |
| `Rick-van-Dam/Singularity` | GITHUB | Zu alt: 2225d |
| `mbierlee/poodinis` | GITHUB | Zu alt: 283d |
| `opensumi/di` | GITHUB | Zu alt: 401d |
| `conix-security/BTG` | GITHUB | Zu alt: 2882d |
| `go-spring-projects/go-spring` | GITHUB | Zu alt: 163d |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `100cm/thunder` | GITHUB | Zu alt: 3813d |
| `absingh31/Tor_Spider` | GITHUB | Zu alt: 3160d |
| `appsquickly/pilgrim` | GITHUB | Zu alt: 1345d |
| `maou-shonen/hono-simple-DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs` | GITHUB | Zu alt: 2016d |
| `di-ninja/di-ninja` | GITHUB | Zu alt: 564d |
| `HangfireIO/Hangfire.Autofac` | GITHUB | Zu alt: 646d |
| `krylosov-aa/context-async-sqlalchemy` | GITHUB | Zu alt: 126d |
| `ChistaDev/Chista` | GITHUB | Zu alt: 883d |
| `INotfound/Magic` | GITHUB | Zu alt: 1008d |
| `zhulik/pal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlyElhaddad/ThunderboltIoc` | GITHUB | Zu alt: 412d |
| `otavia-projects/otavia` | GITHUB | Zu alt: 139d |
| `enisn/DotNurseInjector` | GITHUB | Zu alt: 1027d |
| `xiuqianli1996/LSFramework` | GITHUB | Zu alt: 1048d |
| `tstromberg/ttp-bench` | GITHUB | Zu alt: 132d |
| `KnisterPeter/tsdi` | GITHUB | Zu alt: 1056d |
| `phantom0004/morpheus_IOC_scanner` | GITHUB | Zu alt: 613d |
| `OsmanKandemir/web-wordlist-generator` | GITHUB | Zu alt: 875d |
| `assafkip/huntkit` | GITHUB | IP-Datei 186d alt |
| `bdqfork/festival` | GITHUB | Zu alt: 2420d |
| `blacktop/docker-yara` | GITHUB | Zu alt: 1476d |
| `inversiland/inversiland` | GITHUB | Zu alt: 668d |
| `Washi1337/cilfi` | GITHUB | Zu alt: 74d |
| `byme8/ZeroIoC` | GITHUB | Zu alt: 516d |
| `sergeysychov/behaviour_inject` | GITHUB | Zu alt: 1127d |
| `0xDanielLopez/TweetFeed_code` | GITHUB | Zu alt: 1427d |
| `aloisdeniel/dioc` | GITHUB | Zu alt: 2371d |
| `d3fvxl/inject` | GITHUB | Zu alt: 2434d |
| `red-gold/ts-ui` | GITHUB | Zu alt: 864d |
| `jacoborus/wiremap` | GITHUB | Zu alt: 287d |
| `wenbo2018/mini-springframework` | GITHUB | Zu alt: 3206d |
| `FarseerNet/Farseer.Net` | GITHUB | Zu alt: 1325d |
| `imnbwd/FriendEditor` | GITHUB | Zu alt: 3502d |
| `mjirous/cinject` | GITHUB | Zu alt: 3251d |
| `iorate/ublacklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ruddernation-Designs/Adobe-URL-Block-List` | GITHUB | Zu alt: 129d |
| `marteinn/The-Big-Username-Blocklist` | GITHUB | Zu alt: 1831d |
| `XD-MHLOO/facebook-gql-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NyanSatan/kanzitools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evilsocket/bleah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sullo/nikto` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HyperDbg/HyperDbg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LanHikari22/GBA-IDA-Pseudo-Terminal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lief-project/LIEF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ianhan/BitmapFonts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `malcomvetter/ManagedInjection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swisscom/detections` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CravateRouge/bloodyAD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dnsdb/dnsdbq` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GemGeorge/SniperPhish` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `payloadbox/xxe-injection-payload-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lmacken/pyrasite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mgreen27/Powershell-IR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `globocom/huskyCI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hideckies/exploit-notes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `can1357/NoVmp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aappleby/smhasher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wetw0rk/AWAE-PREP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `raandree/ManagedPasswordFilter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `github/secure_headers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `csirtunicamp/flowsscripts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nakiami/mellivora` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 23,063 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 19,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,488 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,440 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,836 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,738 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,775 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,951 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,951 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,447 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 4,048 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,825 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 840 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 562 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 572 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 477 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 296 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,451 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,705 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 19,576 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 12,161 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 7,094 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,988 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 6,048 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 215,384 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,189 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 5,482 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,635 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 3,667 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,767 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 4,403 | 64.3% | 938 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 54,069 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,149 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,962 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 117,732 | 0.2% | 36 | 2026-07-05 |
| `telekom_security_listbot` | GITHUB | 482 | 10.4% | 22 | 2026-10-18 |
| `dinoz0rg_proxy_list` | GITHUB | 91,702 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,924 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 93,818 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 108,164 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,647 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 102,398 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,752 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 118,865 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 497 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 503,534 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,720 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 173,723 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 84,317 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 172,349 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 175,266 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 106,009 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 82,336 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 257,739 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 49,976 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 202,929 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,102 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 16,470 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 14,164 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 180,020 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 46,412 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 9,688 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,191 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 24,618 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 15,146 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 12,638 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 8,122 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,743 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,170 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 2,880 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,318 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 702 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,473 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 3,222 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,993 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,808 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 122,847 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,049 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 29,179 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 2,737 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 4,302 | 79.4% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,724 | 64.3% | 10 | 2026-10-11 |
| `ian_lusule_proxies` | GITHUB | 3,691 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,710 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,324 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 373,460 | 22.0% | 6 | 2026-07-08 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,300 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 67 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 105,081 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 90,860 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 23,076 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 111 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 90,880 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,412 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,687 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 177 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 18,969 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 18,096 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 25,271 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,382 | 31.1% | 1 | 2026-07-14 |
| `klonet_it_ip_threat_lists` | GITHUB | 120,464 | 51.5% | 1 | 2026-10-11 |
| `klonet_it_ip_threat_lists_blocklist_apache` | GITHUB | 9,277 | 9.7% | 1 | 2026-10-11 |
| `idleadmin_threatfeed` | GITHUB | 48,893 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 67,802 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,694 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 119,850 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 388 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,170 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 196,810 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,537 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 119,838 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 227,997 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 34,476 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 10,801 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 19,786 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,717 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 10,827 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 8,594 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,627 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 6,576 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,500 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,208 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,124 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,529 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 4,946 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,923 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 730 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 5,484 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,044 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,210 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,395 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,294 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,353 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,147 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,175 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,537 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,197 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,252 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 546 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,437 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,750 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,209 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 12,675 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,372 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 93,192 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 90,826 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 93,320 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 94,605 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 92,871 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 91,035 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 22,249 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 39,401 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 4,118 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,569 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,080 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 53,230 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 30,152 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 10,716 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 17,471 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 26 | 63.9% | 0 | 2026-08-12 |
| `zgzyh_malicious_website_detection` | GITHUB | 33,314 | 3.1% | 0 | 2026-08-15 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,314 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,817 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 6,270 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,498 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 1,505 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 717 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 281 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 6,381 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 96,455 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 94,287 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 91,169 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 90,196 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 89,030 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 28,736 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 2,718 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 2,681 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_20` | GITHUB | 184 | 92.3% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 789 | 76.9% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_24` | GITHUB | 157 | 90.4% | 0 | 2026-09-25 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,278 | 6.8% | 0 | 2026-10-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,219 | 63.9% | 0 | 2026-10-04 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 2,331 | 5.4% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_all_90d` | GITHUB | 6,280 | 61.9% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_aggressive` | GITHUB | 217 | 80.9% | 0 | 2026-10-11 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 175,298 | 17.9% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 16,846 | 59.1% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 9,628 | 80.7% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_tor_exits` | GITHUB | 1,209 | 69.1% | 0 | 2026-10-18 |
| `claudiusdecimius_ioc_ipsets_sblam` | GITHUB | 1,159 | 30.3% | 0 | 2026-10-18 |

---
*Generiert: 2026-10-18 11:03 CEST (Europe/Berlin)*