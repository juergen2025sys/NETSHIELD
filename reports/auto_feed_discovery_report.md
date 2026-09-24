# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-24 08:46 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 15 |
| Kandidaten gesamt | **11735** |
| davon GitHub (Topics+Code) | **11645** |
| davon GitLab | **90** |
| davon Awesome-Lists | **2202** |
| Tools/Libraries vor Eval gefiltert | **947** |
| davon Hard-Reject (awesome-Liste etc.) | **217** |
| EVAL-Kandidaten (nach Stratifizierung) | **443** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **443** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **442** |
| Neu angenommene Feed-Dateien | **7** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **185** |
| Abgelehnte Repositories (dieser Run) | **442** |
| davon GitLab abgelehnt | **10** |
| Feeds gesamt (aktiv) | **192** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **162214** |
| SQLite-Refresh-Cache-Hits | **0/186** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **281** |
| Repo zu alt (>30d) | **133** |
| Falsche Größe (<30 / >2,000,000 IPs) | **19** |
| IP-Datei veraltet (>30d) | **8** |
| Sonstige | **3** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `configserverapps_service_blocklists_ssh_1d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 4,018 | 80.5% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 3,332 | 79.4% | 0.0% | 10 | 🆕 NEU |
| `brandontroidl_blocklist` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 3,783 | 67.4% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_30d` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 3,503 | 69.2% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_30d` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 3,503 | 69.2% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_7d` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 908 | 61.7% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_24h` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 480 | 65.2% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_7d` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 908 | 61.7% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_24h` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 480 | 65.2% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_standard` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 122 | 52.5% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_standard` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 122 | 52.5% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `mthcht/ThreatIntel-Reports` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `murchie85/twitterCyberMonitor` | GITHUB | Zu alt: 1221d |
| `murchie85/murchie85.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kwiecien-rafal/histamine-fighter` | GITHUB | Größe: 0 IPs |
| `allenai/dolma` | GITHUB | Zu alt: 31d |
| `nickspaargaren/no-google` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RealCrazyAnonymous/Filter-Lists` | GITHUB | Zu alt: 43d |
| `BrowserWorks/waterfox` | GITHUB | IP-Datei 744d alt |
| `uBlockOrigin/uAssets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tribixbite/CleverKeys` | GITHUB | IP-Datei 66d alt |
| `trietptm/Security-News` | GITHUB | Zu alt: 1002d |
| `TamGamer97/spellbound` | GITHUB | Zu alt: 172d |
| `surprisetalk/licensure` | GITHUB | Zu alt: 938d |
| `pengelana/blocklist` | GITHUB | Größe: 0 IPs |
| `keboli/CTI-annotated-datasets` | GITHUB | Zu alt: 325d |
| `RepoAnalysis/RepoSnipy` | GITHUB | Zu alt: 956d |
| `Kilroy1337/ioc_lists` | GITHUB | Zu alt: 1116d |
| `visualstudioblyat/bushido` | GITHUB | Zu alt: 120d |
| `amount/secops-lists` | GITHUB | Zu alt: 336d |
| `Backlinko-LLC/2020-google-searches` | GITHUB | Zu alt: 2128d |
| `michredteam/RTbookNotes` | GITHUB | Zu alt: 816d |
| `NotaInutilis/Super-SEO-Spam-Suppressor` | GITHUB | Größe: 0 IPs |
| `goastian/midori-desktop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gfw-report/sp25-regional` | GITHUB | Zu alt: 501d |
| `dabi-team/someData` | GITHUB | Zu alt: 1428d |
| `cmndcntrlcyber/code-trainer-pipeline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `curtislbyrd/CyberVault` | GITHUB | Zu alt: 195d |
| `wessorh/yara-x-benchmarks` | GITHUB | Zu alt: 99d |
| `smart-rg/drafts` | GITHUB | Zu alt: 2393d |
| `0i0/deepme-crawler` | GITHUB | Zu alt: 1175d |
| `lxyeternal/IntelliRadar` | GITHUB | Zu alt: 218d |
| `jayala-29/svm2023-artifacts` | GITHUB | Zu alt: 1224d |
| `ArtDeuce/Semantics-Research` | GITHUB | Zu alt: 634d |
| `mitchellkrogza/apache-ultimate-bad-bot-blocker` | GITHUB | Overlap zu gering: 0.4% |
| `mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites` | GITHUB | Zu alt: 1074d |
| `mitchellkrogza/fail2ban-useful-scripts` | GITHUB | Zu alt: 3018d |
| `mitchellkrogza/linux-server-administration-scripts` | GITHUB | Zu alt: 3460d |
| `all-contributors/allcontributors.org` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `firehol/blocklist-ipsets` | GITHUB | Größe: 2619743 IPs |
| `firehol/iprange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `firehol/firehol` | GITHUB | Zu alt: 177d |
| `derhuerst/email-providers` | GITHUB | Zu alt: 338d |
| `ThreatMon/ThreatMon-Daily-C2-Feeds` | GITHUB | Zu alt: 1002d |
| `carbonblack/active_c2_ioc_public` | GITHUB | Zu alt: 1396d |
| `cbuijs/oisd` | GITHUB | Größe: 0 IPs |
| `alsyundawy/Microsoft-Office-For-MacOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cbuijs/ipasn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OktayAlver/siberkapan` | GITHUB | Zu alt: 31d |
| `Mohammedcha/gplay-scraper` | GITHUB | Zu alt: 312d |
| `Mohammedcha/UnityReskinGuard` | GITHUB | Zu alt: 1153d |
| `Mohammedcha/ReskinGuard` | GITHUB | Zu alt: 1154d |
| `Mohammedcha/Play-Apps-Sortering` | GITHUB | Zu alt: 2786d |
| `ebrasha/free-v2ray-public-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `noctiro/stormin` | GITHUB | Zu alt: 137d |
| `romainmarcoux/malicious-hash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mohammedcha/Keywords-Highlighter` | GITHUB | Zu alt: 2786d |
| `JasonLovesDoggo/caddy-defender` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2205d |
| `inversify/InversifyJS` | GITHUB | Zu alt: 309d |
| `midwayjs/midway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anjoy8/Blog.Core` | GITHUB | Zu alt: 161d |
| `ets-labs/python-dependency-injector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typestack/typedi` | GITHUB | Zu alt: 330d |
| `jeffijoe/awilix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oblac/jodd` | GITHUB | Zu alt: 892d |
| `w3tecch/express-typescript-boilerplate` | GITHUB | Zu alt: 1236d |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellokaton/java-bible` | GITHUB | Zu alt: 1685d |
| `samber/do` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PHP-DI/PHP-DI` | GITHUB | Zu alt: 267d |
| `appsquickly/typhoon` | GITHUB | Zu alt: 2104d |
| `nutzam/nutz` | GITHUB | Zu alt: 51d |
| `unitycontainer/unity` | GITHUB | Zu alt: 977d |
| `gustavopsantos/Reflex` | GITHUB | Zu alt: 98d |
| `zycgit/hasor-old` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `reactiveui/splat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ntxinh/AspNetCore-DDD` | GITHUB | Zu alt: 270d |
| `danielpalme/IocPerformance` | GITHUB | Zu alt: 1162d |
| `YairHalberstadt/stronginject` | GITHUB | Zu alt: 451d |
| `forrest-orr/moneta` | GITHUB | Zu alt: 922d |
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VictorTzeng/Zxw.Framework.NetCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `exilon/QuickLib` | GITHUB | Zu alt: 139d |
| `stanfrbd/cyberbro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anakic/Jot` | GITHUB | Zu alt: 349d |
| `golobby/container` | GITHUB | Zu alt: 392d |
| `yoyofx/yoyogo` | GITHUB | Zu alt: 888d |
| `SwingFrog/Summer` | GITHUB | Zu alt: 525d |
| `ciscocsirt/GOSINT` | GITHUB | Zu alt: 1234d |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `farseer-go/fs` | GITHUB | Zu alt: 95d |
| `suites-dev/suites` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EcsRx/ecsrx` | GITHUB | Zu alt: 461d |
| `roadwy/DefenderYara` | GITHUB | Zu alt: 133d |
| `Savory/Danet` | GITHUB | Zu alt: 38d |
| `thiagobustamante/typescript-ioc` | GITHUB | Zu alt: 805d |
| `bingcool/swoolefy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafaelfgx/DotNetCore` | GITHUB | Zu alt: 37d |
| `gendigitalinc/ioc` | GITHUB | Zu alt: 115d |
| `ivlevAstef/DITranquillity` | GITHUB | Zu alt: 140d |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pengweiqhca/Xunit.DependencyInjection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `binghe001/BingheGuide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brianway/spring-learning` | GITHUB | Zu alt: 3678d |
| `midwayjs/midway-faas` | GITHUB | Zu alt: 2275d |
| `yinguangyao/blog` | GITHUB | Zu alt: 75d |
| `prodaft/malware-ioc` | GITHUB | Zu alt: 324d |
| `mwemuorg/mwemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `urfnet/URF.Core` | GITHUB | Zu alt: 736d |
| `owja/ioc` | GITHUB | Zu alt: 751d |
| `zazoomauro/node-dependency-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tshemsedinov/Patterns-JavaScript` | GITHUB | Zu alt: 228d |
| `inversify/monorepo` | GITHUB | IP-Datei 335d alt |
| `d1mnewz/interviews` | GITHUB | Zu alt: 1905d |
| `eggjs/tegg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `baidu/CarbonGraph` | GITHUB | Zu alt: 689d |
| `ditekshen/detection` | GITHUB | Zu alt: 692d |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loresoft/Injectio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zheksoon/dioma` | GITHUB | Zu alt: 881d |
| `d3fvxl/di` | GITHUB | Zu alt: 1013d |
| `testdeck/testdeck` | GITHUB | Zu alt: 610d |
| `gnaeus/react-ioc` | GITHUB | Zu alt: 1057d |
| `GreedyBear-Project/GreedyBear` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mthcht/Purpleteam` | GITHUB | Zu alt: 643d |
| `intentor/adic` | GITHUB | Zu alt: 1872d |
| `urfnet/URF.NET` | GITHUB | Zu alt: 3046d |
| `Go-To-Byte/DouSheng` | GITHUB | Zu alt: 1214d |
| `hidevopsio/hiboot` | GITHUB | Zu alt: 108d |
| `molszanski/iti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dry-rb/dry-auto_inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wzhudev/redi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `agileago/vue3-oop` | GITHUB | Zu alt: 461d |
| `assafmo/xioc` | GITHUB | Zu alt: 2349d |
| `aalex954/evilginx2-TTPs` | GITHUB | Zu alt: 526d |
| `artberri/diod` | GITHUB | Zu alt: 720d |
| `wix-incubator/obsidian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `z4kn4fein/stashbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gensecaihq/Shai-Hulud-2.0-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xpleemoon/XModulable` | GITHUB | Zu alt: 3155d |
| `Puresharper/Puresharp` | GITHUB | Zu alt: 2793d |
| `MySixGod/SpringImpl_v2.0` | GITHUB | Zu alt: 3369d |
| `exuanbo/di-wise` | GITHUB | Zu alt: 589d |
| `TAKETODAY/today-infrastructure` | GITHUB | IP-Datei 257d alt |
| `Koatty/koatty` | GITHUB | Zu alt: 151d |
| `jbreckmckye/node-typescript-architecture` | GITHUB | Zu alt: 1029d |
| `100nm/python-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zovajs/zova` | GITHUB | Zu alt: 103d |
| `zzzzbw/doodle` | GITHUB | Zu alt: 1560d |
| `jsuarezruiz/xamarin-forms-perf-playground` | GITHUB | Zu alt: 1386d |
| `shihabmridha/nodejs-repository-pattern-and-ioc` | GITHUB | Zu alt: 565d |
| `401trg/detections` | GITHUB | Zu alt: 1989d |
| `roo-oliv/injectable` | GITHUB | Zu alt: 385d |
| `NullArray/Mimir` | GITHUB | Zu alt: 2781d |
| `vuldb/cyber_threat_intelligence` | GITHUB | Zu alt: 52d |
| `ecomfe/uioc` | GITHUB | Zu alt: 3268d |
| `vercube/vercube` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nikku/didi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AsenaJs/Asena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mnasyrov/ditox` | GITHUB | Zu alt: 60d |
| `typesoft/container-ioc` | GITHUB | Zu alt: 2434d |
| `ZihanType/rudi` | GITHUB | Zu alt: 632d |
| `scanurag/FoodFrenzy` | GITHUB | Zu alt: 281d |
| `nicolascotton/nject` | GITHUB | Zu alt: 87d |
| `wessberg/DI-compiler` | GITHUB | Zu alt: 693d |
| `dmitryb-dev/waiter` | GITHUB | Zu alt: 954d |
| `uditalias/injex` | GITHUB | Zu alt: 338d |
| `go-spring-rip/spring-core` | GITHUB | Zu alt: 105d |
| `bootsrc/containerx` | GITHUB | Zu alt: 2811d |
| `Rick-van-Dam/Singularity` | GITHUB | Zu alt: 2201d |
| `mbierlee/poodinis` | GITHUB | Zu alt: 259d |
| `opensumi/di` | GITHUB | Zu alt: 377d |
| `conix-security/BTG` | GITHUB | Zu alt: 2858d |
| `go-spring-projects/go-spring` | GITHUB | Zu alt: 139d |
| `absingh31/Tor_Spider` | GITHUB | Zu alt: 3136d |
| `100cm/thunder` | GITHUB | Zu alt: 3789d |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `appsquickly/pilgrim` | GITHUB | Zu alt: 1321d |
| `ioc-fang/ioc-fanger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `modern-python/modern-di` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maou-shonen/hono-simple-DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs` | GITHUB | Zu alt: 1992d |
| `di-ninja/di-ninja` | GITHUB | Zu alt: 540d |
| `HangfireIO/Hangfire.Autofac` | GITHUB | Zu alt: 622d |
| `ChistaDev/Chista` | GITHUB | Zu alt: 859d |
| `krylosov-aa/context-async-sqlalchemy` | GITHUB | Zu alt: 102d |
| `INotfound/Magic` | GITHUB | Zu alt: 984d |
| `zhulik/pal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlyElhaddad/ThunderboltIoc` | GITHUB | Zu alt: 388d |
| `otavia-projects/otavia` | GITHUB | Zu alt: 115d |
| `enisn/DotNurseInjector` | GITHUB | Zu alt: 1003d |
| `xiuqianli1996/LSFramework` | GITHUB | Zu alt: 1024d |
| `tstromberg/ttp-bench` | GITHUB | Zu alt: 108d |
| `MISP/misp-workbench` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `exp0se/harbinger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InQuest/omnibus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ciscocsirt/gosint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `silascutler/MalPipe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stephenbrannon/IOCextractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4d31/sqhunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/malstrom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TAXIIProject/yeti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fhightower/onemillion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KasperskyLab/klara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yahoo/PyIOCe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Netflix/Scumblr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BinaryDefense/goatrider` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/jager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dougiep16/actortrackr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityRiskAdvisors/sra-taxii2-server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CylanceSPEAR/CyBot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `facebook/ThreatExchange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheHive-Project/Hippocampe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/Loki` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mandiant/ioc_writer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `paulpc/nyx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mgeide/poortego` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stratosphereips/Manati` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `michael-yip/ThreatTracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abhinavbom/Threat-Intelligence-Hunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spacepatcher/FireHOL-IP-Aggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ptr32Void/OSTrICa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spacepatcher/softrace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jheise/threatcmd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `STIXProject/stix-viz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SupportIntelligence/Icewater` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ioc-fang/ioc_fanger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yara-Rules/rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yelp/threat_intel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `csirtgadgets/bearded-avenger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EclecticIQ/OpenTAXII` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/Forager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EclecticIQ/cabby` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brianwarehime/threatnote` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HurricaneLabs/machinae` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kbandla/APTnotes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johestephan/ibmxforceex.checker.py` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kx499/ostip` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InQuest/python-iocextract` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `armbues/ioc_parser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CrowdStrike/CrowdFMS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/cacador` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpsenior/threataggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TAXIIProject/libtaxii` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fhightower/ioc-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jheise/threatcrowd_api` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PaloAltoNetworks/minemeld` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tripwire/tardis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `QTek/QRadio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abusesa/abusehelper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lookingglass/opentpx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mlsecproject/combine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `1aN0rmus/TekDefense-Automater` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mlsecproject/tiq-test` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `S03D4-164/Hiryu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aboutsecurity/rastrea2r` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ocmdev/rita` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gfoss/phpmyadmin_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omererdem/honeything` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HoneySat/honeysat-deploy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityTW/delilah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/MTPot` | GITHUB | IP-Datei 3605d alt |
| `yuchincheng/HpfeedsHoneyGraph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `urule99/jsunpack-n` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hbhzwj/imalse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sec51/honeymail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `secureworks/dcept` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betheroot/pghoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GetPageSpeed/nginx-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sefcom/honeyplc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/canarytokendetector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mdp/honeypot.go` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `balte/TelnetHoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `huuck/ADBHoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MalwareTech/CitrixHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/servletpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexbredo/honeypot-ftp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xlfe/cowrie2neo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WebDecoy/FCaptcha` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ppacher/honeyssh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marist-Innovation-Lab/PasitheaHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sreinhardt/Docker-Honeynet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/ghost-usb-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ajackal/arctic-swallow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sahilm/hived` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `packetflare/amthoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `phin3has/mailoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dutchcoders/troje` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sk4ld/gridpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fygrave/honeyntp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fnzv/YAFH` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rubenespadas/DionaeaFR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/glastopf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `threatstream/mhn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aelth/ddospot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `glaslos/honeyprint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tillmannw/honeytrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jesparza/peepdf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/phoneyc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fofapro/fapro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thinkst/canarytokens` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hexgolems/schem` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `torque59/nosqlpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `katkad/Glastopf-Analytics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `run41/honey_ports` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexbredo/honeypot-camera` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eymengunay/EoHoneypotBundle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PaulMaddox/gohoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/honeyalarmg2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gosecure/pyrdp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dtag-dev-sec/tpotce` | GITHUB | IP-Datei 105d alt |
| `hatching/vmcloak` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deroux/longitudinal-analysis-cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:oceaniagov-minitrue/minitrue-unpersons` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:Maingron/fascist-blocklist` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:verdettoqr/link-safety-list` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:oceaniagov-minitrue/minitrue-extension` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:DanDawson/probeguard-404-firewall-cloudflare` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:kikinovak/rh_setup_fail2ban` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:ochita/arcferrix-app-releases` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:andersonmavi30/docker_firewall_automation` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:Ramisto/onephish` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:toxy4ny/BL00DYM4RY` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brandontroidl/blocklist` | GITHUB | Identischer Inhalt wie brandontroidl_blocklist |
| `brandontroidl/blocklist` | GITHUB | Identischer Inhalt wie brandontroidl_blocklist |
| `brandontroidl/blocklist` | GITHUB | Identischer Inhalt wie brandontroidl_blocklist |
| `Peytech20/active-directory-wazuh-attack-detection-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `noainred/The.DVC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jerryhieu2102/lattice-fintech` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rom/Xproxy` | GITHUB | Größe: 0 IPs |
| `Jadax/VibeGaffer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mohit2647-png/SOC--Malware-Analysis-Detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `subwindels-hash/House-Rent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenVibers/OpenVibe.Blog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `invarislabs/invaris-agentsec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Correia-jpv/fucking-games` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yousefjan2007-crypto/robinhood-screener` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marco-naka/gold` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rekkei/TAC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ModernNomad-98/Project-Aegis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `luxingcom/LuZ-0.1.7-DeepSeek-v4.1-Flash-DGXspark-TP4-Ring` | GITHUB | Größe: 0 IPs |
| `abdul259wasay-bot/PUBLIC-VM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `barghsadev/barghsa-core` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0s1r1s/a11y-adjust` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yashuhb18/MediLink` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Blue42hand/commander-gym` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alevsk/laya-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sgoxel/The_Advisor_Game` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Komaster12454/sdg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iucsc0/notify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `daniel-ospina/tortoise` | GITHUB | Größe: 0 IPs |
| `Anbu-00001/Cage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andersonflorez724-commits/escaneo_de_documentos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GhaderiSaber/AcademicSuite` | GITHUB | Größe: 0 IPs |
| `gycha0109-beep/MapleFly` | GITHUB | Größe: 0 IPs |
| `claudekovalenko/nplsocal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `timedwile33/Rooted-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `creativeprofit22/idle-clicker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `overcuriousity/effractor` | GITHUB | Größe: 0 IPs |
| `mihailinl/astra-registry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Latand/delegatus` | GITHUB | Größe: 0 IPs |
| `Baranidharan16/Mail-Shield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ayeshamallick6514-aye/UNITY` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ex4n1m0/OnlyHumans` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `itsaainaa/fake_news_detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stoatworks-labs/mynah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mishnit/daily-darshan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `giuseppemineo685-beep/atlantis-polymarket-screening` | GITHUB | Größe: 0 IPs |
| `Vishalkondi/J-J-CONSULTING` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `obligate-8-deader/Honeycomb-Community-Edition` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `d4m-dev/ubuntu-d4m` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `willrydh/Into-The-Politicalverse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dcc-mcp/dcc-mcp-capcut` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dbourdeau/cyphersolver` | GITHUB | Größe: 0 IPs |
| `achamseddine/SolarDashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Baranidharan16/sih-email-forensics-full` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tanushh18/Deal_Radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `4kercc/workbuddy2api-panel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mohamedzop/usdt-lyd-scanner` | GITHUB | Größe: 0 IPs |
| `Solizardking/solana-clawd` | GITHUB | IP-Datei 112d alt |
| `DereC4/internships-and-newgrad` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BlackMatter-Studios/opencaller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dhanunjaya-kd/fo-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coiffing-charging35/Game-Quest-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ilano13013/1-better` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AndreeSalazar/BMO-X-x86-64` | GITHUB | Größe: 0 IPs |
| `nutted64-heap/Project-PITT-Community-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hyacinth981517taboo/Backrooms-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/fucking-enhansome-sysadmin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tappu001/digital-lens` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `metkarirohit6-hub/ShieldCheck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sumipan/issuesmith` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crypt0rr/EdgeWatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JulienDelquignies/three-js-aaa-agent-skill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Shobhit000s/privacy-aware-cicd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ranxianglei/acp-kernel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CerberusSolutions/TRXController` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kundanvarma/genalpha-bss` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome_ai_agents` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `import-punt-42853/ILL-Optimized-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MoonGameTechnology/MoonGame` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kartik-ins/authguard-service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mappings-copings-1145/Redemption-of-the-Damned-Prototype-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nighpocketed3/Pregnant-Roommates-Send-Help-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jam0k/Ransomware-Intel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aneek22112007-tech/mcp-a2a-secure` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dobidu/forrobox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `canyuda/agent-guard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ekaynac/onprem-ai-adoption-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EternalNight996/findany` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JiRaska/open-bank-oss` | GITHUB | IP-Datei 39d alt |
| `Krajcara/InfraLoom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `scarlettzhangxh/exitliq` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wights38-legrooms/Tropico-7-Prototype-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sriram-Codes-SW/doorprints` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RodrigoVergaraCO/wisip` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `superogira/sdr_rg35xx_plus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inv8rey/incubator-baguio-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anuktasharma1130-dev/dark_threat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mappings-copings-1145/Long-Gone-Prototype-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `YueyuHoshizora/bushwhack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ihsanmp/Open-Terminal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `1600014942/FrontendQD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `soyunninja/kankaku` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `agencybankai-hash/bankai-finalsite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eranoix/linux-control-plane` | GITHUB | Größe: 0 IPs |
| `OpenTacit/tacit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deputy-proxy/cr8or` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Paius-George/Job-Tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hgrosche95/portfolio-page` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ConstraintPanther/usb-drive-encryptor-utility` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coilingadjuring9/Control-Resonant-Beta-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `razzietheman/android-keyboard` | GITHUB | Größe: 0 IPs |
| `benjasantu01-dotcom/limpieza-total-omega` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DeepMidgeLure/remote-camera-access-controller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `golmman/atomic_solver` | GITHUB | Größe: 0 IPs |
| `JohnLuman/JLR-Miner-Tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `helioskozak-cloud/news-desk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rewire82evener/Riot-Control-Simulator-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hostelry-50-bristled/My-Cuckqueen-Girlfriend-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `delimits84698tingling/Skyclimbers-Beta-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jenesis/jenesis-repository` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Leow210/kotoba` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

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
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,638 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 1,978 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,713 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 11,648 | 64.3% | 938 | 2026-09-04 |
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
| `configserverapps_service_blocklists_forums` | GITHUB | 13,344 | 5.5% | 10 | 2026-07-04 |
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
| `configserverapps_service_blocklists_ssh_1d` | GITHUB | 4,018 | 80.5% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 3,332 | 79.4% | 10 | 2026-09-24 |
| `ian_lusule_proxies` | GITHUB | 3,562 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,678 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,385 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 253,416 | 22.0% | 6 | 2026-07-08 |
| `gazpitchy92_ip_blocklist_blacklist` | GITHUB | 241,210 | 19.5% | 6 | 2026-09-20 |
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
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,707 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 147 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 17,403 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 17,263 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 21,126 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,359 | 31.1% | 1 | 2026-07-14 |
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
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 11,531 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,831 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,613 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,000 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,080 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 42,142 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 20,253 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 12,016 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 6,152 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 40 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 28,539 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 154,078 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 18,189 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,010 | 5.1% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,135 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,362 | 9.3% | 0 | 2026-09-13 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,378 | 66.1% | 0 | 2026-09-20 |
| `claudiusdecimius_ioc_ipsets_tor_exits` | GITHUB | 1,374 | 66.5% | 0 | 2026-09-20 |
| `claudiusdecimius_ioc_ipsets_sblam` | GITHUB | 1,099 | 25.9% | 0 | 2026-09-20 |
| `brandontroidl_blocklist` | GITHUB | 3,783 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,503 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 908 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 480 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 122 | 52.5% | 0 | 2026-09-24 |

---
*Generiert: 2026-09-24 08:46 CEST (Europe/Berlin)*