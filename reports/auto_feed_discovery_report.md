# Auto Feed Discovery – Report
**Aktualisiert:** 2026-11-26 20:25 CET (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 17 |
| Kandidaten gesamt | **13021** |
| davon GitHub (Topics+Code) | **12852** |
| davon GitLab | **169** |
| davon Awesome-Lists | **2223** |
| Tools/Libraries vor Eval gefiltert | **1078** |
| davon Hard-Reject (awesome-Liste etc.) | **205** |
| EVAL-Kandidaten (nach Stratifizierung) | **277** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **277** |
| davon angenommene Repositories | **0** |
| davon abgelehnte Repositories | **277** |
| Neu angenommene Feed-Dateien | **3** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **190** |
| Abgelehnte Repositories (dieser Run) | **277** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **193** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **19209** |
| SQLite-Refresh-Cache-Hits | **15/190** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **156** |
| Repo zu alt (>30d) | **111** |
| IP-Datei veraltet (>30d) | **9** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `configserverapps_service_blocklists_level3_v2` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 11,506 | 43.0% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_level4_v2` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 5,683 | 63.0% | 0.0% | 10 | 🆕 NEU |
| `gazpitchy92_ip_blocklist_blacklist` | [gazpitchy92/ip-blocklist](https://github.com/gazpitchy92/ip-blocklist) | GITHUB | 379,525 | 4.5% | 0.0% | 6 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `mitchellkrogza/apache-ultimate-bad-bot-blocker` | GITHUB | Overlap zu gering: 0.0% |
| `mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites` | GITHUB | Zu alt: 1137d |
| `mitchellkrogza/fail2ban-useful-scripts` | GITHUB | Zu alt: 3081d |
| `mitchellkrogza/linux-server-administration-scripts` | GITHUB | Zu alt: 3523d |
| `all-contributors/allcontributors.org` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BlackArch/blackarch` | GITHUB | IP-Datei 730d alt |
| `MobSF/Mobile-Security-Framework-MobSF` | GITHUB | IP-Datei 4096d alt |
| `mpast/mobileAudit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `derhuerst/email-providers` | GITHUB | Zu alt: 401d |
| `AmnestyTech/investigations` | GITHUB | Zu alt: 710d |
| `ThreatMon/ThreatMon-Daily-C2-Feeds` | GITHUB | Zu alt: 1065d |
| `carbonblack/active_c2_ioc_public` | GITHUB | Zu alt: 1459d |
| `grayddq/GScan` | GITHUB | Zu alt: 1572d |
| `adhdproject/spidertrap` | GITHUB | Zu alt: 2346d |
| `opnsense/plugins` | GITHUB | IP-Datei 41d alt |
| `firehol/firehol` | GITHUB | Zu alt: 240d |
| `cbuijs/ipasn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `noctiro/stormin` | GITHUB | Zu alt: 35d |
| `romainmarcoux/malicious-hash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `telekom-security/tpotmobile` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bert-JanP/Incident-Response-Powershell` | GITHUB | Zu alt: 184d |
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2268d |
| `trick77/nftables-blacklist` | GITHUB | IP-Datei 93d alt |
| `inversify/InversifyJS` | GITHUB | Zu alt: 372d |
| `midwayjs/midway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anjoy8/Blog.Core` | GITHUB | Zu alt: 224d |
| `ets-labs/python-dependency-injector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeffijoe/awilix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typestack/typedi` | GITHUB | Zu alt: 393d |
| `oblac/jodd` | GITHUB | Zu alt: 955d |
| `w3tecch/express-typescript-boilerplate` | GITHUB | Zu alt: 1299d |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellokaton/java-bible` | GITHUB | Zu alt: 1748d |
| `samber/do` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PHP-DI/PHP-DI` | GITHUB | Zu alt: 330d |
| `appsquickly/typhoon` | GITHUB | Zu alt: 2167d |
| `nutzam/nutz` | GITHUB | Zu alt: 114d |
| `unitycontainer/unity` | GITHUB | Zu alt: 1040d |
| `gustavopsantos/Reflex` | GITHUB | Zu alt: 47d |
| `interplains/zero-breach` | GITHUB | Zu alt: 37d |
| `zycgit/hasor-old` | GITHUB | Zu alt: 52d |
| `reactiveui/splat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ntxinh/AspNetCore-DDD` | GITHUB | Zu alt: 333d |
| `danielpalme/IocPerformance` | GITHUB | Zu alt: 1225d |
| `YairHalberstadt/stronginject` | GITHUB | Zu alt: 514d |
| `forrest-orr/moneta` | GITHUB | Zu alt: 34d |
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VictorTzeng/Zxw.Framework.NetCore` | GITHUB | Zu alt: 87d |
| `exilon/QuickLib` | GITHUB | Zu alt: 52d |
| `anakic/Jot` | GITHUB | Zu alt: 412d |
| `Patrowl/PatrowlManager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `golobby/container` | GITHUB | Zu alt: 455d |
| `yoyofx/yoyogo` | GITHUB | Zu alt: 951d |
| `0x27/linux.mirai` | GITHUB | Zu alt: 3569d |
| `SwingFrog/Summer` | GITHUB | Zu alt: 588d |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `suites-dev/unit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `farseer-go/fs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `roadwy/DefenderYara` | GITHUB | Zu alt: 196d |
| `EcsRx/ecsrx` | GITHUB | Zu alt: 524d |
| `Savory/Danet` | GITHUB | Zu alt: 101d |
| `thiagobustamante/typescript-ioc` | GITHUB | Zu alt: 868d |
| `bingcool/swoolefy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheHive-Project/Cortex-Analyzers` | GITHUB | IP-Datei 176d alt |
| `gendigitalinc/ioc` | GITHUB | IP-Datei 1638d alt |
| `rafaelfgx/DotNetCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ivlevAstef/DITranquillity` | GITHUB | Zu alt: 203d |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pengweiqhca/Xunit.DependencyInjection` | GITHUB | Zu alt: 93d |
| `binghe001/BingheGuide` | GITHUB | Zu alt: 36d |
| `brianway/spring-learning` | GITHUB | Zu alt: 3741d |
| `midwayjs/midway-faas` | GITHUB | Zu alt: 2338d |
| `prodaft/malware-ioc` | GITHUB | Zu alt: 387d |
| `yinguangyao/blog` | GITHUB | Zu alt: 138d |
| `mwemuorg/mwemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inversify/monorepo` | GITHUB | IP-Datei 398d alt |
| `urfnet/URF.Core` | GITHUB | Zu alt: 799d |
| `owja/ioc` | GITHUB | Zu alt: 814d |
| `zazoomauro/node-dependency-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tshemsedinov/Patterns-JavaScript` | GITHUB | Zu alt: 291d |
| `d1mnewz/interviews` | GITHUB | Zu alt: 1968d |
| `eggjs/tegg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `baidu/CarbonGraph` | GITHUB | Zu alt: 752d |
| `ditekshen/detection` | GITHUB | Zu alt: 755d |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loresoft/Injectio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Patrowl/PatrowlEngines` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zheksoon/dioma` | GITHUB | Zu alt: 944d |
| `d3fvxl/di` | GITHUB | Zu alt: 1076d |
| `testdeck/testdeck` | GITHUB | Zu alt: 673d |
| `gnaeus/react-ioc` | GITHUB | Zu alt: 1120d |
| `mthcht/Purpleteam` | GITHUB | Zu alt: 706d |
| `intentor/adic` | GITHUB | Zu alt: 1935d |
| `urfnet/URF.NET` | GITHUB | Zu alt: 3109d |
| `Go-To-Byte/DouSheng` | GITHUB | Zu alt: 1277d |
| `molszanski/iti` | GITHUB | Zu alt: 85d |
| `hidevopsio/hiboot` | GITHUB | Zu alt: 171d |
| `dry-rb/dry-auto_inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wzhudev/redi` | GITHUB | Zu alt: 75d |
| `agileago/vue3-oop` | GITHUB | Zu alt: 524d |
| `aalex954/evilginx2-TTPs` | GITHUB | Zu alt: 589d |
| `assafmo/xioc` | GITHUB | Zu alt: 2412d |
| `artberri/diod` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wix-incubator/obsidian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `z4kn4fein/stashbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gensecaihq/Shai-Hulud-2.0-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Patrowl/PatrowlDocs` | GITHUB | Zu alt: 1689d |
| `Puresharper/Puresharp` | GITHUB | Zu alt: 2856d |
| `xpleemoon/XModulable` | GITHUB | Zu alt: 3218d |
| `MySixGod/SpringImpl_v2.0` | GITHUB | Zu alt: 3432d |
| `exuanbo/di-wise` | GITHUB | Zu alt: 652d |
| `TAKETODAY/today-infrastructure` | GITHUB | IP-Datei 320d alt |
| `Koatty/koatty` | GITHUB | Zu alt: 57d |
| `jbreckmckye/node-typescript-architecture` | GITHUB | Zu alt: 1092d |
| `100nm/python-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zzzzbw/doodle` | GITHUB | Zu alt: 1623d |
| `zovajs/zova` | GITHUB | Zu alt: 56d |
| `vuldb/cyber_threat_intelligence` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jsuarezruiz/xamarin-forms-perf-playground` | GITHUB | Zu alt: 1449d |
| `shihabmridha/nodejs-repository-pattern-and-ioc` | GITHUB | Zu alt: 628d |
| `401trg/detections` | GITHUB | Zu alt: 2052d |
| `MotherSphere/NIKKE-Launcher-Check` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `roo-oliv/injectable` | GITHUB | Zu alt: 448d |
| `NullArray/Mimir` | GITHUB | Zu alt: 2844d |
| `ecomfe/uioc` | GITHUB | Zu alt: 3331d |
| `vercube/vercube` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nikku/didi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AsenaJs/Asena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mnasyrov/ditox` | GITHUB | Zu alt: 39d |
| `typesoft/container-ioc` | GITHUB | Zu alt: 2497d |
| `ZihanType/rudi` | GITHUB | Zu alt: 695d |
| `scanurag/FoodFrenzy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nicolascotton/nject` | GITHUB | Zu alt: 150d |
| `wessberg/DI-compiler` | GITHUB | Zu alt: 756d |
| `dmitryb-dev/waiter` | GITHUB | Zu alt: 1017d |
| `uditalias/injex` | GITHUB | Zu alt: 401d |
| `go-spring-rip/spring-core` | GITHUB | Zu alt: 168d |
| `bootsrc/containerx` | GITHUB | Zu alt: 2874d |
| `assafkip/investigators-copilot` | GITHUB | IP-Datei 225d alt |
| `Rick-van-Dam/Singularity` | GITHUB | Zu alt: 2264d |
| `mbierlee/poodinis` | GITHUB | Zu alt: 322d |
| `opensumi/di` | GITHUB | Zu alt: 440d |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `go-spring-projects/go-spring` | GITHUB | Zu alt: 202d |
| `absingh31/Tor_Spider` | GITHUB | Zu alt: 3199d |
| `conix-security/BTG` | GITHUB | Zu alt: 2921d |
| `100cm/thunder` | GITHUB | Zu alt: 3852d |
| `appsquickly/pilgrim` | GITHUB | Zu alt: 1384d |
| `ioc-fang/ioc-fanger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maou-shonen/hono-simple-DI` | GITHUB | Zu alt: 65d |
| `parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs` | GITHUB | Zu alt: 2055d |
| `di-ninja/di-ninja` | GITHUB | Zu alt: 603d |
| `HangfireIO/Hangfire.Autofac` | GITHUB | Zu alt: 685d |
| `krylosov-aa/context-async-sqlalchemy` | GITHUB | Zu alt: 165d |
| `ChistaDev/Chista` | GITHUB | Zu alt: 922d |
| `INotfound/Magic` | GITHUB | Zu alt: 1047d |
| `zhulik/pal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `otavia-projects/otavia` | GITHUB | Zu alt: 178d |
| `AlyElhaddad/ThunderboltIoc` | GITHUB | Zu alt: 451d |
| `enisn/DotNurseInjector` | GITHUB | Zu alt: 1066d |
| `tstromberg/ttp-bench` | GITHUB | Zu alt: 171d |
| `silascutler/MalPipe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stephenbrannon/IOCextractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kbandla/APTnotes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InQuest/omnibus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `1aN0rmus/TekDefense-Automater` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tripwire/tardis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CrowdStrike/CrowdFMS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpsenior/threataggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spacepatcher/FireHOL-IP-Aggregator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yelp/threat_intel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `STIXProject/stix-viz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `exp0se/harbinger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/Forager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CylanceSPEAR/CyBot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aboutsecurity/rastrea2r` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EclecticIQ/OpenTAXII` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spacepatcher/softrace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HurricaneLabs/machinae` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abhinavbom/Threat-Intelligence-Hunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BinaryDefense/goatrider` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `armbues/ioc_parser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Neo23x0/Loki` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mgeide/poortego` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `InQuest/python-iocextract` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brianwarehime/threatnote` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johestephan/ibmxforceex.checker.py` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yara-Rules/rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abusesa/abusehelper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheHive-Project/Hippocampe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yahoo/PyIOCe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mandiant/ioc_writer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `facebook/ThreatExchange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mlsecproject/tiq-test` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `S03D4-164/Hiryu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ioc-fang/ioc_fanger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `michael-yip/ThreatTracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/jager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TAXIIProject/libtaxii` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityRiskAdvisors/sra-taxii2-server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mlsecproject/combine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jheise/threatcmd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fhightower/onemillion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stratosphereips/Manati` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jheise/threatcrowd_api` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Netflix/Scumblr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ptr32Void/OSTrICa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/cacador` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TAXIIProject/yeti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SupportIntelligence/Icewater` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EclecticIQ/cabby` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ciscocsirt/gosint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `paulpc/nyx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `QTek/QRadio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ocmdev/rita` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PaloAltoNetworks/minemeld` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lookingglass/opentpx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4d31/sqhunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dougiep16/actortrackr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kx499/ostip` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `byt3smith/malstrom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KasperskyLab/klara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/StrutsHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f0rw4rd/potsnitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hexgolems/pint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christophe77/node-ftp-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `katkad/Glastopf-Analytics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `madirish/kojoney2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `graneed/bwpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zeerg/helix-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aelth/ddospot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ajackal/arctic-swallow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rubenespadas/DionaeaFR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `buffer/pylibemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hbhzwj/imalse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/flux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shiva-spampot/shiva` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aplura/Tango` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dutchcoders/troje` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `buffer/libemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jedie/django-kippo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `batchmcnulty/Malbait` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/manuka` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fw42/honeymap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/micros_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mycert/ESPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sreinhardt/Docker-Honeynet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mfontani/kippo-stats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bjeborn/basic-auth-pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `antonsatt/ssh-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lcashdol/WAPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thinkst/opencanary` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sec51/honeymail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERT-Polska/HSN-Capture-HPC-NG` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magisterquis/vnclowpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jadb/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/ghost-usb-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERT-Polska/hsn2-bundle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `desaster/kippo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Novetta/delilah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/phoneyc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shbhmsingh72/Honeypot-Research-Papers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dmpayton/django-admin-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MattCarothers/mhn-core-docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/honeycomb_plugins` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eymengunay/EoHoneypotBundle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oguzy/ovizart` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `juandresrodca/DorkCraft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `certsocietegenerale/FIR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fox-it/dissect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bad-antics/nullsec-linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SwiftOnSecurity/sysmon-config` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cynative/cynative` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Netflix-Skunkworks/diffy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deralexxx/security-apis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dogoncouch/logdissect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 23,442 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,078 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 8,506 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,558 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,824 | 0.2% | 120 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 4,008 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 4,850 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 597 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,314 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 739 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 565 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 486 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 244 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,974 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,974 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 20,600 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 14,994 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 7,583 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 5,157 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 7,147 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 218,371 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,584 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 7,471 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,636 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 5,107 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 32,778 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 4,518 | 64.3% | 938 | 2026-09-04 |
| `cbuijs_hagezi` | GITHUB | 29,759 | 37.9% | 129 | 2026-11-08 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 584 | 19.0% | 49 | 2026-11-22 |
| `stamparm_maltrail` | GITHUB | 16,845 | 2.4% | 8661 | 2026-11-22 |
| `criticalpathsecurity_zeek_intelligence_feeds` | GITHUB | 472 | 42.0% | 407 | 2026-11-22 |
| `mohammedcha_proxripper` | GITHUB | 52,941 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,326 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,715 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 119,244 | 0.2% | 36 | 2026-07-05 |
| `telekom_security_listbot` | GITHUB | 535 | 10.4% | 22 | 2026-10-18 |
| `dinoz0rg_proxy_list` | GITHUB | 91,819 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,890 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 94,877 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 110,709 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 7,763 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 126,488 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 16,965 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 95,157 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 568 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 498,591 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 220,071 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 174,815 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 98,248 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 173,269 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 188,362 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 82,985 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 91,103 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 324,717 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 73,135 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 239,002 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 25,899 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 15,382 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 14,628 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 277,018 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,858 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 12,616 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,658 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 29,940 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 17,062 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 14,819 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 30,493 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 1,916 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,283 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 4,714 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,939 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 470 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,647 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 3,389 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,997 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,982 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 148,943 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 894 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 28,872 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 5,457 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 4,693 | 79.4% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,861 | 64.3% | 10 | 2026-10-11 |
| `configserverapps_service_blocklists_level3_v2` | GITHUB | 11,506 | 43.0% | 10 | 2026-11-26 |
| `configserverapps_service_blocklists_level4_v2` | GITHUB | 5,683 | 63.0% | 10 | 2026-11-26 |
| `ian_lusule_proxies` | GITHUB | 2,961 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,645 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,365 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 394,045 | 22.0% | 6 | 2026-07-08 |
| `gazpitchy92_ip_blocklist_blacklist` | GITHUB | 379,525 | 4.5% | 6 | 2026-11-26 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,399 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 91 | 97.4% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 108,552 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 23,414 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 83 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 107,317 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 4,342 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,731 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 74 | 28.1% | 2 | 2026-08-02 |
| `runtechx_dns_runtech_ao` | GITHUB | 20,991 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 32,164 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,439 | 31.1% | 1 | 2026-07-14 |
| `klonet_it_ip_threat_lists` | GITHUB | 146,251 | 51.5% | 1 | 2026-10-11 |
| `klonet_it_ip_threat_lists_blocklist_apache` | GITHUB | 10,129 | 9.7% | 1 | 2026-10-11 |
| `idleadmin_threatfeed` | GITHUB | 50,133 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 77,831 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,077 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 141,568 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 198,010 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 142,311 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 237,582 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,236 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 39,019 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 494 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 16,889 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 17,537 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,690 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 8,224 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,303 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,614 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 3,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,583 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,117 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,531 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,966 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,438 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 460 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 10,461 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,003 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,255 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 994 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 899 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,001 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,162 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 742 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,099 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 956 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,336 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 595 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,975 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,459 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 978 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 29,005 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 91,906 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 90,382 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 91,632 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 94,562 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 88,079 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 93,157 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 110,977 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,539 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 39,583 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,765 | 2.7% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,000 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 16,220 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 35,287 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 17,337 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 10,881 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 3,016 | 71.1% | 0 | 2026-08-12 |
| `zgzyh_malicious_website_detection` | GITHUB | 33,747 | 3.1% | 0 | 2026-08-15 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 7,531 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 18,493 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 3,058 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,579 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 1,318 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 489 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 227 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 16,813 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 95,012 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 95,499 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 95,649 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 93,743 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 97,201 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 42,876 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 6,452 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 6,385 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 2,265 | 76.9% | 0 | 2026-09-25 |
| `brandontroidl_blocklist_all_90d` | GITHUB | 6,174 | 61.9% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_aggressive` | GITHUB | 68 | 80.9% | 0 | 2026-10-11 |
| `helio4k_bad_ip` | GITHUB | 1,232 | 43.3% | 0 | 2026-10-25 |
| `verkombr_block_list_firewalls` | GITHUB | 958 | 46.9% | 0 | 2026-10-25 |
| `blawoblowa_blackened` | GITHUB | 1,695 | 56.0% | 0 | 2026-11-01 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 7,097 | 13.1% | 0 | 2026-11-08 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,217 | 69.7% | 0 | 2026-11-08 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 188,102 | 1.6% | 0 | 2026-11-22 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 15,188 | 19.8% | 0 | 2026-11-22 |
| `claudiusdecimius_ioc_ipsets_bruteforceblocker` | GITHUB | 579 | 32.4% | 0 | 2026-11-22 |

---
*Generiert: 2026-11-26 20:25 CET (Europe/Berlin)*