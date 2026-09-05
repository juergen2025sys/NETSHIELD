# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-05 18:34 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 11 |
| Kandidaten gesamt | **11490** |
| davon GitHub (Topics+Code) | **11407** |
| davon GitLab | **83** |
| davon Awesome-Lists | **2199** |
| Tools/Libraries vor Eval gefiltert | **891** |
| davon Hard-Reject (awesome-Liste etc.) | **196** |
| EVAL-Kandidaten (nach Stratifizierung) | **461** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **461** |
| davon angenommene Repositories | **0** |
| davon abgelehnte Repositories | **461** |
| Neu angenommene Feed-Dateien | **0** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **190** |
| Abgelehnte Repositories (dieser Run) | **461** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **190** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **160386** |
| SQLite-Refresh-Cache-Hits | **22/191** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **249** |
| Repo zu alt (>30d) | **179** |
| IP-Datei veraltet (>30d) | **21** |
| Falsche Größe (<30 / >2,000,000 IPs) | **11** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `Sandeepr5595/seraph-celestial-commander` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kalidada18/kalidada18` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SEKOIA-IO/documentation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yasirhamza/AndroDR` | GITHUB | IP-Datei 31d alt |
| `Johnng007/Live-Forensicator` | GITHUB | Größe: 0 IPs |
| `xairy/linux-kernel-exploitation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bert-JanP/Hunting-Queries-Detection-Rules` | GITHUB | Zu alt: 44d |
| `AppliedIR/Valhuntir` | GITHUB | Zu alt: 49d |
| `mikeroyal/Open-Source-Security-Guide` | GITHUB | Zu alt: 435d |
| `decal/werdlists` | GITHUB | Zu alt: 752d |
| `michredteam/RTbookNotes` | GITHUB | Zu alt: 797d |
| `curtislbyrd/CyberVault` | GITHUB | Zu alt: 176d |
| `saicharanamaraneni18-source/phishing-mail-incident-response` | GITHUB | Zu alt: 90d |
| `bhengubv/CircleAI` | GITHUB | IP-Datei 43d alt |
| `shubham7003/Security-Infrastructure-Observability-Platform` | GITHUB | Zu alt: 95d |
| `bitjbullock/SysAdmin` | GITHUB | Zu alt: 109d |
| `servo/servo` | GITHUB | Größe: 0 IPs |
| `ankitkumarsh39-sys/email-analyzer-soc-tool` | GITHUB | IP-Datei 106d alt |
| `yuntianze/dmp` | GITHUB | Zu alt: 368d |
| `RealCrazyAnonymous/Filter-Lists` | GITHUB | Overlap zu gering: 2.3% |
| `paulrouget/servo-embedding-example` | GITHUB | Zu alt: 3099d |
| `de-otio/agent-safety-pack` | GITHUB | Zu alt: 67d |
| `shizukutanaka/Muten` | GITHUB | IP-Datei 56d alt |
| `fabricedesre/servonk` | GITHUB | Zu alt: 2886d |
| `WebBluetoothCG/registries` | GITHUB | Zu alt: 1117d |
| `allenai/dolma` | GITHUB | IP-Datei 1010d alt |
| `mxmgorin/retsurf` | GITHUB | IP-Datei 357d alt |
| `seia-soto/dns` | GITHUB | Zu alt: 871d |
| `kakarot-dev/dnsink` | GITHUB | Zu alt: 123d |
| `Drew7/url-blocklist` | GITHUB | Zu alt: 1299d |
| `jesuslopezreynosa/useful-scripts` | GITHUB | IP-Datei 664d alt |
| `1Jamie/project-lotus` | GITHUB | Zu alt: 69d |
| `RaafatTurki/dots` | GITHUB | Größe: 0 IPs |
| `matiaselebi/Secure-DNS` | GITHUB | IP-Datei 40d alt |
| `fx-dev-playground/gecko` | GITHUB | Zu alt: 1333d |
| `chaitanyaBytes/Slipstream` | GITHUB | Zu alt: 97d |
| `paulrouget/servofocus` | GITHUB | Zu alt: 3191d |
| `jschwe/ServoDemo` | GITHUB | Zu alt: 58d |
| `sagittaurius/malware-list-filter-compiler` | GITHUB | Zu alt: 47d |
| `paulrouget/hnbrowser` | GITHUB | Zu alt: 3357d |
| `jialunzhang-psu/SandCell-Artifact` | GITHUB | Zu alt: 233d |
| `ryanyxw/llm-decouple` | GITHUB | Zu alt: 345d |
| `thevoodjev/servo` | GITHUB | IP-Datei 65d alt |
| `arwunmarona/servo` | GITHUB | Zu alt: 37d |
| `mickeyszabo/servo` | GITHUB | Zu alt: 31d |
| `natzarich/servo` | GITHUB | IP-Datei 65d alt |
| `anthonyniqmm/servo` | GITHUB | IP-Datei 65d alt |
| `webbeef/webviewer` | GITHUB | Zu alt: 750d |
| `justinmichaud/ion` | GITHUB | Zu alt: 2876d |
| `moto-browser/moto` | GITHUB | Zu alt: 498d |
| `securesystemslab/pkru-safe-servo` | GITHUB | Zu alt: 1404d |
| `fschutt/servo_gui_test` | GITHUB | Zu alt: 3266d |
| `Baconana-chan/ferro-browser` | GITHUB | Zu alt: 67d |
| `paulrouget/libsimpleservo` | GITHUB | Zu alt: 3259d |
| `karad/my-servo-embedding-example` | GITHUB | Zu alt: 2621d |
| `OwnedByWuigi/dactylic` | GITHUB | Zu alt: 94d |
| `galadran/tor-browser` | GITHUB | Zu alt: 2597d |
| `Anima-OS/Quokka` | GITHUB | Zu alt: 1348d |
| `kinetiknz/gecko` | GITHUB | Zu alt: 2411d |
| `BenEgeIzmirli/mozilla_central_in_c` | GITHUB | Zu alt: 1348d |
| `jsorg71/waterfox_classic_releases` | GITHUB | Zu alt: 1348d |
| `KhaledSaadeh05/SecureMesh-IPS` | GITHUB | Zu alt: 89d |
| `GOKU1117/auto_upload_to_virustotal` | GITHUB | Zu alt: 955d |
| `youssefbouaouina/dfir-threat-hunting-framework` | GITHUB | IP-Datei 32d alt |
| `Nihalgiri001/Continuous_Monitoring_IDS` | GITHUB | Zu alt: 117d |
| `Nikhil-H-N/CIDECODE` | GITHUB | Zu alt: 102d |
| `Jyot-tipsoc/honeypot-threat-lab` | GITHUB | Zu alt: 79d |
| `Juniorpqp/blocklist` | GITHUB | IP-Datei 1928d alt |
| `palevian/70-_MK1` | GITHUB | Größe: 25 IPs |
| `DonDon7755/DonRea` | GITHUB | Zu alt: 507d |
| `ekomsSavior/network_ids` | GITHUB | Zu alt: 210d |
| `nauman-nomi/Firewall-FrontEnd` | GITHUB | Zu alt: 350d |
| `HarikaMurali/Intelligent-Network-Packet-Analyzer` | GITHUB | Zu alt: 306d |
| `Donte61/firewall` | GITHUB | Zu alt: 397d |
| `CuriousMrBear/My-EDL` | GITHUB | Zu alt: 684d |
| `initconf/misp_intel` | GITHUB | Zu alt: 192d |
| `DAYceng/elk4spark` | GITHUB | Zu alt: 1156d |
| `wuguobeijing/StratosphereLinuxIPS-dev` | GITHUB | Zu alt: 1187d |
| `valkyrianlabs/forti-hole` | GITHUB | Zu alt: 723d |
| `ervindaprtma/ervindaprtma.github.io` | GITHUB | Zu alt: 118d |
| `ThreatMon/ThreatMon-Daily-C2-Feeds` | GITHUB | Zu alt: 983d |
| `mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites` | GITHUB | Zu alt: 1055d |
| `xxf098/LiteSpeedTest` | GITHUB | Zu alt: 1078d |
| `carbonblack/active_c2_ioc_public` | GITHUB | Zu alt: 1377d |
| `firehol/firehol` | GITHUB | Zu alt: 158d |
| `ErcinDedeoglu/crypto-market-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `noctiro/stormin` | GITHUB | Zu alt: 118d |
| `Bert-JanP/Incident-Response-Powershell` | GITHUB | Zu alt: 102d |
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2186d |
| `inversify/InversifyJS` | GITHUB | Zu alt: 290d |
| `midwayjs/midway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anjoy8/Blog.Core` | GITHUB | Zu alt: 142d |
| `ets-labs/python-dependency-injector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typestack/typedi` | GITHUB | Zu alt: 311d |
| `jeffijoe/awilix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oblac/jodd` | GITHUB | Zu alt: 873d |
| `w3tecch/express-typescript-boilerplate` | GITHUB | Zu alt: 1217d |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellokaton/java-bible` | GITHUB | Zu alt: 1666d |
| `samber/do` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PHP-DI/PHP-DI` | GITHUB | Zu alt: 248d |
| `appsquickly/typhoon` | GITHUB | Zu alt: 2085d |
| `nutzam/nutz` | GITHUB | Zu alt: 32d |
| `unitycontainer/unity` | GITHUB | Zu alt: 958d |
| `gustavopsantos/Reflex` | GITHUB | Zu alt: 79d |
| `zycgit/hasor` | GITHUB | Zu alt: 1361d |
| `reactiveui/splat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ntxinh/AspNetCore-DDD` | GITHUB | Zu alt: 251d |
| `danielpalme/IocPerformance` | GITHUB | Zu alt: 1143d |
| `YairHalberstadt/stronginject` | GITHUB | Zu alt: 432d |
| `forrest-orr/moneta` | GITHUB | Zu alt: 903d |
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VictorTzeng/Zxw.Framework.NetCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `exilon/QuickLib` | GITHUB | Zu alt: 120d |
| `anakic/Jot` | GITHUB | Zu alt: 330d |
| `golobby/container` | GITHUB | Zu alt: 373d |
| `yoyofx/yoyogo` | GITHUB | Zu alt: 869d |
| `SwingFrog/Summer` | GITHUB | Zu alt: 506d |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `farseer-go/fs` | GITHUB | Zu alt: 76d |
| `suites-dev/suites` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EcsRx/ecsrx` | GITHUB | Zu alt: 442d |
| `roadwy/DefenderYara` | GITHUB | Zu alt: 114d |
| `Savory/Danet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thiagobustamante/typescript-ioc` | GITHUB | Zu alt: 786d |
| `bingcool/swoolefy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafaelfgx/DotNetCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gendigitalinc/ioc` | GITHUB | Zu alt: 96d |
| `ivlevAstef/DITranquillity` | GITHUB | Zu alt: 121d |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pengweiqhca/Xunit.DependencyInjection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `binghe001/BingheGuide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brianway/spring-learning` | GITHUB | Zu alt: 3659d |
| `midwayjs/midway-faas` | GITHUB | Zu alt: 2256d |
| `yinguangyao/blog` | GITHUB | Zu alt: 56d |
| `prodaft/malware-ioc` | GITHUB | Zu alt: 305d |
| `mwemuorg/mwemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `urfnet/URF.Core` | GITHUB | Zu alt: 717d |
| `owja/ioc` | GITHUB | Zu alt: 732d |
| `zazoomauro/node-dependency-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tshemsedinov/Patterns-JavaScript` | GITHUB | Zu alt: 209d |
| `inversify/monorepo` | GITHUB | IP-Datei 316d alt |
| `d1mnewz/interviews` | GITHUB | Zu alt: 1886d |
| `eggjs/tegg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ditekshen/detection` | GITHUB | Zu alt: 673d |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loresoft/Injectio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zheksoon/dioma` | GITHUB | Zu alt: 862d |
| `d3fvxl/di` | GITHUB | Zu alt: 994d |
| `testdeck/testdeck` | GITHUB | Zu alt: 591d |
| `gnaeus/react-ioc` | GITHUB | Zu alt: 1038d |
| `intentor/adic` | GITHUB | Zu alt: 1853d |
| `urfnet/URF.NET` | GITHUB | Zu alt: 3027d |
| `Go-To-Byte/DouSheng` | GITHUB | Zu alt: 1195d |
| `hidevopsio/hiboot` | GITHUB | Zu alt: 89d |
| `dry-rb/dry-auto_inject` | GITHUB | Zu alt: 102d |
| `molszanski/iti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wzhudev/redi` | GITHUB | Zu alt: 50d |
| `agileago/vue3-oop` | GITHUB | Zu alt: 442d |
| `assafmo/xioc` | GITHUB | Zu alt: 2330d |
| `aalex954/evilginx2-TTPs` | GITHUB | Zu alt: 507d |
| `artberri/diod` | GITHUB | Zu alt: 701d |
| `wix-incubator/obsidian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `z4kn4fein/stashbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gensecaihq/Shai-Hulud-2.0-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Puresharper/Puresharp` | GITHUB | Zu alt: 2774d |
| `xpleemoon/XModulable` | GITHUB | Zu alt: 3136d |
| `MySixGod/SpringImpl_v2.0` | GITHUB | Zu alt: 3350d |
| `exuanbo/di-wise` | GITHUB | Zu alt: 570d |
| `TAKETODAY/today-infrastructure` | GITHUB | IP-Datei 238d alt |
| `Koatty/koatty` | GITHUB | Zu alt: 132d |
| `100nm/python-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbreckmckye/node-typescript-architecture` | GITHUB | Zu alt: 1010d |
| `zovajs/zova` | GITHUB | Zu alt: 84d |
| `zzzzbw/doodle` | GITHUB | Zu alt: 1541d |
| `jsuarezruiz/xamarin-forms-perf-playground` | GITHUB | Zu alt: 1367d |
| `shihabmridha/nodejs-repository-pattern-and-ioc` | GITHUB | Zu alt: 546d |
| `401trg/detections` | GITHUB | Zu alt: 1970d |
| `roo-oliv/injectable` | GITHUB | Zu alt: 366d |
| `NullArray/Mimir` | GITHUB | Zu alt: 2762d |
| `ecomfe/uioc` | GITHUB | Zu alt: 3249d |
| `vercube/vercube` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nikku/didi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mnasyrov/ditox` | GITHUB | Zu alt: 41d |
| `AsenaJs/Asena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typesoft/container-ioc` | GITHUB | Zu alt: 2415d |
| `ZihanType/rudi` | GITHUB | Zu alt: 613d |
| `scanurag/FoodFrenzy` | GITHUB | Zu alt: 262d |
| `nicolascotton/nject` | GITHUB | Zu alt: 68d |
| `wessberg/DI-compiler` | GITHUB | Zu alt: 674d |
| `dmitryb-dev/waiter` | GITHUB | Zu alt: 935d |
| `uditalias/injex` | GITHUB | Zu alt: 319d |
| `go-spring-rip/spring-core` | GITHUB | Zu alt: 86d |
| `bootsrc/containerx` | GITHUB | Zu alt: 2792d |
| `Rick-van-Dam/Singularity` | GITHUB | Zu alt: 2182d |
| `mbierlee/poodinis` | GITHUB | Zu alt: 240d |
| `conix-security/BTG` | GITHUB | Zu alt: 2839d |
| `go-spring-projects/go-spring` | GITHUB | Zu alt: 120d |
| `opensumi/di` | GITHUB | Zu alt: 358d |
| `absingh31/Tor_Spider` | GITHUB | Zu alt: 3117d |
| `100cm/thunder` | GITHUB | Zu alt: 3770d |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `appsquickly/pilgrim` | GITHUB | Zu alt: 1302d |
| `modern-python/modern-di` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maou-shonen/hono-simple-DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs` | GITHUB | Zu alt: 1973d |
| `di-ninja/di-ninja` | GITHUB | Zu alt: 521d |
| `HangfireIO/Hangfire.Autofac` | GITHUB | Zu alt: 603d |
| `krylosov-aa/context-async-sqlalchemy` | GITHUB | Zu alt: 83d |
| `ChistaDev/Chista` | GITHUB | Zu alt: 840d |
| `INotfound/Magic` | GITHUB | Zu alt: 965d |
| `zhulik/pal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlyElhaddad/ThunderboltIoc` | GITHUB | Zu alt: 369d |
| `otavia-projects/otavia` | GITHUB | Zu alt: 96d |
| `enisn/DotNurseInjector` | GITHUB | Zu alt: 984d |
| `xiuqianli1996/LSFramework` | GITHUB | Zu alt: 1005d |
| `tstromberg/ttp-bench` | GITHUB | Zu alt: 89d |
| `KnisterPeter/tsdi` | GITHUB | Zu alt: 1013d |
| `phantom0004/morpheus_IOC_scanner` | GITHUB | Zu alt: 570d |
| `OsmanKandemir/web-wordlist-generator` | GITHUB | Zu alt: 832d |
| `bdqfork/festival` | GITHUB | Zu alt: 2377d |
| `assafkip/huntkit` | GITHUB | IP-Datei 143d alt |
| `blacktop/docker-yara` | GITHUB | Zu alt: 1433d |
| `0xDanielLopez/TweetFeed_code` | GITHUB | Zu alt: 1384d |
| `inversiland/inversiland` | GITHUB | Zu alt: 625d |
| `byme8/ZeroIoC` | GITHUB | Zu alt: 473d |
| `sergeysychov/behaviour_inject` | GITHUB | Zu alt: 1084d |
| `aloisdeniel/dioc` | GITHUB | Zu alt: 2328d |
| `d3fvxl/inject` | GITHUB | Zu alt: 2391d |
| `red-gold/ts-ui` | GITHUB | Zu alt: 821d |
| `Washi1337/cilfi` | GITHUB | Zu alt: 31d |
| `jacoborus/wiremap` | GITHUB | Zu alt: 244d |
| `imnbwd/FriendEditor` | GITHUB | Zu alt: 3459d |
| `wenbo2018/mini-springframework` | GITHUB | Zu alt: 3163d |
| `FarseerNet/Farseer.Net` | GITHUB | Zu alt: 1282d |
| `iorate/ublacklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ruddernation-Designs/Adobe-URL-Block-List` | GITHUB | Zu alt: 86d |
| `Stevoisiak/Stevos-AI-Blocklist` | GITHUB | Größe: 0 IPs |
| `marteinn/The-Big-Username-Blocklist` | GITHUB | Zu alt: 1788d |
| `DavidMoore/ipfilter` | GITHUB | Zu alt: 218d |
| `secretsquirrel/recomposer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keydet89/RegRipper2.8` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `unipacker/unipacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rurik/Java_IDX_Parser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/ember` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uppusaikiran/malware-organiser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `micheloosterhof/cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LDO-CERT/orochi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NationalSecurityAgency/ghidra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sleuthkit/scalpel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `monnappa22/Limon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vmt/udis86` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aol/moloch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sroberts/malwarehouse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ashishb/android-security-awesome` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `michael-yip/MaltegoVT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omriher/CapTipper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbremer/httpreplay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xd4d/de4dot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/capa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `programa-stic/barf-project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/AnalyzePDF` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hempnall/broyara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `horsicq/Detect-It-Easy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `longld/peda` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keithjjones/visualize_logs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aquynh/capstone` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keithjjones/cuckoo-modified-api` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Konloch/bytecode-viewer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `malwaremusings/unpacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RPISEC/Malware` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `detuxsandbox/detux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pidydx/SMRT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `david3107/squatm3gator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `akamhy/waybackpy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `projectdiscovery/dnsx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/Website-Diff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Berchez/OSINT-steam` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/github_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TeehanLax/Hyperlapse.js` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ArthurHeitmann/arctic_shift` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atiilla/gitrecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lissy93/personal-security-checklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vericle/intellyweave` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vognik/maltego-telegram` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fauvidoTechnologies/PyBrowserAutomation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `owasp-amass/amass` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wireservice/csvkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `subzeroid/insto` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `heldersepu/gmapcatcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atiilla/geospy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gorhill/uBlock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DataSploit/datasploit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IvanGlinkin/CCTV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GreyNoise-Intelligence/pygreynoise` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `snort3/snort3` | GITHUB | IP-Datei 172d alt |
| `ntop/ntopng` | GITHUB | IP-Datei 969d alt |
| `zeek/zeek` | GITHUB | IP-Datei 38d alt |
| `secrary/makin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `leveldown-security/SVD-Loader-Ghidra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `facebookresearch/Cupcake` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nuxmorpheus/EHREM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `redcanaryco/AtomicTestHarnesses` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mwrlabs/dref` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `plackyhacker/Shellcode-Injection-Techniques` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iosiro/baserunner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ganapati/RsaCtfTool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bitcoin/bitcoin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `naingyeminn/CentOS7_Lockdown` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DavidXanatos/DiskCryptor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ly4k/Certipy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tasox/LogRM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inmcm/kravatte` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `naim94a/lumen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microsoft/console` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kudelskisecurity/cryptochallenge18` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `janestreet/magic-trace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microsoft/Windows-driver-samples` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evilsocket/shellz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kacos2000/Win10` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dumb-password-rules/dumb-password-rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `guitmz/midrashim` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `putsi/privatecollaborator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `colental/byob` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corelan/mona` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pd0wm/pq-flasher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kenorb-contrib/tg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zardus/preeny` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xR0/shellver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mthbernardes/GTRS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ufrisk/pcileech` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stufus/reconerator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Super-Guesser/ctf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Anon-Exploiter/SiteBroker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RedDrip7/SunBurst_DGA_Decode` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MISP/misp-warninglists` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thi-ng/tinyalloc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swisskyrepo/GraphQLmap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `geohot/qira` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cedowens/Mythic-Macro-Generator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PartialVolume/shredos.x86_64` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brad-duncan/June-2021-forensic-quiz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sapphirex00/Threat-Hunting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Security-Onion-Solutions/securityonion-docs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `project-everest/hacl-star` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `6IX7ine/certstreamcatcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bing0o/simple_ransomware` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xsp-SRD/mortar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RPwnage/pwn-my` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gmatuz/cve-scanner-exploiting-pocs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `curi0usJack/ADImporter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Viralmaniar/Remote-Desktop-Caching-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mr-Un1k0d3r/DKMC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shenril/Sitadel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `helviojunior/shellcodetester` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `offensive-security/exploitdb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zodiacon/Win10SysProgBookSamples` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `redacted/XKCD-password-generator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arc298/instagram-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DarkSpiritz/DarkSpiritz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sephirothx/sketchy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eiyanproject/homelab-monitoring` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kingdol666/AgentWorkShop` | GITHUB | Größe: 0 IPs |
| `Achalnawal2745/patchforge-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vedeshskhatri/Urban-Furniture-Accounting-System` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ProjectLanternDI3P1P2/dotnet-backend-template` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jaurakunal/isitsecure` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `smolders-outdoor-4/Dynasty-Warriors-3-Complete-Edition-Remastered-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `enhansome/enhansome-yara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `datapip/datapip.de-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Roadpeak/NHP-BACKEND` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HebertyRichards/to-do-list-backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `patrickotim680-byte/Wisp-App` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cloud-itonami/cloud-itonami-dns-resolver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MFurqan5/MFurqan5` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pakde-semar/flowintel-reverify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lordcheetah/FODMAP-NOOM-DASH` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benjasantu01-dotcom/limpieza-total-omega` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `operator13/campingWorld-qa-agent-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `embolden-stricter-1/Bouncemasters2-Pengu-Throw-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nightswatchhq/nuthatch` | GITHUB | Größe: 0 IPs |
| `accessed2lazy/We-Were-Here-Tomorrow-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mumtaz-7/taz-screening-futures` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sree-Mithra/recoverai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `linny006/skills-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sploithunter/HaloAndHorns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mumtaz-7/taz-screening` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stems-yeshivot5786/KaiJu-Girls-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Guillaume-Lombardo/simple-md-to-docx-converter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ornament9edamame/Glory-To-The-Heroes-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CypherNova1337/VoidAI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `itssergekalajian-hub/news-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `krishnakoushik9/Garuda-Sentinel---Abuse-Ring-Fraud-Spike-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Crystal-Bell/M.A.D.-Works-Ecosystem-V2.0-Manifesto-Index-Structure` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbgainesiii-byte/brown-and-gaines` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benmpolak/the-league` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `StackVisionCode/TaxVsion_BackEnd` | GITHUB | IP-Datei 70d alt |
| `huddle173654pizzazz/Loftia-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sanchomuzax/PicasaPy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sagarxettri000/geet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Eladlavy12/apt-scout` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `guilz-dev/belay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amineelkhayari/pfa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `redonemakhlouf64-cyber/asp-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PhilGoode/honeypot-malware-research` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `angelulloaexchange-afk/Wand-Enhancer2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `leonbubova/soft-landing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UVE-QA/aws-devops-sdet-demo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lei-TzuY/security-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gunners-sticks-8/Warhammer-Survivors-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `impurely-jigging79154/Witchbrook-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `venkateshv1266/my-pi-setup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AgentSystemLabs/nebula` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WorkWithAnjola/WorkWithAnjola` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arunprasadlv/customer-support-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yogisyahroni/applyer-indonesia` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dustpans-2345cassavas/Lantern-of-the-Laughless-Saint-Community-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Shivam1337/quantix-hft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skinsdreamers6/Dimraeth-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jmpsec/osctrl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sampaiofa-tech/Raix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marcodemm/bughunter-harness` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aesblynn85-debug/RidgecrestThreatAdvisory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `songyaeji/sec-feed-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betwixthawked99459/Expedition-Into-Darkness-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DrEgoroff-drift/drift` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bluzsammy-png/Deeyoung` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `memhtml/memhtml` | GITHUB | Größe: 0 IPs |
| `ETHgenight/ict-quant-ai-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `2584210631-star/mc-scanner-v3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sebiboga/testlink-upgraded` | GITHUB | Größe: 0 IPs |
| `babaali131718-spec/rs2b0t-quest-forge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lochanjune1721-eng/viralyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `emstrad/DAMPSCAN` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tylevo/Tylevo.TacticalServicesControl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tamil05t/Exfiltrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiteshtara/enterprise-agentops` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carnage-sunned523436/Heros-Adventure-Another-Tale-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KarthikGovindan320/Odoo-finals` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tthoma24/brscan-mac` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KwasiAsante/Music_Enrichment_Management_Service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Abo-esmahel/Rasd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `soyeht/soyeht-ios` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rube-188swinish/Silent-Breath-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cardpay/unlimeety` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skimp-vetch-74610/Fragile-Existence-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ModernIlham/NEW-AMAN-IKN` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MazedOut/TallyBook_Ai_Finance_Controller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `visal2002/Dzongkha-Standard-Testing-System` | GITHUB | Größe: 0 IPs |
| `yukiyuki1900/repoForgeAgent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Atith-C/ApplyMerge---Concurrent-Infrastructure-Apply-Reconciliation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rppalmer/ORIS` | GITHUB | Größe: 0 IPs |
| `yidongw/foxhole-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evoelsewhere/evoflux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maccavelli/magic-cli-remote` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kronfarore/halo-run-enhancer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Princepadariya/Altosa-Exim-LLP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `erikhinderer/couchbase-agent-operations-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `accessed2lazy/AION-2-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tombaldwin/candor-spec` | GITHUB | IP-Datei 46d alt |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 29,049 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,480 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,461 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 11,228 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,852 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,636 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,750 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,686 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,953 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,342 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 2,829 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 1,911 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,309 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 790 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 755 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 630 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 328 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 53,715 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,459 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 17,241 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 8,764 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,226 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,681 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 2,912 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 213,865 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,720 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,909 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,634 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 124,033 | 0.1% | 1560 | 2026-08-01 |
| `hookzof_socks5_list` | GITHUB | 192 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,698 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 11,272 | 64.3% | 938 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 52,803 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,484 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 116,732 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,711 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 93,629 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,537 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,504 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 104,489 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,711 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 124,009 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,394 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 114,270 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 564 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 483,877 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,175 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 171,770 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 180,938 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 147,292 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 129,692 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 102,641 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 128,323 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 99,845 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 215,543 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 62,360 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 151,890 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 33,246 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 24,212 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 25,163 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 21,549 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 19,358 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 36,782 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 15,801 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 12,512 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 8,161 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 18,258 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 9,716 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,583 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 9,279 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 6,474 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 1,838 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 11,047 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,855 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,788 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 1,127 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,458 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,938 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 9,459 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 3,377 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 82,267 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,757 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,066 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 57,260 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 4,215 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,702 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 2,127 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,297 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 84,995 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 289,938 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,276 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,111 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 6,384 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,558 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 28 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 85,223 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 93,718 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,395 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 86 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 223,908 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,186 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,704 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 186,510 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 31,213 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 6,806 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 2,615 | 34.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_compromised` | GITHUB | 15,544 | 65.9% | 2 | 2026-08-01 |
| `securitylist1568_fortigate` | GITHUB | 178 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 14,764 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 14,847 | 76.5% | 3 | 2026-08-09 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,063 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,960 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 15,978 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,334 | 31.1% | 1 | 2026-07-14 |
| `fwahyui_masifa_ipblacklist` | GITHUB | 126,973 | 91.7% | 1 | 2026-08-16 |
| `idleadmin_threatfeed` | GITHUB | 55,536 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 58,496 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,788 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 132,763 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 460 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 194,194 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 133,248 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 164,206 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,237 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 33,900 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 493 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 20,765 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 15,543 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,734 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 6,484 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 10,099 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,655 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,595 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 5,250 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,953 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,115 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,533 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,667 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,854 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 1,325 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,093 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,368 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,339 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,350 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,290 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,238 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 959 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,116 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,169 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 999 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,495 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 708 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,950 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,884 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,470 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 14,172 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,309 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 93,735 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 94,868 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 92,467 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 91,223 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 92,022 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 88,624 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,824 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 44,977 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 12,211 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,952 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,065 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,500 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,820 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 43,812 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 21,272 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 13,595 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 5,923 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 51 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 25,440 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 129,795 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 21,615 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,783 | 5.1% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 5,952 | 7.6% | 0 | 2026-09-04 |

---
*Generiert: 2026-09-05 18:34 CEST (Europe/Berlin)*