# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-27 12:11 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 15 |
| Kandidaten gesamt | **11950** |
| davon GitHub (Topics+Code) | **11858** |
| davon GitLab | **92** |
| davon Awesome-Lists | **2197** |
| Tools/Libraries vor Eval gefiltert | **949** |
| davon Hard-Reject (awesome-Liste etc.) | **217** |
| EVAL-Kandidaten (nach Stratifizierung) | **424** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **424** |
| davon angenommene Repositories | **0** |
| davon abgelehnte Repositories | **424** |
| Neu angenommene Feed-Dateien | **0** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **198** |
| Abgelehnte Repositories (dieser Run) | **424** |
| davon GitLab abgelehnt | **4** |
| Feeds gesamt (aktiv) | **198** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **159875** |
| SQLite-Refresh-Cache-Hits | **12/205** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **206** |
| Repo zu alt (>30d) | **197** |
| IP-Datei veraltet (>30d) | **10** |
| Falsche Größe (<30 / >2,000,000 IPs) | **10** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `djkurlander/knock-knock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jnMetaCode/shellward` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jaegeral/security-apis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aw-junaid/Hacking-Tools` | GITHUB | Zu alt: 39d |
| `thefear078/DracoLure` | GITHUB | Zu alt: 61d |
| `rfxn/advanced-policy-firewall` | GITHUB | Zu alt: 128d |
| `mikeroyal/Open-Source-Security-Guide` | GITHUB | Zu alt: 457d |
| `stratosphereips/AIP` | GITHUB | Zu alt: 683d |
| `mikeroyal/Digital-Forensics-Guide` | GITHUB | Zu alt: 997d |
| `murchie85/murchie85.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `allenai/dolma` | GITHUB | Zu alt: 34d |
| `nickspaargaren/no-google` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BrowserWorks/waterfox` | GITHUB | IP-Datei 747d alt |
| `uBlockOrigin/uAssets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TamGamer97/spellbound` | GITHUB | Zu alt: 175d |
| `surprisetalk/licensure` | GITHUB | Zu alt: 941d |
| `pengelana/blocklist` | GITHUB | Größe: 0 IPs |
| `keboli/CTI-annotated-datasets` | GITHUB | Zu alt: 328d |
| `RepoAnalysis/RepoSnipy` | GITHUB | Zu alt: 959d |
| `Kilroy1337/ioc_lists` | GITHUB | Zu alt: 1119d |
| `visualstudioblyat/bushido` | GITHUB | Zu alt: 123d |
| `amount/secops-lists` | GITHUB | Zu alt: 339d |
| `Backlinko-LLC/2020-google-searches` | GITHUB | Zu alt: 2131d |
| `michredteam/RTbookNotes` | GITHUB | Zu alt: 819d |
| `goastian/midori-desktop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gfw-report/sp25-regional` | GITHUB | Zu alt: 504d |
| `dabi-team/someData` | GITHUB | Zu alt: 1431d |
| `cmndcntrlcyber/code-trainer-pipeline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `curtislbyrd/CyberVault` | GITHUB | Zu alt: 198d |
| `wessorh/yara-x-benchmarks` | GITHUB | Zu alt: 102d |
| `smart-rg/drafts` | GITHUB | Zu alt: 2396d |
| `0i0/deepme-crawler` | GITHUB | Zu alt: 1178d |
| `lxyeternal/IntelliRadar` | GITHUB | Zu alt: 221d |
| `jayala-29/svm2023-artifacts` | GITHUB | Zu alt: 1227d |
| `ArtDeuce/Semantics-Research` | GITHUB | Zu alt: 637d |
| `yaocccc/nvim` | GITHUB | Zu alt: 70d |
| `antonmedv/chat.php` | GITHUB | Zu alt: 164d |
| `Sharp-Team/chia-khoa-thanh-cong-fpt` | GITHUB | Zu alt: 1182d |
| `1979139113/0day-today-exploits` | GITHUB | Zu alt: 2297d |
| `n1h1lu5/pluralsight-hack-yourself-first` | GITHUB | Zu alt: 3889d |
| `arstgit/high-frequency-vocabulary` | GITHUB | Zu alt: 2455d |
| `b001io/wagner-fischer` | GITHUB | Zu alt: 969d |
| `zydou/high-frequency-words` | GITHUB | Zu alt: 1634d |
| `Squuv/WifiBF` | GITHUB | Zu alt: 2184d |
| `antirez/hnstyle` | GITHUB | Zu alt: 529d |
| `Shubham22u/Cehv11-12-Question-Answer` | GITHUB | Zu alt: 1281d |
| `lukas-reineke/dotfiles` | GITHUB | Zu alt: 460d |
| `akatakun/l4d2-scripts` | GITHUB | Zu alt: 2891d |
| `yitu-opensource/ConvBert` | GITHUB | Zu alt: 1454d |
| `westackai/glassworm-scanner` | GITHUB | Zu alt: 37d |
| `dpl0/phrack` | GITHUB | Zu alt: 558d |
| `perjayro/Facebook_brute` | GITHUB | Zu alt: 1716d |
| `dhalima3/Autoscribe` | GITHUB | Zu alt: 4052d |
| `Vishal-1756/WordGameBot` | GITHUB | Zu alt: 482d |
| `ZenarchistCode/ZenVirus` | GITHUB | Zu alt: 1285d |
| `bnusss/flow_network_embedding` | GITHUB | Zu alt: 3219d |
| `WPPlugins/reportattacks` | GITHUB | Zu alt: 3338d |
| `iank/capitals-solver` | GITHUB | Zu alt: 4119d |
| `amkraft/X-Files` | GITHUB | Zu alt: 3698d |
| `agonopol/go-stem` | GITHUB | Zu alt: 3025d |
| `ordinall/TypingMaster` | GITHUB | Zu alt: 1729d |
| `collinalexbell/SpectrumWifiCrack` | GITHUB | Zu alt: 2276d |
| `ajusa/sanictype` | GITHUB | Zu alt: 3284d |
| `DGoldDragon28/Unangband` | GITHUB | Zu alt: 489d |
| `hintjens/psychopathcode` | GITHUB | Zu alt: 3597d |
| `shubhamg0sai/Fbbrute` | GITHUB | Zu alt: 1673d |
| `OisinMoran/ShortestSearch` | GITHUB | Zu alt: 3237d |
| `WPPlugins/wp-doctor` | GITHUB | Zu alt: 3359d |
| `gabe-mousa/offline-type-speed` | GITHUB | Zu alt: 2533d |
| `shreyazh/cyber-sec` | GITHUB | Zu alt: 245d |
| `leedsrising/CamlMessage` | GITHUB | Zu alt: 2911d |
| `LondonStudios/W3W-FiveM` | GITHUB | Zu alt: 1664d |
| `CosineP/acrograms` | GITHUB | Zu alt: 2607d |
| `altostratous/abse` | GITHUB | Zu alt: 3900d |
| `HackDavis/github-workshop` | GITHUB | Zu alt: 2524d |
| `planemanner/ELECTRA` | GITHUB | Zu alt: 1641d |
| `M4DM0e/wpCrack` | GITHUB | Zu alt: 1846d |
| `thoppe/homophonic-encryption` | GITHUB | Zu alt: 3995d |
| `tanmoysrt/Word_Puzzle_Solve_And_Check_Existance` | GITHUB | Zu alt: 2349d |
| `sohzm/Tyfinity` | GITHUB | Zu alt: 1570d |
| `mitchellkrogza/apache-ultimate-bad-bot-blocker` | GITHUB | Overlap zu gering: 0.4% |
| `mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites` | GITHUB | Zu alt: 1077d |
| `mitchellkrogza/fail2ban-useful-scripts` | GITHUB | Zu alt: 3021d |
| `mitchellkrogza/linux-server-administration-scripts` | GITHUB | Zu alt: 3463d |
| `derhuerst/email-providers` | GITHUB | Zu alt: 341d |
| `ThreatMon/ThreatMon-Daily-C2-Feeds` | GITHUB | Zu alt: 1005d |
| `adhdproject/spidertrap` | GITHUB | Zu alt: 2286d |
| `firehol/iprange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `firehol/firehol` | GITHUB | Zu alt: 180d |
| `carbonblack/active_c2_ioc_public` | GITHUB | Zu alt: 1399d |
| `Mohammedcha/gplay-scraper` | GITHUB | Zu alt: 315d |
| `Mohammedcha/UnityReskinGuard` | GITHUB | Zu alt: 1156d |
| `Mohammedcha/ReskinGuard` | GITHUB | Zu alt: 1157d |
| `Mohammedcha/Play-Apps-Sortering` | GITHUB | Zu alt: 2789d |
| `noctiro/stormin` | GITHUB | Zu alt: 140d |
| `Mohammedcha/Keywords-Highlighter` | GITHUB | Zu alt: 2789d |
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2208d |
| `inversify/InversifyJS` | GITHUB | Zu alt: 312d |
| `midwayjs/midway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anjoy8/Blog.Core` | GITHUB | Zu alt: 164d |
| `ets-labs/python-dependency-injector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typestack/typedi` | GITHUB | Zu alt: 333d |
| `jeffijoe/awilix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oblac/jodd` | GITHUB | Zu alt: 895d |
| `w3tecch/express-typescript-boilerplate` | GITHUB | Zu alt: 1239d |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellokaton/java-bible` | GITHUB | Zu alt: 1688d |
| `samber/do` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PHP-DI/PHP-DI` | GITHUB | Zu alt: 270d |
| `appsquickly/typhoon` | GITHUB | Zu alt: 2107d |
| `nutzam/nutz` | GITHUB | Zu alt: 54d |
| `unitycontainer/unity` | GITHUB | Zu alt: 980d |
| `gustavopsantos/Reflex` | GITHUB | Zu alt: 101d |
| `zycgit/hasor-old` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `reactiveui/splat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ntxinh/AspNetCore-DDD` | GITHUB | Zu alt: 273d |
| `danielpalme/IocPerformance` | GITHUB | Zu alt: 1165d |
| `YairHalberstadt/stronginject` | GITHUB | Zu alt: 454d |
| `forrest-orr/moneta` | GITHUB | Zu alt: 925d |
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VictorTzeng/Zxw.Framework.NetCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `exilon/QuickLib` | GITHUB | Zu alt: 142d |
| `anakic/Jot` | GITHUB | Zu alt: 352d |
| `golobby/container` | GITHUB | Zu alt: 395d |
| `yoyofx/yoyogo` | GITHUB | Zu alt: 891d |
| `SwingFrog/Summer` | GITHUB | Zu alt: 528d |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `farseer-go/fs` | GITHUB | Zu alt: 98d |
| `suites-dev/suites` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EcsRx/ecsrx` | GITHUB | Zu alt: 464d |
| `roadwy/DefenderYara` | GITHUB | Zu alt: 136d |
| `Savory/Danet` | GITHUB | Zu alt: 41d |
| `thiagobustamante/typescript-ioc` | GITHUB | Zu alt: 808d |
| `bingcool/swoolefy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafaelfgx/DotNetCore` | GITHUB | Zu alt: 40d |
| `gendigitalinc/ioc` | GITHUB | Zu alt: 118d |
| `ivlevAstef/DITranquillity` | GITHUB | Zu alt: 143d |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pengweiqhca/Xunit.DependencyInjection` | GITHUB | Zu alt: 33d |
| `binghe001/BingheGuide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brianway/spring-learning` | GITHUB | Zu alt: 3681d |
| `midwayjs/midway-faas` | GITHUB | Zu alt: 2278d |
| `yinguangyao/blog` | GITHUB | Zu alt: 78d |
| `prodaft/malware-ioc` | GITHUB | Zu alt: 327d |
| `mwemuorg/mwemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `urfnet/URF.Core` | GITHUB | Zu alt: 739d |
| `owja/ioc` | GITHUB | Zu alt: 754d |
| `zazoomauro/node-dependency-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tshemsedinov/Patterns-JavaScript` | GITHUB | Zu alt: 231d |
| `inversify/monorepo` | GITHUB | IP-Datei 338d alt |
| `d1mnewz/interviews` | GITHUB | Zu alt: 1908d |
| `eggjs/tegg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ditekshen/detection` | GITHUB | Zu alt: 695d |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loresoft/Injectio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zheksoon/dioma` | GITHUB | Zu alt: 884d |
| `d3fvxl/di` | GITHUB | Zu alt: 1016d |
| `testdeck/testdeck` | GITHUB | Zu alt: 613d |
| `gnaeus/react-ioc` | GITHUB | Zu alt: 1060d |
| `intentor/adic` | GITHUB | Zu alt: 1875d |
| `urfnet/URF.NET` | GITHUB | Zu alt: 3049d |
| `Go-To-Byte/DouSheng` | GITHUB | Zu alt: 1217d |
| `hidevopsio/hiboot` | GITHUB | Zu alt: 111d |
| `molszanski/iti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dry-rb/dry-auto_inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wzhudev/redi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `agileago/vue3-oop` | GITHUB | Zu alt: 464d |
| `assafmo/xioc` | GITHUB | Zu alt: 2352d |
| `aalex954/evilginx2-TTPs` | GITHUB | Zu alt: 529d |
| `artberri/diod` | GITHUB | Zu alt: 723d |
| `wix-incubator/obsidian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `z4kn4fein/stashbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gensecaihq/Shai-Hulud-2.0-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xpleemoon/XModulable` | GITHUB | Zu alt: 3158d |
| `Puresharper/Puresharp` | GITHUB | Zu alt: 2796d |
| `MySixGod/SpringImpl_v2.0` | GITHUB | Zu alt: 3372d |
| `exuanbo/di-wise` | GITHUB | Zu alt: 592d |
| `TAKETODAY/today-infrastructure` | GITHUB | IP-Datei 260d alt |
| `Koatty/koatty` | GITHUB | Zu alt: 154d |
| `jbreckmckye/node-typescript-architecture` | GITHUB | Zu alt: 1032d |
| `100nm/python-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zovajs/zova` | GITHUB | Zu alt: 106d |
| `zzzzbw/doodle` | GITHUB | Zu alt: 1563d |
| `jsuarezruiz/xamarin-forms-perf-playground` | GITHUB | Zu alt: 1389d |
| `shihabmridha/nodejs-repository-pattern-and-ioc` | GITHUB | Zu alt: 568d |
| `401trg/detections` | GITHUB | Zu alt: 1992d |
| `roo-oliv/injectable` | GITHUB | Zu alt: 388d |
| `NullArray/Mimir` | GITHUB | Zu alt: 2784d |
| `vuldb/cyber_threat_intelligence` | GITHUB | Zu alt: 55d |
| `ecomfe/uioc` | GITHUB | Zu alt: 3271d |
| `vercube/vercube` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nikku/didi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AsenaJs/Asena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mnasyrov/ditox` | GITHUB | Zu alt: 63d |
| `typesoft/container-ioc` | GITHUB | Zu alt: 2437d |
| `ZihanType/rudi` | GITHUB | Zu alt: 635d |
| `scanurag/FoodFrenzy` | GITHUB | Zu alt: 284d |
| `nicolascotton/nject` | GITHUB | Zu alt: 90d |
| `wessberg/DI-compiler` | GITHUB | Zu alt: 696d |
| `dmitryb-dev/waiter` | GITHUB | Zu alt: 957d |
| `uditalias/injex` | GITHUB | Zu alt: 341d |
| `go-spring-rip/spring-core` | GITHUB | Zu alt: 108d |
| `bootsrc/containerx` | GITHUB | Zu alt: 2814d |
| `Rick-van-Dam/Singularity` | GITHUB | Zu alt: 2204d |
| `mbierlee/poodinis` | GITHUB | Zu alt: 262d |
| `opensumi/di` | GITHUB | Zu alt: 380d |
| `conix-security/BTG` | GITHUB | Zu alt: 2861d |
| `go-spring-projects/go-spring` | GITHUB | Zu alt: 142d |
| `100cm/thunder` | GITHUB | Zu alt: 3792d |
| `absingh31/Tor_Spider` | GITHUB | Zu alt: 3139d |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `appsquickly/pilgrim` | GITHUB | Zu alt: 1324d |
| `modern-python/modern-di` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maou-shonen/hono-simple-DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs` | GITHUB | Zu alt: 1995d |
| `di-ninja/di-ninja` | GITHUB | Zu alt: 543d |
| `HangfireIO/Hangfire.Autofac` | GITHUB | Zu alt: 625d |
| `ChistaDev/Chista` | GITHUB | Zu alt: 862d |
| `krylosov-aa/context-async-sqlalchemy` | GITHUB | Zu alt: 105d |
| `INotfound/Magic` | GITHUB | Zu alt: 987d |
| `zhulik/pal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlyElhaddad/ThunderboltIoc` | GITHUB | Zu alt: 391d |
| `otavia-projects/otavia` | GITHUB | Zu alt: 118d |
| `enisn/DotNurseInjector` | GITHUB | Zu alt: 1006d |
| `xiuqianli1996/LSFramework` | GITHUB | Zu alt: 1027d |
| `tstromberg/ttp-bench` | GITHUB | Zu alt: 111d |
| `KnisterPeter/tsdi` | GITHUB | Zu alt: 1035d |
| `OsmanKandemir/web-wordlist-generator` | GITHUB | Zu alt: 854d |
| `phantom0004/morpheus_IOC_scanner` | GITHUB | Zu alt: 592d |
| `bdqfork/festival` | GITHUB | Zu alt: 2399d |
| `assafkip/huntkit` | GITHUB | IP-Datei 165d alt |
| `blacktop/docker-yara` | GITHUB | Zu alt: 1455d |
| `inversiland/inversiland` | GITHUB | Zu alt: 647d |
| `byme8/ZeroIoC` | GITHUB | Zu alt: 495d |
| `sergeysychov/behaviour_inject` | GITHUB | Zu alt: 1106d |
| `aloisdeniel/dioc` | GITHUB | Zu alt: 2350d |
| `0xDanielLopez/TweetFeed_code` | GITHUB | Zu alt: 1406d |
| `Washi1337/cilfi` | GITHUB | Zu alt: 53d |
| `d3fvxl/inject` | GITHUB | Zu alt: 2413d |
| `red-gold/ts-ui` | GITHUB | Zu alt: 843d |
| `jacoborus/wiremap` | GITHUB | Zu alt: 266d |
| `wenbo2018/mini-springframework` | GITHUB | Zu alt: 3185d |
| `InQuest/ThreatIngestor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kurolabs/stegcloak` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `v8blink/Chromium-based-XSS-Taint-Tracking` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/binarypig` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `docbleach/DocBleach` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zigrin-Security/CakeFuzzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marcwebbie/passpie` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `insidersec/insider` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cossacklabs/themis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spectralops/netz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RIPE-NCC/hadoop-pcap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jery0843/torforge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `51j0/Android-Storage-Extractor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaplanelad/shellfirm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rapid7/metasploit-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `segmentio/chamber` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amocrenco/owasp-testing-checklist-v4-markdown` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `padok-team/cognito-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Storyyeller/enjarify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RedTeamPentesting/monsoon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gamelinux/passivedns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `curiefense/curiefense` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spectralops/teller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nbs-system/naxsi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `USArmyResearchLab/Dshell` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fugue/credstash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lyft/confidant` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Khadinxc/Sigma2KQL` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pfq/PFQ` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nxgn-kd01/shai-hulud-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fingerprintjs/fingerprint-android` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `k4m4/movies-for-hackers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KishanBagaria/padding-oracle-attacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ConradIrwin/dotgpg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GrapheneOS/hardened_malloc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cloudflare/redoctober` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Khadinxc/Sigma2SPL` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dev-sec/ansible-os-hardening` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UDcide/udcide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khast3x/Redcloud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `apps/guardrails` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spectralops/preflight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nxgn-kd01/react2shell-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skylot/jadx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sergiomarotco/Network-segmentation-cheat-sheet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GoVanguard/legion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tfsec/tfsec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `simsong/tcpflow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `firezone/firezone` | GITHUB | IP-Datei 48d alt |
| `rusty-ferris-club/recon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/tsunami-security-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ossf/allstar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ANSSI-FR/AD-control-paths` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `latchset/tang` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keikoproj/kube-forensics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/sunburst_countermeasures` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spaceraccoon/manuka` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `securitywithoutborders/hardentools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/gvisor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `realparisi/WMI_Monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `securestate/king-phisher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mikeperry-tor/vanguards` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sonatype-nexus-community/repo-diff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `slackhq/nebula` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `linuz/Sticky-Keys-Slayer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `latchset/clevis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yelp/osxcollector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `opensourcesec/CIRTKit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Apr4h/CobaltStrikeScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `apple/password-manager-resources` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PlumHound/PlumHound` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `toniblyx/prowler` | GITHUB | Größe: 0 IPs |
| `opsgenie/kubernetes-event-exporter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alichtman/stronghold` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nsacyber/Windows-Secure-Host-Baseline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `certsocietegenerale/swordphish-awareness` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `apiiro/combobulator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sensepost/notruler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pellegre/libcrafter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cloudflare/mitmengine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nccgroup/PMapper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `technosophos/helm-gpg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/santa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/red_team_tool_countermeasures` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JupiterOne/starbase` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `genuinetools/bane` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Infocyte/PSHunt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `awslabs/git-secrets` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coreos/clair` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rams3sh/Aaia` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `serain/mailspoof` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/ukip` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `firstlookmedia/gpgsync` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThreatResponse/aws_ir` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jkroepke/helm-secrets` | GITHUB | IP-Datei 2345d alt |
| `darkoperator/Posh-VirusTotal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `facebook/osquery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `containers/bubblewrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codeexpress/respounder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jtesta/ssh-audit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SSLMate/certspotter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `snyk-labs/snync` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `darkbitio/mkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `muxinc/certificate-expiry-monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VirusTotal/yara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `censys/censys-python` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sensepost/ruler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tonarino/innernet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cruise-automation/k-rail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `certsocietegenerale/NotifySecurity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CrowdStrike/automactc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `theupdateframework/notary` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `opensourcesec/Forager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cisagov/untitledgoosetool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hadojae/DATA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NetSPI/SpoofSpotter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trilwu/apttrail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0pc0deFR/YaraRules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/OpenIOC_1.1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:iiTONELOC/sigint` | GITLAB | Zu alt: 137d |
| `gitlab:valtersit/threat-ip-blocklist` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:ayinedjimi-consultants/YaraGen-AI` | GITLAB | Zu alt: 128d |
| `gitlab:ayinedjimi-consultants/ThreatIntel-GPT` | GITLAB | Zu alt: 128d |
| `Latnook/voteball` | GITHUB | IP-Datei 40d alt |
| `wizzydizzy-ctrl/dragons-gate-staff-hud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wizzydizzy-ctrl/dragons-gate-player-hud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `adarshkumar-s/document-screening` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stSoftwareAU/VibeCoder` | GITHUB | Größe: 0 IPs |
| `gtpw0494-png/Witforge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PyDataAnalytics/navigating-ai-risk` | GITHUB | IP-Datei 116d alt |
| `coinsecuritiescompany/AIFP-4-Mesh-Hackathon-Colosseum-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alihuzaifa-siddiqui302/fintech-fraud-detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VikashChoudhary-04/SecureForge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ADIMIR21/Hollow-Knight-Bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kidus-yahun/anti_phishing_extension` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BravoRicDev/scrocco-llm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Oontlaw/SkillSync` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SLIIT-Y4-ORG/SSD-SE4030-ASSIGNMENT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wgo26/eea` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ali-ulu/huqan` | GITHUB | IP-Datei 57d alt |
| `alulema/ccr-receipts-lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GrischaTDev/flipbase` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `greenblacked/AI` | GITHUB | Größe: 0 IPs |
| `pranee54/AgentDoctor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ayborg43/codeRoute` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `007sriram00-oss/anticheat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rhizomatics/signalk-einklabel-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maci0/appattic` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yumaitau/PaperBoy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mdshahjadkhan124-ui/MovieTctBooking` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aznred/Destiny-Rugby` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Gurukiran10/research-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `millymilly29/agent-firewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mudit-R/order-matching-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khalid-naami/marine-traffic-actor` | GITHUB | Größe: 0 IPs |
| `succedd/workbuddy_it-interview` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x812033727/travel_scanner` | GITHUB | Größe: 0 IPs |
| `maci0/openshift-baseline-security` | GITHUB | Größe: 0 IPs |
| `Siddiquiashrafhussain/SIF-Sentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rangeballsdirect/rangeballsdirect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drashtiavaiya/sql-assignment` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vxture/vx-agent-yucer` | GITHUB | IP-Datei 46d alt |
| `minibike522wilds/EXODUS-Leaked-Dev-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eugeniughelbur/jev-engineering` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OthmaneBlial/MobaRust` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RunbotRobot/chess-repertoire-simple` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jadolg/elodin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RohitMunnuru9/DOGFOODHACK` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yash122005/resume_analyser1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `definite-gazpacho66/Gears-of-War-E-Day-Beta-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SAKETH070706/SIH_2K26` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `24eg105r65-glitch/thunder-weather-forecasting` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IHUI-INF-AI/IHUI-AI` | GITHUB | Größe: 0 IPs |
| `majeed74905/Majeed-Portfolio-Backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeevanchandrashekhar31-a11y/ECDAT` | GITHUB | Größe: 0 IPs |
| `vikas-kumawatt/flyleaf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `samuel-1-avson/CipherVault` | GITHUB | Größe: 0 IPs |
| `sorrels-30180-funner/Liminal-Point-Prototype-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `saunters7prune/Sex-Idler-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nickdotname/ugc-factory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 22,924 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,650 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,401 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 5,036 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,847 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,779 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,722 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,883 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,950 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,225 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,004 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 1,900 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 876 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 680 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 692 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 630 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 387 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,258 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,727 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 18,333 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 10,283 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,669 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,642 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 4,389 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 212,858 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,585 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 4,247 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,632 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 2,247 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,712 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 11,778 | 64.3% | 938 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 54,016 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,748 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 118,244 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 116,923 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 91,576 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,714 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,502 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 106,409 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,654 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 102,567 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 7,000 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 124,669 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 669 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 474,162 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,458 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 172,566 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 162,942 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 138,460 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 153,965 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 89,397 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 111,323 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 83,029 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 235,606 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 58,232 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 180,300 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 32,623 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 26,506 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 24,590 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 16,525 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 20,807 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 177,974 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,729 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 11,672 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,237 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 21,546 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 13,823 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,418 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 11,377 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 7,317 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,192 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 11,432 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,377 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,878 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 5,100 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,628 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,787 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,856 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,949 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 105,017 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,737 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,019 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 28,978 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,080 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 3,367 | 79.4% | 10 | 2026-09-24 |
| `ian_lusule_proxies` | GITHUB | 4,140 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 2,086 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,409 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 375,370 | 22.0% | 6 | 2026-07-08 |
| `gazpitchy92_ip_blocklist_blacklist` | GITHUB | 370,106 | 25.4% | 6 | 2026-09-25 |
| `officialputuid_proxyforeveryone` | GITHUB | 7,922 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 6,787 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 7,396 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,520 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 102 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 96,434 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 94,207 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,587 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 86 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 93,820 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,858 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,706 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 358 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 17,659 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 17,383 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 21,628 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,360 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 52,041 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 62,973 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,718 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 115,719 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 349 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 195,513 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,536 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 115,156 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 203,021 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 34,352 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 15,593 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 18,503 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,728 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 9,830 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,191 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,638 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 5,415 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,532 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,117 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,532 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 4,856 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,828 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 6,344 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 3,963 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,208 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,374 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,423 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,350 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,341 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,718 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,226 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,918 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,173 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,467 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 686 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,944 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,693 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 966 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 11,972 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 91,523 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 91,166 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 89,935 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 94,845 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 93,910 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 93,202 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 89,838 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,214 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 43,252 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 11,895 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,868 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,856 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,000 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,080 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 42,432 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 20,500 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 11,810 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 6,590 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 36 | 63.9% | 0 | 2026-08-12 |
| `zgzyh_malicious_website_detection` | GITHUB | 29,173 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 153,962 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 16,860 | 54.9% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,148 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,372 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 4,035 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,531 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 988 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 183 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 81 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 5,963 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 98,653 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 91,280 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 92,801 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 91,006 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 88,372 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 26,508 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 1,028 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 1,018 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_20` | GITHUB | 183 | 92.3% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 251 | 76.9% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_24` | GITHUB | 157 | 90.4% | 0 | 2026-09-25 |

---
*Generiert: 2026-09-27 12:11 CEST (Europe/Berlin)*