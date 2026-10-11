# Auto Feed Discovery – Report
**Aktualisiert:** 2026-10-11 13:00 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 16 |
| Kandidaten gesamt | **11797** |
| davon GitHub (Topics+Code) | **11701** |
| davon GitLab | **96** |
| davon Awesome-Lists | **2208** |
| Tools/Libraries vor Eval gefiltert | **941** |
| davon Hard-Reject (awesome-Liste etc.) | **201** |
| EVAL-Kandidaten (nach Stratifizierung) | **417** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **417** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **415** |
| Neu angenommene Feed-Dateien | **2** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **194** |
| Abgelehnte Repositories (dieser Run) | **415** |
| davon GitLab abgelehnt | **7** |
| Feeds gesamt (aktiv) | **196** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **141053** |
| SQLite-Refresh-Cache-Hits | **6/198** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **250** |
| Repo zu alt (>30d) | **121** |
| IP-Datei veraltet (>30d) | **32** |
| Falsche Größe (<30 / >2,000,000 IPs) | **11** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |
| Sonstige | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `configserverapps_service_blocklists_attacks_mail` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 5,474 | 64.3% | 0.0% | 10 | 🆕 NEU |
| `cbuijs_hagezi` | [cbuijs/hagezi](https://github.com/cbuijs/hagezi) | GITHUB | 28,901 | 38.6% | 0.0% | 127 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `mitchellkrogza/apache-ultimate-bad-bot-blocker` | GITHUB | Overlap zu gering: 0.4% |
| `mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites` | GITHUB | Zu alt: 1091d |
| `mitchellkrogza/fail2ban-useful-scripts` | GITHUB | Zu alt: 3035d |
| `mitchellkrogza/linux-server-administration-scripts` | GITHUB | Zu alt: 3477d |
| `eset/malware-ioc` | GITHUB | IP-Datei 3442d alt |
| `derhuerst/email-providers` | GITHUB | Zu alt: 355d |
| `ThreatMon/ThreatMon-Daily-C2-Feeds` | GITHUB | Zu alt: 1019d |
| `adhdproject/spidertrap` | GITHUB | Zu alt: 2300d |
| `firehol/iprange` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `firehol/firehol` | GITHUB | Zu alt: 194d |
| `carbonblack/active_c2_ioc_public` | GITHUB | Zu alt: 1413d |
| `OktayAlver/siberkapan` | GITHUB | Zu alt: 48d |
| `noctiro/stormin` | GITHUB | Zu alt: 154d |
| `CriticalPathSecurity/Zeek-Intelligence-Feeds` | GITHUB | Identischer Inhalt wie kraloveckey_ipsets_blocklist_bds_atif |
| `Bert-JanP/Incident-Response-Powershell` | GITHUB | Zu alt: 138d |
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2222d |
| `inversify/InversifyJS` | GITHUB | Zu alt: 326d |
| `midwayjs/midway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anjoy8/Blog.Core` | GITHUB | Zu alt: 178d |
| `ets-labs/python-dependency-injector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typestack/typedi` | GITHUB | Zu alt: 347d |
| `jeffijoe/awilix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oblac/jodd` | GITHUB | Zu alt: 909d |
| `w3tecch/express-typescript-boilerplate` | GITHUB | Zu alt: 1253d |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellokaton/java-bible` | GITHUB | Zu alt: 1702d |
| `samber/do` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PHP-DI/PHP-DI` | GITHUB | Zu alt: 284d |
| `appsquickly/typhoon` | GITHUB | Zu alt: 2121d |
| `nutzam/nutz` | GITHUB | Zu alt: 68d |
| `unitycontainer/unity` | GITHUB | Zu alt: 994d |
| `gustavopsantos/Reflex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zycgit/hasor-old` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `reactiveui/splat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ntxinh/AspNetCore-DDD` | GITHUB | Zu alt: 287d |
| `danielpalme/IocPerformance` | GITHUB | Zu alt: 1179d |
| `YairHalberstadt/stronginject` | GITHUB | Zu alt: 468d |
| `forrest-orr/moneta` | GITHUB | Zu alt: 939d |
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VictorTzeng/Zxw.Framework.NetCore` | GITHUB | Zu alt: 41d |
| `exilon/QuickLib` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anakic/Jot` | GITHUB | Zu alt: 366d |
| `golobby/container` | GITHUB | Zu alt: 409d |
| `yoyofx/yoyogo` | GITHUB | Zu alt: 905d |
| `0x27/linux.mirai` | GITHUB | Zu alt: 3523d |
| `SwingFrog/Summer` | GITHUB | Zu alt: 542d |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `suites-dev/suites-unit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `farseer-go/fs` | GITHUB | Zu alt: 112d |
| `EcsRx/ecsrx` | GITHUB | Zu alt: 478d |
| `roadwy/DefenderYara` | GITHUB | Zu alt: 150d |
| `Savory/Danet` | GITHUB | Zu alt: 55d |
| `thiagobustamante/typescript-ioc` | GITHUB | Zu alt: 822d |
| `bingcool/swoolefy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafaelfgx/DotNetCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gendigitalinc/ioc` | GITHUB | IP-Datei 1592d alt |
| `ivlevAstef/DITranquillity` | GITHUB | Zu alt: 157d |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pengweiqhca/Xunit.DependencyInjection` | GITHUB | Zu alt: 47d |
| `binghe001/BingheGuide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brianway/spring-learning` | GITHUB | Zu alt: 3695d |
| `midwayjs/midway-faas` | GITHUB | Zu alt: 2292d |
| `yinguangyao/blog` | GITHUB | Zu alt: 92d |
| `prodaft/malware-ioc` | GITHUB | Zu alt: 341d |
| `mwemuorg/mwemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `urfnet/URF.Core` | GITHUB | Zu alt: 753d |
| `owja/ioc` | GITHUB | Zu alt: 768d |
| `zazoomauro/node-dependency-injection` | GITHUB | Zu alt: 32d |
| `tshemsedinov/Patterns-JavaScript` | GITHUB | Zu alt: 245d |
| `inversify/monorepo` | GITHUB | IP-Datei 352d alt |
| `d1mnewz/interviews` | GITHUB | Zu alt: 1922d |
| `eggjs/tegg` | GITHUB | Zu alt: 34d |
| `ditekshen/detection` | GITHUB | Zu alt: 709d |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loresoft/Injectio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zheksoon/dioma` | GITHUB | Zu alt: 898d |
| `d3fvxl/di` | GITHUB | Zu alt: 1030d |
| `testdeck/testdeck` | GITHUB | Zu alt: 627d |
| `gnaeus/react-ioc` | GITHUB | Zu alt: 1074d |
| `intentor/adic` | GITHUB | Zu alt: 1889d |
| `urfnet/URF.NET` | GITHUB | Zu alt: 3063d |
| `Go-To-Byte/DouSheng` | GITHUB | Zu alt: 1231d |
| `molszanski/iti` | GITHUB | Zu alt: 39d |
| `hidevopsio/hiboot` | GITHUB | Zu alt: 125d |
| `dry-rb/dry-auto_inject` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wzhudev/redi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `agileago/vue3-oop` | GITHUB | Zu alt: 478d |
| `assafmo/xioc` | GITHUB | Zu alt: 2366d |
| `aalex954/evilginx2-TTPs` | GITHUB | Zu alt: 543d |
| `artberri/diod` | GITHUB | Zu alt: 737d |
| `wix-incubator/obsidian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `z4kn4fein/stashbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gensecaihq/Shai-Hulud-2.0-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xpleemoon/XModulable` | GITHUB | Zu alt: 3172d |
| `Puresharper/Puresharp` | GITHUB | Zu alt: 2810d |
| `MySixGod/SpringImpl_v2.0` | GITHUB | Zu alt: 3386d |
| `exuanbo/di-wise` | GITHUB | Zu alt: 606d |
| `TAKETODAY/today-infrastructure` | GITHUB | IP-Datei 274d alt |
| `Koatty/koatty` | GITHUB | IP-Datei 681d alt |
| `jbreckmckye/node-typescript-architecture` | GITHUB | Zu alt: 1046d |
| `100nm/python-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zzzzbw/doodle` | GITHUB | Zu alt: 1577d |
| `zovajs/zova` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jsuarezruiz/xamarin-forms-perf-playground` | GITHUB | Zu alt: 1403d |
| `shihabmridha/nodejs-repository-pattern-and-ioc` | GITHUB | Zu alt: 582d |
| `401trg/detections` | GITHUB | Zu alt: 2006d |
| `roo-oliv/injectable` | GITHUB | Zu alt: 402d |
| `NullArray/Mimir` | GITHUB | Zu alt: 2798d |
| `vuldb/cyber_threat_intelligence` | GITHUB | Zu alt: 69d |
| `ecomfe/uioc` | GITHUB | Zu alt: 3285d |
| `vercube/vercube` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nikku/didi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AsenaJs/Asena` | GITHUB | Zu alt: 39d |
| `mnasyrov/ditox` | GITHUB | Zu alt: 77d |
| `typesoft/container-ioc` | GITHUB | Zu alt: 2451d |
| `ZihanType/rudi` | GITHUB | Zu alt: 649d |
| `scanurag/FoodFrenzy` | GITHUB | Zu alt: 298d |
| `nicolascotton/nject` | GITHUB | Zu alt: 104d |
| `wessberg/DI-compiler` | GITHUB | Zu alt: 710d |
| `dmitryb-dev/waiter` | GITHUB | Zu alt: 971d |
| `uditalias/injex` | GITHUB | Zu alt: 355d |
| `go-spring-rip/spring-core` | GITHUB | Zu alt: 122d |
| `bootsrc/containerx` | GITHUB | Zu alt: 2828d |
| `Rick-van-Dam/Singularity` | GITHUB | Zu alt: 2218d |
| `mbierlee/poodinis` | GITHUB | Zu alt: 276d |
| `opensumi/di` | GITHUB | Zu alt: 394d |
| `conix-security/BTG` | GITHUB | Zu alt: 2875d |
| `go-spring-projects/go-spring` | GITHUB | Zu alt: 156d |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `absingh31/Tor_Spider` | GITHUB | Zu alt: 3153d |
| `100cm/thunder` | GITHUB | Zu alt: 3806d |
| `appsquickly/pilgrim` | GITHUB | Zu alt: 1338d |
| `maou-shonen/hono-simple-DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs` | GITHUB | Zu alt: 2009d |
| `di-ninja/di-ninja` | GITHUB | Zu alt: 557d |
| `HangfireIO/Hangfire.Autofac` | GITHUB | Zu alt: 639d |
| `krylosov-aa/context-async-sqlalchemy` | GITHUB | Zu alt: 119d |
| `ChistaDev/Chista` | GITHUB | Zu alt: 876d |
| `INotfound/Magic` | GITHUB | Zu alt: 1001d |
| `zhulik/pal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlyElhaddad/ThunderboltIoc` | GITHUB | Zu alt: 405d |
| `otavia-projects/otavia` | GITHUB | Zu alt: 132d |
| `enisn/DotNurseInjector` | GITHUB | Zu alt: 1020d |
| `xiuqianli1996/LSFramework` | GITHUB | Zu alt: 1041d |
| `tstromberg/ttp-bench` | GITHUB | Zu alt: 125d |
| `KnisterPeter/tsdi` | GITHUB | Zu alt: 1049d |
| `phantom0004/morpheus_IOC_scanner` | GITHUB | Zu alt: 606d |
| `OsmanKandemir/web-wordlist-generator` | GITHUB | Zu alt: 868d |
| `assafkip/huntkit` | GITHUB | IP-Datei 179d alt |
| `bdqfork/festival` | GITHUB | Zu alt: 2413d |
| `blacktop/docker-yara` | GITHUB | Zu alt: 1469d |
| `0xDanielLopez/TweetFeed_code` | GITHUB | Zu alt: 1420d |
| `Washi1337/cilfi` | GITHUB | Zu alt: 67d |
| `inversiland/inversiland` | GITHUB | Zu alt: 661d |
| `byme8/ZeroIoC` | GITHUB | Zu alt: 509d |
| `sergeysychov/behaviour_inject` | GITHUB | Zu alt: 1120d |
| `aloisdeniel/dioc` | GITHUB | Zu alt: 2364d |
| `d3fvxl/inject` | GITHUB | Zu alt: 2427d |
| `red-gold/ts-ui` | GITHUB | Zu alt: 857d |
| `jacoborus/wiremap` | GITHUB | Zu alt: 280d |
| `wenbo2018/mini-springframework` | GITHUB | Zu alt: 3199d |
| `GeiserX/Wayback-Diff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NPCmillionaire/dread-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `renkagod/tg-chat-dump` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `axmaier/tme-s` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xPloits3c/DorkEye` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/Telegram-Archive` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splunk/security_content` | GITHUB | IP-Datei 151d alt |
| `tenzir/vast` | GITHUB | Größe: 0 IPs |
| `SuperCowPowers/data_hacking` | GITHUB | IP-Datei 4517d alt |
| `splunk/attack_data` | GITHUB | IP-Datei 62d alt |
| `Cyb3rWard0g/ThreatHunter-Playbook` | GITHUB | IP-Datei 1489d alt |
| `olafhartong/ThreatHunting` | GITHUB | IP-Datei 1465d alt |
| `wazuh/wazuh` | GITHUB | IP-Datei 37d alt |
| `microsoft/msticpy` | GITHUB | IP-Datei 268d alt |
| `Yelp/elastalert` | GITHUB | IP-Datei 2635d alt |
| `endgameinc/eqllib` | GITHUB | IP-Datei 2634d alt |
| `splunk/attack_range` | GITHUB | IP-Datei 522d alt |
| `google/google-authenticator` | GITHUB | IP-Datei 5708d alt |
| `bridgecrewio/checkov` | GITHUB | IP-Datei 1040d alt |
| `lunasec-io/lunasec` | GITHUB | IP-Datei 1363d alt |
| `ClickSecurity/data_hacking` | GITHUB | IP-Datei 4517d alt |
| `pry0cc/axiom` | GITHUB | IP-Datei 1128d alt |
| `isgasho/finshir` | GITHUB | IP-Datei 2725d alt |
| `Khadinxc/TerraSigma` | GITHUB | IP-Datei 221d alt |
| `Bearer/bearer` | GITHUB | IP-Datei 846d alt |
| `deepfence/ThreatMapper` | GITHUB | IP-Datei 839d alt |
| `aboul3la/Sublist3r` | GITHUB | IP-Datei 2471d alt |
| `nccgroup/ScoutSuite` | GITHUB | IP-Datei 950d alt |
| `Neo23x0/sigma` | GITHUB | IP-Datei 319d alt |
| `nsacyber/GRASSMARLIN` | GITHUB | IP-Datei 3393d alt |
| `bitnami-labs/sealed-secrets` | GITHUB | IP-Datei 951d alt |
| `cystack/stealer-fingerprints` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MISP/misp-rfc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `airbus-seclab/qemu_blog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CipherShed/CipherShed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xlabssecurity/WAF-Hook` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hathcox/ToorChat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s0lst1c3/eaphammer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codewhitesec/HandleKatz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityRiskAdvisors/VECTR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ajinabraham/CMSScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ghostinthewires/Azure-Readiness-Checklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `6IX7ine/certstreamcatcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RoganDawes/P4wnP1_aloa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dustyfresh/PHP-vulnerability-audit-cheatsheet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Silva97/pei` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stufus/reconerator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lab41/PySEAL` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CoatiSoftware/Sourcetrail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alexey-T/CudaText` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3v4Si0N/HTTP-revshell` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `integrity-sa/burpcollaborator-docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skelsec/pypykatz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inmcm/kravatte` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cohdjn/cisecurity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deepinstinct/Lsass-Shtinkering` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wmkhoo/taintgrind` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fx5/not_random` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `m4tx/uefi-jitfuck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MISP/MISP-sizer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ufrisk/pcileech` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zeyad-Azima/Huawei_Thief` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GoSecure/malboxes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GhostPack/Rubeus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EdOverflow/can-i-take-over-xyz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SpiderLabs/social_mapper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `g-solaria/OSINTforPenTests` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marin-m/pbtk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `m8r0wn/subscraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MISP/PyMISP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `minimaxir/big-list-of-naughty-strings` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `allyomalley/dnsobserver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `grimm-co/NotQuite0DayFriday` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `streaak/keyhacks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `endgameinc/xori` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityRiskAdvisors/msspray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corna/me_cleaner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mbechler/marshalsec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SekoiaLab/fastir_artifacts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `36hours/idaemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nalen98/AngryGhidra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `davidprowe/BadBlood` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zodiacon/windowskernelprogrammingbook` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `offensivedev/urldozer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xsp-SRD/mortar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tegal1337/CiLocks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bing0o/SubEnum` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sebastianbiallas/ht` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre/attack-navigator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ciscocsirt/malspider` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nogginware/mstscdump` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `securitytxt/security-txt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `merrychap/shellen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JPCERTCC/ToolAnalysisResultSheet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mazen160/jwt-pwn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mthbernardes/QMKhuehuebr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dmarman/sha256algorithm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kudelskisecurity/cryptochallenge18` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `caioluders/PII-Identifier` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lawrenceamer/0xsp-Mongoose` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bing0o/Python-Scripts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gchq/CyberChef` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xZDH/o365spray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomnomnom/hacks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `o-o-overflow/dc2019q-ooops` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xRadi/OWASP-Web-Checklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Paradoxis/StegCracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `noperator/panos-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lakiw/pcfg_cracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `70corre20matar/cppngrok` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sfakiana/SANS-CTI-Summit-2021` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `davidtavarez/pwndb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shadowsocks/v2ray-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `joesecurity/joesandboxcloudapi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hackerschoice/gs-transfer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AnuragAnalog/hackerrank` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Spacial/csirt` | GITHUB | IP-Datei 2177d alt |
| `google/0x0g-2018-badge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ropnop/windapsearch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `presidentbeef/brakeman` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:phishdestroy/trustname-evidence` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:phishdestroy/namesilo-evidence` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:phishdestroy/phishdestroy` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:phishdestroy/ScamIntelLogs` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:phishdestroy/DestroyScammers` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:phishdestroy/medium-archive-phishdestroy` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:cyberintel-spain-ops/cyberintel-spain` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Levinders/hoolam` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PaulKinlan/agents` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `margaryanlabs/Margaryan-distribution` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mort2307/NightJar-Audio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fin-auren/Data-Engineering-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kshirsagar1994/The_Downloader` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tensozanghetzu-hub/horde-studio-apk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VaibhavGautam01/PQC-Migration-System` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tashaingle/GhostCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abigailnkimani-cyber/end_module_capstone` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arleoarlo-max/Arcane-Chip-Forge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nidhishakolkar01-lgtm/INFERA-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Spillers478/Global-Situation-Watch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zhuravel/magnum` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Its-Anandu/ISTE-WEBDEV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SniperDZ-Pro/SniperDZ-Pro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ManitShukla/CrossNexus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Phillip-England/englandsoftware.com` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nasiruddin-ai/PassiveArray` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrgoonie/zuey-me` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `himamshukg/bankism-ai-firewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Faiazzend/JusticeSphereAI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Islandyout/engine` | GITHUB | Größe: 0 IPs |
| `serenade18/twigaSoftApi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mohan123216/Iot_bot` | GITHUB | Größe: 0 IPs |
| `jere0208-png/RoomScanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Chaitanyasarkate/git-vault` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ranbir5ingh/dead-drop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KiaroSama/Telegram-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pavancharak/parmana` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neuroplastio/hotty-blitz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kurodesires/DigiEntry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `adamcir/Metrostroi_Expanded` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `papawattu/coxswain` | GITHUB | Größe: 0 IPs |
| `aaditya-paul/neuro-cache` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zema26/clairii-rai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `e-kulikov/pisar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GNPranesh-5/mediguard-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Avivovadia/MizeAssignment` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aliyan2525/oriel-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nalinkaggarwal/voice-dating-app` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `claythe3ed/heptagon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bherbruck/solvecraft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mohsen-niksirat/Tonora` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jfms7s/obsidian-sync` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vin-EdLabs/ClipNerve` | GITHUB | Größe: 0 IPs |
| `blandest-liner22392/Tribal-Fantasy-Orc-Girl-Romance-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `renaud-ist/yr_portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sai181006/CyberTrace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hornetrish/Phantom-Camo-Companion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Patil-26/Deepfake-Detection-using-Vision-Transformer-and-Temporal-Audio-Analytics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ryanhunt/torrent2synology` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lomehong/agent-ssh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `petfold/loopmarket` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stevelasudata/sky-dragon-duel-brain` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `asimu-prancing/Once-Human` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `niyongaboemmy/universal-bridge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JMC50/stelinfo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amit-dev01/Atheris` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iphoenk/FPL-iphoenk-engine` | GITHUB | IP-Datei 41d alt |
| `JFrusher/WarRoom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `year-thous869120/Harrowlands-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mixeme/selfpost` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rentefeale/MaskMyIP-Utility-Suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Saifuf1/nexora-license-portal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `banqueenie6/360-Nsa-Cyber-Weapons-Defense-Tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Freddy546/eset-internet-security-pro-toolset` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shijiu-world/VAutoStop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mailsvb2-bot/Universal-Communication-Runtime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bhoomiaiml26-hash/HerGaurdian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eragasa/projectkoios-simulations` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codefortoyama/kitekite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alphav00/poolos-saas` | GITHUB | Größe: 0 IPs |
| `VuradoUA/quantumtrace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Adityaaun/AgentShield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salrazafilm-debug/our-world` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `07kamrul/Uttar-Kaundia-Society` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neo1777/vps1777` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zerabyte88/phantek-gallery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `namansharma24092007-rgb/civic-reporter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `siddharthmanebusiness-ops/MGR-Blade-Symphony` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ionatech2025/global_pharmachain` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ASADOV8668/laravel-digistocki` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shortsjunction55-crypto/ledger-forge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `storytold/photocraft` | GITHUB | Größe: 0 IPs |
| `Sumit-ptdar/tdsskiller-relic-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mountainman-1904/Need-For-Speed-Most-Wanted-Full-Version` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sspallai/edl_objects` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nordicnode/freebuff-changelog` | GITHUB | Größe: 0 IPs |
| `LysaAnne/baby-app` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Omb2121/DYP-HACKTHON` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UnknownAlienHuman/eliot-swarm-controller` | GITHUB | Größe: 0 IPs |
| `jjjh7401/AI-Lighting_Console` | GITHUB | Größe: 0 IPs |
| `aicologne/aic-hardware-deals` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loreseekerl/nightfront-td-values` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uuidna/qpu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexkhovrenkov/test_project_DB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pixelspy-1/Yet-Another-Cleaner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jedharveycambel18-arch/gecko-tcp-bridge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeisenback/max-gravity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `perfidy-joke8633/Sugar-Phone-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amit-dev01/ai-backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `El-Dorado26/hive-honeypot-network` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `laceyenterprises/agentpaddock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Levango7/NexusSky` | GITHUB | Größe: 0 IPs |
| `interestingyong/codegraph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Burry071/evenlight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NullAITech/zoth-studio-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Abhrxdip/os` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fummah/milven-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RealKiro/cfnb-go` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `princedangola130-creator/grid-bot-core` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `terfabinda/website_earms` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alfatraktorbow53/Dauntless` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KingEmma7/kemma-technologies` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Abhrxdip/SelfOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nawazr22/ef-checksum-validator-v24.10` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `henrygoldsmith07-wq/draftwise` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dlecrivain/homelab-iac` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nuguna2/VWO-Ingenious-Solver-Package` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VivekReddy1234/SecureFileSharing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TwilightDuck/OpenQuill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ablation-Tool/ablation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SaadiDK-003/secondhand` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MakhnoGK/cerebrium` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `H4R5H1L-27/Credify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MANUJ0613/Manu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 22,097 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,733 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 10,611 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,675 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,862 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,738 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,775 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,951 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,951 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,281 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 2,861 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 1,952 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 973 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 714 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 753 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 658 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 420 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,316 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,703 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 19,190 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 11,206 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,447 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,509 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 5,136 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 214,569 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 3,983 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 5,378 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,628 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 3,252 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,723 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 4,642 | 64.3% | 938 | 2026-09-04 |
| `cbuijs_hagezi` | GITHUB | 28,901 | 38.6% | 127 | 2026-10-11 |
| `mohammedcha_proxripper` | GITHUB | 53,226 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,136 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,473 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 117,439 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 91,711 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,676 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 93,487 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 107,636 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,671 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 103,589 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,672 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 114,722 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 600 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 500,290 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,645 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 173,316 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 163,471 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 167,086 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 168,929 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 77,437 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 107,514 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 82,493 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 250,327 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 50,168 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 194,853 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 17,095 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 10,434 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,216 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 15,725 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 13,225 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 179,269 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 17,854 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 10,025 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 8,021 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 23,418 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 14,673 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 12,189 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 7,806 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 1,951 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,369 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 12,751 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,290 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 2,995 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,323 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,940 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,505 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,828 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 117,540 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 920 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 29,706 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,203 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 4,207 | 79.4% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,474 | 64.3% | 10 | 2026-10-11 |
| `ian_lusule_proxies` | GITHUB | 2,951 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,496 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,501 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 353,977 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 7,922 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 6,787 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 7,396 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,412 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 93 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 102,466 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 89,522 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,833 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 85 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 89,014 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,498 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,679 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 224 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 18,559 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 18,096 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 24,370 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,374 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 49,722 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 66,162 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,736 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 116,734 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 385 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,170 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 196,381 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,537 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 118,954 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 223,685 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,241 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 34,770 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 17,285 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 18,526 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,719 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 9,947 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 8,594 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,629 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 6,526 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,500 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,214 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,118 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 4,798 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,844 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 3,489 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 4,168 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,064 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,200 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,376 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,306 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,344 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,215 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,163 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,351 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,154 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,456 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 540 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,420 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,747 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,196 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 9,778 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 93,330 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 91,627 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 93,945 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 91,327 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 92,957 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 94,685 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 90,614 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 22,316 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 40,162 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 4,179 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,352 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,060 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 52,431 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 29,576 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 10,659 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 17,002 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 26 | 63.9% | 0 | 2026-08-12 |
| `zgzyh_malicious_website_detection` | GITHUB | 32,181 | 3.1% | 0 | 2026-08-15 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,234 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,627 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 5,368 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,132 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 895 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 376 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 287 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 6,067 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 91,470 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 94,314 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 90,827 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 88,893 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 90,137 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 27,907 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 2,209 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 2,179 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_20` | GITHUB | 184 | 92.3% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 601 | 76.9% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_24` | GITHUB | 157 | 90.4% | 0 | 2026-09-25 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,278 | 6.8% | 0 | 2026-10-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,210 | 63.9% | 0 | 2026-10-04 |

---
*Generiert: 2026-10-11 13:00 CEST (Europe/Berlin)*