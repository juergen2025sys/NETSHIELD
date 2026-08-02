# Auto Feed Discovery – Report
**Aktualisiert:** 2026-08-02 19:15 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **10276** |
| davon GitHub (Topics+Code) | **10199** |
| davon GitLab | **77** |
| davon Awesome-Lists | **2205** |
| Tools/Libraries vor Eval gefiltert | **699** |
| davon Hard-Reject (awesome-Liste etc.) | **188** |
| EVAL-Kandidaten (nach Stratifizierung) | **369** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **369** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **368** |
| Neu angenommene Feed-Dateien | **2** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **173** |
| Abgelehnte Repositories (dieser Run) | **368** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **175** |
| IPs in seen_db bestätigt | **3200306** |
| Neue IPs eingetragen | **494** |
| seen_db gesamt | **14,275,955** |
| HQ-Referenz-IPs (6 Quellen) | **110644** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Repo zu alt (>30d) | **209** |
| Keine IP-Datei im Repo | **131** |
| IP-Datei veraltet (>30d) | **22** |
| Falsche Größe (<100 / >2,000,000 IPs) | **6** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `ziyadnz_threat_intel_ip_feeds_ipv4_blacklist` | [ziyadnz/threat-intel-ip-feeds](https://github.com/ziyadnz/threat-intel-ip-feeds) | GITHUB | 106,703 | 46.2% | 0.0% | 8 | 🆕 NEU |
| `securitylist1568_fortigate` | [securitylist1568/Fortigate](https://github.com/securitylist1568/Fortigate) | GITHUB | 153 | 28.1% | 0.65% | 2 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `bb1nfosec/Information-Security-Tasks` | GITHUB | IP-Datei 72d alt |
| `AppliedIR/Valhuntir` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LETHAL-FORENSICS/Microsoft-Analyzer-Suite` | GITHUB | IP-Datei 44d alt |
| `parseword/nolovia` | GITHUB | Zu alt: 34d |
| `codelassey/tpot-soc-automation` | GITHUB | Zu alt: 47d |
| `Intevation/intelmq-mailgen` | GITHUB | Zu alt: 85d |
| `DXC-0/soc-ressources` | GITHUB | Zu alt: 111d |
| `mikeroyal/Open-Source-Security-Guide` | GITHUB | Zu alt: 401d |
| `LearningKijo/KQL` | GITHUB | Zu alt: 618d |
| `curated-intel/Log4Shell-IOCs` | GITHUB | Zu alt: 1612d |
| `Bert-JanP/Hunting-Queries-Detection-Rules` | GITHUB | IP-Datei 1112d alt |
| `michredteam/RTbookNotes` | GITHUB | Zu alt: 763d |
| `curtislbyrd/CyberVault` | GITHUB | Zu alt: 142d |
| `saicharanamaraneni18-source/phishing-mail-incident-response` | GITHUB | Zu alt: 56d |
| `shubham7003/Security-Infrastructure-Observability-Platform` | GITHUB | Zu alt: 61d |
| `bhengubv/CircleAI` | GITHUB | Größe: 0 IPs |
| `bitjbullock/SysAdmin` | GITHUB | Zu alt: 75d |
| `servo/servo` | GITHUB | Größe: 0 IPs |
| `ankitkumarsh39-sys/email-analyzer-soc-tool` | GITHUB | Zu alt: 39d |
| `yuntianze/dmp` | GITHUB | Zu alt: 334d |
| `paulrouget/servo-embedding-example` | GITHUB | Zu alt: 3065d |
| `de-otio/agent-safety-pack` | GITHUB | Zu alt: 33d |
| `fabricedesre/servonk` | GITHUB | Zu alt: 2852d |
| `WebBluetoothCG/registries` | GITHUB | Zu alt: 1083d |
| `shizukutanaka/Muten` | GITHUB | Größe: 0 IPs |
| `humaidq/dotfiles` | GITHUB | Größe: 0 IPs |
| `allenai/dolma` | GITHUB | Zu alt: 270d |
| `jesuslopezreynosa/useful-scripts` | GITHUB | IP-Datei 630d alt |
| `seia-soto/dns` | GITHUB | Zu alt: 837d |
| `kakarot-dev/dnsink` | GITHUB | Zu alt: 89d |
| `1Jamie/project-lotus` | GITHUB | Zu alt: 35d |
| `mxmgorin/retsurf` | GITHUB | IP-Datei 323d alt |
| `matiaselebi/Secure-DNS` | GITHUB | Größe: 0 IPs |
| `fx-dev-playground/gecko` | GITHUB | Zu alt: 1299d |
| `chaitanyaBytes/Slipstream` | GITHUB | Zu alt: 63d |
| `paulrouget/servofocus` | GITHUB | Zu alt: 3157d |
| `jschwe/ServoDemo` | GITHUB | IP-Datei 108d alt |
| `sagittaurius/malware-list-filter-compiler` | GITHUB | IP-Datei 63d alt |
| `paulrouget/hnbrowser` | GITHUB | Zu alt: 3323d |
| `jialunzhang-psu/SandCell-Artifact` | GITHUB | Zu alt: 199d |
| `ryanyxw/llm-decouple` | GITHUB | Zu alt: 311d |
| `arwunmarona/servo` | GITHUB | IP-Datei 31d alt |
| `anthonyniqmm/servo` | GITHUB | IP-Datei 31d alt |
| `webbeef/webviewer` | GITHUB | Zu alt: 716d |
| `justinmichaud/ion` | GITHUB | Zu alt: 2842d |
| `moto-browser/moto` | GITHUB | Zu alt: 464d |
| `securesystemslab/pkru-safe-servo` | GITHUB | Zu alt: 1370d |
| `fschutt/servo_gui_test` | GITHUB | Zu alt: 3232d |
| `Baconana-chan/ferro-browser` | GITHUB | Zu alt: 33d |
| `paulrouget/libsimpleservo` | GITHUB | Zu alt: 3225d |
| `karad/my-servo-embedding-example` | GITHUB | Zu alt: 2587d |
| `OwnedByWuigi/dactylic` | GITHUB | Zu alt: 60d |
| `galadran/tor-browser` | GITHUB | Zu alt: 2563d |
| `Anima-OS/Quokka` | GITHUB | Zu alt: 1314d |
| `kinetiknz/gecko` | GITHUB | Zu alt: 2377d |
| `BenEgeIzmirli/mozilla_central_in_c` | GITHUB | Zu alt: 1314d |
| `jsorg71/waterfox_classic_releases` | GITHUB | Zu alt: 1314d |
| `Nikhil-H-N/CIDECODE` | GITHUB | Zu alt: 68d |
| `nauman-nomi/Firewall-FrontEnd` | GITHUB | Zu alt: 316d |
| `initconf/misp_intel` | GITHUB | Zu alt: 158d |
| `DAYceng/elk4spark` | GITHUB | Zu alt: 1122d |
| `wuguobeijing/StratosphereLinuxIPS-dev` | GITHUB | Zu alt: 1153d |
| `valkyrianlabs/forti-hole` | GITHUB | Zu alt: 689d |
| `ervindaprtma/ervindaprtma.github.io` | GITHUB | Zu alt: 84d |
| `helsecert/blocklist` | GITHUB | Zu alt: 107d |
| `GhostKellz/arch` | GITHUB | IP-Datei 310d alt |
| `Vu1nT0tal/yarb` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `KevinGuenay/fortigate-baseline` | GITHUB | Zu alt: 72d |
| `kj299/threat-intel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spatiumddi/spatiumddi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BassilekinJean/Configuration-Inter-VLANS-avec-Fortigate-` | GITHUB | Zu alt: 470d |
| `fortinet/aws-lambda-guardduty` | GITHUB | Zu alt: 1177d |
| `demisto/content-docs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `habib-wael/DEPI-Enterprise-Network-Infrastructure` | GITHUB | Zu alt: 238d |
| `icloolg/Cyber_Machine_Solutions` | GITHUB | Zu alt: 598d |
| `nericksen/xsoar-cli` | GITHUB | Zu alt: 1277d |
| `automateyournetwork/netclaw` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `malek-annabi/misp-to-fortigate-ebl` | GITHUB | Zu alt: 403d |
| `GhostKellz/ghostkellz.sh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JasonLovesDoggo/caddy-defender` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2152d |
| `inversify/InversifyJS` | GITHUB | Zu alt: 256d |
| `midwayjs/midway` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `microsoft/tsyringe` | GITHUB | Zu alt: 193d |
| `anjoy8/Blog.Core` | GITHUB | Zu alt: 108d |
| `ets-labs/python-dependency-injector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `typestack/typedi` | GITHUB | Zu alt: 277d |
| `jeffijoe/awilix` | GITHUB | Zu alt: 48d |
| `oblac/jodd` | GITHUB | Zu alt: 839d |
| `w3tecch/express-typescript-boilerplate` | GITHUB | Zu alt: 1183d |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hellokaton/java-bible` | GITHUB | Zu alt: 1632d |
| `samber/do` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PHP-DI/PHP-DI` | GITHUB | Zu alt: 214d |
| `appsquickly/typhoon` | GITHUB | Zu alt: 2051d |
| `nutzam/nutz` | GITHUB | Zu alt: 278d |
| `unitycontainer/unity` | GITHUB | Zu alt: 924d |
| `gustavopsantos/Reflex` | GITHUB | Zu alt: 45d |
| `deepfence/YaraHunter` | GITHUB | Zu alt: 148d |
| `ForbiddenProgrammer/conti-pentester-guide-leak` | GITHUB | Zu alt: 1811d |
| `ClouGence/hasor` | GITHUB | Zu alt: 1327d |
| `reactiveui/splat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pedramamini/ThreatIngestor` | GITHUB | Zu alt: 68d |
| `danielpalme/IocPerformance` | GITHUB | Zu alt: 1109d |
| `ntxinh/AspNetCore-DDD` | GITHUB | Zu alt: 217d |
| `YairHalberstadt/stronginject` | GITHUB | Zu alt: 398d |
| `forrest-orr/moneta` | GITHUB | Zu alt: 869d |
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `VictorTzeng/Zxw.Framework.NetCore` | GITHUB | Zu alt: 110d |
| `exilon/QuickLib` | GITHUB | Zu alt: 86d |
| `anakic/Jot` | GITHUB | Zu alt: 296d |
| `Patrowl/PatrowlManager` | GITHUB | Zu alt: 145d |
| `golobby/container` | GITHUB | Zu alt: 339d |
| `pedramamini/iocextract` | GITHUB | Zu alt: 704d |
| `yoyofx/yoyogo` | GITHUB | Zu alt: 835d |
| `SwingFrog/Summer` | GITHUB | Zu alt: 472d |
| `ciscocsirt/GOSINT` | GITHUB | Zu alt: 1181d |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `farseer-go/fs` | GITHUB | Zu alt: 42d |
| `EcsRx/ecsrx` | GITHUB | Zu alt: 408d |
| `suites-dev/suites` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `roadwy/DefenderYara` | GITHUB | Zu alt: 80d |
| `thiagobustamante/typescript-ioc` | GITHUB | Zu alt: 752d |
| `Savory/Danet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bingcool/swoolefy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rafaelfgx/DotNetCore` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gendigitalinc/ioc` | GITHUB | Zu alt: 62d |
| `ivlevAstef/DITranquillity` | GITHUB | Zu alt: 87d |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pengweiqhca/Xunit.DependencyInjection` | GITHUB | Zu alt: 54d |
| `binghe001/BingheGuide` | GITHUB | Zu alt: 44d |
| `brianway/spring-learning` | GITHUB | Zu alt: 3625d |
| `midwayjs/midway-faas` | GITHUB | Zu alt: 2222d |
| `prodaft/malware-ioc` | GITHUB | Zu alt: 271d |
| `yinguangyao/blog` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mwemuorg/mwemu` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `urfnet/URF.Core` | GITHUB | Zu alt: 683d |
| `owja/ioc` | GITHUB | Zu alt: 698d |
| `zazoomauro/node-dependency-injection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tshemsedinov/Patterns-JavaScript` | GITHUB | Zu alt: 175d |
| `inversify/monorepo` | GITHUB | IP-Datei 282d alt |
| `d1mnewz/interviews` | GITHUB | Zu alt: 1852d |
| `eggjs/tegg` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `baidu/CarbonGraph` | GITHUB | Zu alt: 636d |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Patrowl/PatrowlEngines` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `d3fvxl/di` | GITHUB | Zu alt: 960d |
| `zheksoon/dioma` | GITHUB | Zu alt: 828d |
| `testdeck/testdeck` | GITHUB | Zu alt: 557d |
| `gnaeus/react-ioc` | GITHUB | Zu alt: 1004d |
| `mthcht/Purpleteam` | GITHUB | Zu alt: 590d |
| `intentor/adic` | GITHUB | Zu alt: 1819d |
| `urfnet/URF.NET` | GITHUB | Zu alt: 2993d |
| `Go-To-Byte/DouSheng` | GITHUB | Zu alt: 1161d |
| `hidevopsio/hiboot` | GITHUB | Zu alt: 55d |
| `dry-rb/dry-auto_inject` | GITHUB | Zu alt: 68d |
| `molszanski/iti` | GITHUB | Zu alt: 163d |
| `wzhudev/redi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `agileago/vue3-oop` | GITHUB | Zu alt: 408d |
| `assafmo/xioc` | GITHUB | Zu alt: 2296d |
| `aalex954/evilginx2-TTPs` | GITHUB | Zu alt: 473d |
| `artberri/diod` | GITHUB | Zu alt: 667d |
| `wix-incubator/obsidian` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `z4kn4fein/stashbox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Patrowl/PatrowlDocs` | GITHUB | Zu alt: 1573d |
| `microsoft/MinIoC` | GITHUB | Zu alt: 1147d |
| `Puresharper/Puresharp` | GITHUB | Zu alt: 2740d |
| `xpleemoon/XModulable` | GITHUB | Zu alt: 3102d |
| `MySixGod/SpringImpl_v2.0` | GITHUB | Zu alt: 3316d |
| `exuanbo/di-wise` | GITHUB | Zu alt: 536d |
| `TAKETODAY/today-infrastructure` | GITHUB | IP-Datei 204d alt |
| `Koatty/koatty` | GITHUB | Zu alt: 98d |
| `jbreckmckye/node-typescript-architecture` | GITHUB | Zu alt: 976d |
| `100nm/python-injection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zovajs/zova` | GITHUB | Zu alt: 50d |
| `zzzzbw/doodle` | GITHUB | Zu alt: 1507d |
| `jsuarezruiz/xamarin-forms-perf-playground` | GITHUB | Zu alt: 1333d |
| `shihabmridha/nodejs-repository-pattern-and-ioc` | GITHUB | Zu alt: 512d |
| `401trg/detections` | GITHUB | Zu alt: 1936d |
| `roo-oliv/injectable` | GITHUB | Zu alt: 332d |
| `NullArray/Mimir` | GITHUB | Zu alt: 2728d |
| `vuldb/cyber_threat_intelligence` | GITHUB | Zu alt: 78d |
| `ecomfe/uioc` | GITHUB | Zu alt: 3215d |
| `nikku/didi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mnasyrov/ditox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `typesoft/container-ioc` | GITHUB | Zu alt: 2381d |
| `ZihanType/rudi` | GITHUB | Zu alt: 579d |
| `vercube/vercube` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AsenaJs/Asena` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `scanurag/FoodFrenzy` | GITHUB | Zu alt: 228d |
| `nicolascotton/nject` | GITHUB | Zu alt: 34d |
| `CYB3RMX/MalwareHashDB` | GITHUB | Zu alt: 551d |
| `wessberg/DI-compiler` | GITHUB | Zu alt: 640d |
| `dmitryb-dev/waiter` | GITHUB | Zu alt: 901d |
| `uditalias/injex` | GITHUB | Zu alt: 285d |
| `cisagov/ioc-scanner` | GITHUB | Zu alt: 81d |
| `go-spring-rip/spring-core` | GITHUB | Zu alt: 52d |
| `bootsrc/containerx` | GITHUB | Zu alt: 2758d |
| `Rick-van-Dam/Singularity` | GITHUB | Zu alt: 2148d |
| `mbierlee/poodinis` | GITHUB | Zu alt: 206d |
| `conix-security/BTG` | GITHUB | Zu alt: 2805d |
| `go-spring-projects/go-spring` | GITHUB | Zu alt: 86d |
| `opensumi/di` | GITHUB | Zu alt: 324d |
| `absingh31/Tor_Spider` | GITHUB | Zu alt: 3083d |
| `appsquickly/pilgrim` | GITHUB | Zu alt: 1268d |
| `100cm/thunder` | GITHUB | Zu alt: 3736d |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `maou-shonen/hono-simple-DI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `di-ninja/di-ninja` | GITHUB | Zu alt: 487d |
| `parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs` | GITHUB | Zu alt: 1939d |
| `HangfireIO/Hangfire.Autofac` | GITHUB | Zu alt: 569d |
| `ChistaDev/Chista` | GITHUB | Zu alt: 806d |
| `modern-python/modern-di` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `krylosov-aa/context-async-sqlalchemy` | GITHUB | Zu alt: 49d |
| `zhulik/pal` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `INotfound/Magic` | GITHUB | Zu alt: 931d |
| `AlyElhaddad/ThunderboltIoc` | GITHUB | Zu alt: 335d |
| `enisn/DotNurseInjector` | GITHUB | Zu alt: 950d |
| `KnisterPeter/tsdi` | GITHUB | Zu alt: 979d |
| `otavia-projects/otavia` | GITHUB | Zu alt: 62d |
| `xiuqianli1996/LSFramework` | GITHUB | Zu alt: 971d |
| `tstromberg/ttp-bench` | GITHUB | Zu alt: 55d |
| `OsmanKandemir/web-wordlist-generator` | GITHUB | Zu alt: 798d |
| `phantom0004/morpheus_IOC_scanner` | GITHUB | Zu alt: 536d |
| `bdqfork/festival` | GITHUB | Zu alt: 2343d |
| `blacktop/docker-yara` | GITHUB | Zu alt: 1399d |
| `0xDanielLopez/TweetFeed_code` | GITHUB | Zu alt: 1350d |
| `inversiland/inversiland` | GITHUB | Zu alt: 591d |
| `sergeysychov/behaviour_inject` | GITHUB | Zu alt: 1050d |
| `aloisdeniel/dioc` | GITHUB | Zu alt: 2294d |
| `d3fvxl/inject` | GITHUB | Zu alt: 2357d |
| `byme8/ZeroIoC` | GITHUB | Zu alt: 439d |
| `red-gold/ts-ui` | GITHUB | Zu alt: 787d |
| `assafkip/huntkit` | GITHUB | IP-Datei 109d alt |
| `imnbwd/FriendEditor` | GITHUB | Zu alt: 3425d |
| `TheHive-Project/Zerofox2TH` | GITHUB | Zu alt: 2344d |
| `jacoborus/wiremap` | GITHUB | Zu alt: 210d |
| `wenbo2018/mini-springframework` | GITHUB | Zu alt: 3129d |
| `FarseerNet/Farseer.Net` | GITHUB | Zu alt: 1248d |
| `mjirous/cinject` | GITHUB | Zu alt: 3174d |
| `IOCoin/DIONS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ruddernation-Designs/Adobe-URL-Block-List` | GITHUB | Zu alt: 52d |
| `Stevoisiak/Stevos-AI-Blocklist` | GITHUB | Größe: 0 IPs |
| `marteinn/The-Big-Username-Blocklist` | GITHUB | Zu alt: 1754d |
| `DavidMoore/ipfilter` | GITHUB | Zu alt: 184d |
| `ipverse/as-ip-blocks` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `equk/windows` | GITHUB | Zu alt: 621d |
| `Paxxs/Google-Blocklist` | GITHUB | Zu alt: 370d |
| `gardenfence/blocklist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `samber/the-great-gpt-firewall` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `greyhat-academy/lists.d` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mhxion/pornaway` | GITHUB | Zu alt: 819d |
| `Reginald-Gillespie/Spotify-AI-Band-Blocker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `momenbasel/puresnitch` | GITHUB | Zu alt: 55d |
| `blockadeio/chrome_extension` | GITHUB | Zu alt: 2065d |
| `WaGi-Coding/WaGis-Mass-IP-Blacklister-Windows` | GITHUB | Zu alt: 820d |
| `DWW256/distracting-websites` | GITHUB | Zu alt: 141d |
| `sundowndev/phoneinfoga` | GITHUB | Zu alt: 208d |
| `qcod/laravel-gamify` | GITHUB | Zu alt: 444d |
| `sublime-security/emailrep.io` | GITHUB | Zu alt: 869d |
| `trustgraph/trustgraph` | GITHUB | Zu alt: 640d |
| `johannchopin/stackoverflow-readme-profile` | GITHUB | Zu alt: 625d |
| `ansezz/laravel-gamify` | GITHUB | Zu alt: 1909d |
| `givepraise/praise` | GITHUB | Zu alt: 657d |
| `arian-gogani/nobulex` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `interep-project/reputation-service` | GITHUB | Zu alt: 1192d |
| `rainbowdashlabs/reputation-bot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OpenNewsLabs/autoEdit_2` | GITHUB | Zu alt: 882d |
| `linux-msm/qdl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Giovix92/EDLUnlock` | GITHUB | Zu alt: 1888d |
| `thefirefox12537/qctools_tff` | GITHUB | Zu alt: 1442d |
| `strongtz/edl-ng` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Alephgsm/SAMSUNG-EDL-Loaders` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Alephgsm/SAM-unbrick-debrick` | GITHUB | Zu alt: 894d |
| `HadiKhoirudin/Qualcomm-Tool` | GITHUB | Zu alt: 909d |
| `AdaUnlocked/OnePlus-9008-JiuZhuan-Guide` | GITHUB | Zu alt: 197d |
| `tamm2904/MTFLASH_UBL_SNAPDRAGON` | GITHUB | Zu alt: 61d |
| `nil0x42/duplicut` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shramos/polymorph` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Flangvik/AMSI.fail` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gentilkiwi/mimikatz` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jserv/MazuCC` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pwnwiki/pwnwiki.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cloudflare/cloudflare-blog` | GITHUB | IP-Datei 857d alt |
| `woj-ciech/Kamerka-GUI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `13o-bbr-bbq/machine_learning_security` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `as0ler/r2flutch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Jigsaw-Code/outline-server` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `google/google-ctf` | GITHUB | IP-Datei 1392d alt |
| `NetSPI/JavaSerialKiller` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bohops/WSMan-WinRM` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `two06/Inception` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CCob/SharpBlock` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xmikos/setools-android` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RootUp/BFuzz` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `naim94a/lumen` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gelstudios/gitfiti` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ps1337/reinschauer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MicrosoftDocs/microsoft-365-docs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `geohot/qira` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ViRb3/magisk-frida` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hunters-forge/API-To-Event` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `s0lst1c3/eaphammer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `google/bochspwn-reloaded` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Anof-cyber/MobSecco` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ncsa/ssh-auditor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `IoT-PTv/IoT-PT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xyele/hackerone_wordlist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `adon90/pentest_compilation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `last-byte/HppDLL` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `davidtavarez/pwndb` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BullsEye0/ghost_eye` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `idiom/pftriage` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lawrenceamer/0xsp-Mongoose` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `70corre20matar/cppngrok` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ScarredMonk/SysmonSimulator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0xR0/shellver` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `malwarialabs/DerbyCon2019` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `iknowjason/AriaCloud` | GITHUB | IP-Datei 2216d alt |
| `nettitude/PoshC2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wetw0rk/AWAE-PREP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hasherezade/malware_training_vol1` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jaredhaight/PowerShellClassLab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hardik05/Damn_Vulnerable_C_Program` | GITHUB | IP-Datei 1116d alt |
| `stuxnet999/MemLabs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `p0dalirius/LDAPmonitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TURROKS/Maltego_WhatsMyName` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eversinc33/Banshee` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `namazso/physmem_drivers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `leechristensen/Random` | GITHUB | IP-Datei 712d alt |
| `microsoft/Windows-driver-samples` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trailofbits/sinter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jcesarstef/dotdotslash` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ganapati/RsaCtfTool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `s1egesystems/C-S1lentProcess1njector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PartialVolume/shredos.x86_64` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `leveldown-security/SVD-Loader-Ghidra` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tomnomnom/assetfinder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `copperhead/linux-hardened` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `boy-hack/hack-requests` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Porchetta-Industries/pyMalleableC2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `helviojunior/webfinder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Semmle/ql` | GITHUB | IP-Datei 254d alt |
| `aj-code/TimingIntrusionTool5000` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `x64dbg/Scripts` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fboldewin/COM-Code-Helper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `davidprowe/BadBlood` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `akacastor/oobin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `taviso/ctftool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ckane/CS7038-Malware-Analysis` | GITHUB | IP-Datei 1685d alt |
| `enkomio/shed` | GITHUB | IP-Datei 3203d alt |
| `o-o-overflow/dc2021q-a-fallen-lap-ray` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `UltimateHackers/Striker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zodiacon/WindowsInternals` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ossf/scorecard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `R0X4R/Garud` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jdu2600/Windows10EtwEvents` | GITHUB | IP-Datei 2408d alt |
| `s4n7h0/Practical-Reverse-Engineering-using-Radare2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shjalayeri/DriveCrypt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `d1vious/git-wild-hunt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trustedsec/unicorn` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ZephrFish/DockerAttack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mubix/repos` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ghostinthewires/Azure-Readiness-Checklist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eset/stadeo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mazen160/jwt-pwn` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ANSSI-FR/ADTimeline` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `cbuijs_hagezi` | GITHUB | 45,676 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 22,071 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 16,304 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 7,511 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,446 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 585 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 18,364 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 464 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 253 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 4,824 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,664 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,514 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,991 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,325 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,470 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,793 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,022 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 606 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 632 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 513 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 313 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 36,374 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 11,615 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 10,283 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 8,252 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 5,796 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,477 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 2,718 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 197,127 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,089 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 2,931 | 2.6% | 116 | 2026-07-05 |
| `breakingtechfr_proxy_free` | GITHUB | 29,347 | 0.6% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_all` | GITHUB | 32,012 | 0.5% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks4` | GITHUB | 7,200 | 1.9% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks5` | GITHUB | 5,942 | 2.2% | 55 | 2026-07-14 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,630 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 116,442 | 0.1% | 1560 | 2026-08-01 |
| `mohammedcha_proxripper` | GITHUB | 53,281 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,840 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 116,709 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 114,896 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 84,445 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,996 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 84,630 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 101,844 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,888 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 108,377 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 106,578 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 586 | 36.7% | 8 | 2026-07-03 |
| `ziyadnz_threat_intel_ip_feeds_ipv4_blacklist` | GITHUB | 106,703 | 46.2% | 8 | 2026-08-02 |
| `darzanebor_mikroblack` | GITHUB | 41,628 | 26.6% | 13 | 2026-07-05 |
| `ankaboot_source_email_open_data` | GITHUB | 491,438 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,727 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,621 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 170,645 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 140,066 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 105,263 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 87,401 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 108,839 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 83,387 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 185,139 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 48,660 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 72,214 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 29,221 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 19,859 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 33,512 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,410 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 14,913 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 13,525 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 27,518 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 12,806 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,595 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,432 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 13,009 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 7,816 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,880 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 7,067 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 5,539 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 3,010 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,317 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 4,264 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,601 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 402 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,518 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 5,654 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,545 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,651 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 47,274 | 43.0% | 10 | 2026-08-02 |
| `ian_lusule_proxies` | GITHUB | 3,252 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,649 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 865 | 17.2% | 9 | 2026-07-08 |
| `sereinfy_adrules` | GITHUB | 1,316 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 82,101 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 302,728 | 22.0% | 6 | 2026-07-08 |
| `gazpitchy92_ip_blocklist_blacklist` | GITHUB | 262,260 | 23.0% | 6 | 2026-08-02 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,277 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,479 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 5,451 | 2.6% | 7 | 2026-07-04 |
| `realizelol_torblocklist` | GITHUB | 1,562 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 39 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 62,998 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 67,446 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,048 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 110 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 197,595 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,725 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,661 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 180,721 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 23,948 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 7,516 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 2,864 | 34.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_compromised` | GITHUB | 15,563 | 65.9% | 2 | 2026-08-01 |
| `securitylist1568_fortigate` | GITHUB | 153 | 28.1% | 2 | 2026-08-02 |
| `fadouse_clash_threat_intel` | GITHUB | 8,131 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 8,500 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 170,279 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,056 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,976 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 16,508 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,287 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 48,762 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 51,722 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,451 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 111,108 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 377 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,168 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 192,314 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 109,823 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 127,662 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 31,975 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 494 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 18,842 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 16,422 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,774 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 6,883 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 3,392 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,674 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,186 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 1,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 1,681 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,117 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,078 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,090 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 448 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,858 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,832 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,407 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 554 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 528 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 528 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 992 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 449 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,100 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 487 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,461 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 694 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,279 | 6.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_maltrail_scanners` | GITHUB | 16,854 | 14.9% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_iblocklist_cruzit_web_attacks` | GITHUB | 13,871 | 0.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 5,631 | 5.0% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,127 | 24.2% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,961 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,504 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 978 | 8.1% | 0 | 2026-07-31 |
| `bitwire_it_ip_list_fetch` | GITHUB | 33,169 | 24.7% | 0 | 2026-08-01 |
| `serp07_dude_blacklist_ip` | GITHUB | 4,639 | 31.6% | 0 | 2026-08-01 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,412 | 47.9% | 0 | 2026-08-02 |

---
*Generiert: 2026-08-02 19:15 UTC*