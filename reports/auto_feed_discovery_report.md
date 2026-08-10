# Auto Feed Discovery – Report
**Aktualisiert:** 2026-08-10 20:54 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **10676** |
| davon GitHub (Topics+Code) | **10599** |
| davon GitLab | **77** |
| davon Awesome-Lists | **2199** |
| Tools/Libraries vor Eval gefiltert | **810** |
| davon Hard-Reject (awesome-Liste etc.) | **192** |
| EVAL-Kandidaten (nach Stratifizierung) | **500** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **500** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **499** |
| Neu angenommene Feed-Dateien | **6** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **189** |
| Abgelehnte Repositories (dieser Run) | **499** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **195** |
| IPs in seen_db bestätigt | **3700057** |
| Neue IPs eingetragen | **26399** |
| seen_db gesamt | **13,217,109** |
| HQ-Referenz-IPs (6 Quellen) | **121350** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **247** |
| Repo zu alt (>30d) | **208** |
| IP-Datei veraltet (>30d) | **23** |
| Falsche Größe (<30 / >2,000,000 IPs) | **21** |
| Sonstige | **2** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `claudiusdecimius_ioc_ipsets` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 108,983 | 9.4% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 14,874 | 65.2% | 0.5% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 12,763 | 64.3% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 4,113 | 2.7% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 3,655 | 5.0% | 1.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_myip` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 1,690 | 46.3% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `yasirhamza/AndroDR` | GITHUB | Größe: 0 IPs |
| `AppliedIR/Valhuntir` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DXC-0/soc-ressources` | GITHUB | Zu alt: 119d |
| `mikeroyal/Open-Source-Security-Guide` | GITHUB | Zu alt: 409d |
| `Bert-JanP/Hunting-Queries-Detection-Rules` | GITHUB | IP-Datei 1120d alt |
| `michredteam/RTbookNotes` | GITHUB | Zu alt: 771d |
| `curtislbyrd/CyberVault` | GITHUB | Zu alt: 150d |
| `saicharanamaraneni18-source/phishing-mail-incident-response` | GITHUB | Zu alt: 64d |
| `shubham7003/Security-Infrastructure-Observability-Platform` | GITHUB | Zu alt: 69d |
| `bhengubv/CircleAI` | GITHUB | Größe: 0 IPs |
| `bitjbullock/SysAdmin` | GITHUB | Zu alt: 83d |
| `servo/servo` | GITHUB | Größe: 0 IPs |
| `ankitkumarsh39-sys/email-analyzer-soc-tool` | GITHUB | IP-Datei 80d alt |
| `yuntianze/dmp` | GITHUB | Zu alt: 342d |
| `brojangles24/BlocklistAggregate` | GITHUB | Größe: 0 IPs |
| `paulrouget/servo-embedding-example` | GITHUB | Zu alt: 3073d |
| `de-otio/agent-safety-pack` | GITHUB | Zu alt: 41d |
| `fabricedesre/servonk` | GITHUB | Zu alt: 2860d |
| `WebBluetoothCG/registries` | GITHUB | Zu alt: 1091d |
| `shizukutanaka/Muten` | GITHUB | Größe: 0 IPs |
| `humaidq/dotfiles` | GITHUB | Größe: 0 IPs |
| `allenai/dolma` | GITHUB | Zu alt: 278d |
| `jesuslopezreynosa/useful-scripts` | GITHUB | IP-Datei 638d alt |
| `seia-soto/dns` | GITHUB | Zu alt: 845d |
| `kakarot-dev/dnsink` | GITHUB | Zu alt: 97d |
| `1Jamie/project-lotus` | GITHUB | Zu alt: 43d |
| `matiaselebi/Secure-DNS` | GITHUB | Größe: 0 IPs |
| `mxmgorin/retsurf` | GITHUB | IP-Datei 331d alt |
| `RaulZarnescu/Intrusion-Prevention-System` | GITHUB | Größe: 0 IPs |
| `fx-dev-playground/gecko` | GITHUB | Zu alt: 1307d |
| `chaitanyaBytes/Slipstream` | GITHUB | Zu alt: 71d |
| `paulrouget/servofocus` | GITHUB | Zu alt: 3165d |
| `jschwe/ServoDemo` | GITHUB | Zu alt: 32d |
| `sagittaurius/malware-list-filter-compiler` | GITHUB | IP-Datei 71d alt |
| `paulrouget/hnbrowser` | GITHUB | Zu alt: 3331d |
| `jialunzhang-psu/SandCell-Artifact` | GITHUB | Zu alt: 207d |
| `ryanyxw/llm-decouple` | GITHUB | Zu alt: 319d |
| `rouxlmoven/servo` | GITHUB | IP-Datei 39d alt |
| `anthonyniqmm/servo` | GITHUB | IP-Datei 39d alt |
| `arwunmarona/servo` | GITHUB | IP-Datei 39d alt |
| `webbeef/webviewer` | GITHUB | Zu alt: 724d |
| `justinmichaud/ion` | GITHUB | Zu alt: 2850d |
| `moto-browser/moto` | GITHUB | Zu alt: 472d |
| `securesystemslab/pkru-safe-servo` | GITHUB | Zu alt: 1378d |
| `fschutt/servo_gui_test` | GITHUB | Zu alt: 3240d |
| `Baconana-chan/ferro-browser` | GITHUB | Zu alt: 41d |
| `paulrouget/libsimpleservo` | GITHUB | Zu alt: 3233d |
| `karad/my-servo-embedding-example` | GITHUB | Zu alt: 2595d |
| `OwnedByWuigi/dactylic` | GITHUB | Zu alt: 68d |
| `galadran/tor-browser` | GITHUB | Zu alt: 2571d |
| `Anima-OS/Quokka` | GITHUB | Zu alt: 1322d |
| `kinetiknz/gecko` | GITHUB | Zu alt: 2385d |
| `BenEgeIzmirli/mozilla_central_in_c` | GITHUB | Zu alt: 1322d |
| `jsorg71/waterfox_classic_releases` | GITHUB | Zu alt: 1322d |
| `youssefbouaouina/dfir-threat-hunting-framework` | GITHUB | Größe: 0 IPs |
| `Nikhil-H-N/CIDECODE` | GITHUB | Zu alt: 76d |
| `nauman-nomi/Firewall-FrontEnd` | GITHUB | Zu alt: 324d |
| `CuriousMrBear/My-EDL` | GITHUB | Zu alt: 658d |
| `initconf/misp_intel` | GITHUB | Zu alt: 166d |
| `DAYceng/elk4spark` | GITHUB | Zu alt: 1130d |
| `wuguobeijing/StratosphereLinuxIPS-dev` | GITHUB | Zu alt: 1161d |
| `first20hours/google-10000-english` | GITHUB | Zu alt: 1181d |
| `daviddao/awful-ai` | GITHUB | Zu alt: 536d |
| `nv-tlabs/SCube` | GITHUB | Zu alt: 300d |
| `PKU-Alignment/safe-rlhf` | GITHUB | Zu alt: 259d |
| `punishell/bbtips` | GITHUB | Zu alt: 375d |
| `TheAlanNix/cisco-security-tools` | GITHUB | Zu alt: 1341d |
| `sbhooley/ainativelang` | GITHUB | Zu alt: 46d |
| `hyunjun/bookmarks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yitu-opensource/ConvBert` | GITHUB | Zu alt: 1406d |
| `temm1e-labs/temm1e` | GITHUB | Zu alt: 37d |
| `LycheeMem/LycheeMem` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tmgthb/Autonomous-Agents` | GITHUB | Zu alt: 47d |
| `MontrealAI/AGI-Alpha-Agent-v0` | GITHUB | Zu alt: 102d |
| `FlagOpen/FlagData` | GITHUB | Zu alt: 788d |
| `mikeroyal/Parrot-Security-Guide` | GITHUB | Zu alt: 1826d |
| `Abhinavbwj/Claude-skills-for-Computational-Designers` | GITHUB | Zu alt: 137d |
| `guy032/InfraQuery` | GITHUB | Zu alt: 279d |
| `mikeroyal/Fedora-Guide` | GITHUB | Zu alt: 949d |
| `claude-did-this/claude-hub` | GITHUB | Zu alt: 287d |
| `noctiro/stormin` | GITHUB | Zu alt: 92d |
| `mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites` | GITHUB | Zu alt: 1029d |
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2160d |
| `inversify/InversifyJS` | GITHUB | Zu alt: 264d |
| `midwayjs/midway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anjoy8/Blog.Core` | GITHUB | Zu alt: 116d |
| `ets-labs/python-dependency-injector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typestack/typedi` | GITHUB | Zu alt: 285d |
| `jeffijoe/awilix` | GITHUB | Zu alt: 56d |
| `oblac/jodd` | GITHUB | Zu alt: 847d |
| `w3tecch/express-typescript-boilerplate` | GITHUB | Zu alt: 1191d |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellokaton/java-bible` | GITHUB | Zu alt: 1640d |
| `samber/do` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PHP-DI/PHP-DI` | GITHUB | Zu alt: 222d |
| `appsquickly/typhoon` | GITHUB | Zu alt: 2059d |
| `nutzam/nutz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `unitycontainer/unity` | GITHUB | Zu alt: 932d |
| `gustavopsantos/Reflex` | GITHUB | Zu alt: 53d |
| `ClouGence/hasor` | GITHUB | Zu alt: 1335d |
| `reactiveui/splat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `danielpalme/IocPerformance` | GITHUB | Zu alt: 1117d |
| `ntxinh/AspNetCore-DDD` | GITHUB | Zu alt: 225d |
| `YairHalberstadt/stronginject` | GITHUB | Zu alt: 406d |
| `forrest-orr/moneta` | GITHUB | Zu alt: 877d |
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VictorTzeng/Zxw.Framework.NetCore` | GITHUB | Zu alt: 118d |
| `exilon/QuickLib` | GITHUB | Zu alt: 94d |
| `anakic/Jot` | GITHUB | Zu alt: 304d |
| `golobby/container` | GITHUB | Zu alt: 347d |
| `yoyofx/yoyogo` | GITHUB | Zu alt: 843d |
| `SwingFrog/Summer` | GITHUB | Zu alt: 480d |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `farseer-go/fs` | GITHUB | Zu alt: 50d |
| `suites-dev/suites` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EcsRx/ecsrx` | GITHUB | Zu alt: 416d |
| `roadwy/DefenderYara` | GITHUB | Zu alt: 88d |
| `thiagobustamante/typescript-ioc` | GITHUB | Zu alt: 760d |
| `Savory/Danet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bingcool/swoolefy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafaelfgx/DotNetCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gendigitalinc/ioc` | GITHUB | Zu alt: 70d |
| `ivlevAstef/DITranquillity` | GITHUB | Zu alt: 95d |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pengweiqhca/Xunit.DependencyInjection` | GITHUB | Zu alt: 62d |
| `binghe001/BingheGuide` | GITHUB | Zu alt: 52d |
| `brianway/spring-learning` | GITHUB | Zu alt: 3633d |
| `midwayjs/midway-faas` | GITHUB | Zu alt: 2230d |
| `yinguangyao/blog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `prodaft/malware-ioc` | GITHUB | Zu alt: 279d |
| `mwemuorg/mwemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `urfnet/URF.Core` | GITHUB | Zu alt: 691d |
| `owja/ioc` | GITHUB | Zu alt: 706d |
| `zazoomauro/node-dependency-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tshemsedinov/Patterns-JavaScript` | GITHUB | Zu alt: 183d |
| `inversify/monorepo` | GITHUB | IP-Datei 290d alt |
| `d1mnewz/interviews` | GITHUB | Zu alt: 1860d |
| `eggjs/tegg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ditekshen/detection` | GITHUB | Zu alt: 647d |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `d3fvxl/di` | GITHUB | Zu alt: 968d |
| `zheksoon/dioma` | GITHUB | Zu alt: 836d |
| `testdeck/testdeck` | GITHUB | Zu alt: 565d |
| `gnaeus/react-ioc` | GITHUB | Zu alt: 1012d |
| `intentor/adic` | GITHUB | Zu alt: 1827d |
| `urfnet/URF.NET` | GITHUB | Zu alt: 3001d |
| `Go-To-Byte/DouSheng` | GITHUB | Zu alt: 1169d |
| `hidevopsio/hiboot` | GITHUB | Zu alt: 63d |
| `dry-rb/dry-auto_inject` | GITHUB | Zu alt: 76d |
| `molszanski/iti` | GITHUB | Zu alt: 171d |
| `wzhudev/redi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `agileago/vue3-oop` | GITHUB | Zu alt: 416d |
| `aalex954/evilginx2-TTPs` | GITHUB | Zu alt: 481d |
| `assafmo/xioc` | GITHUB | Zu alt: 2304d |
| `artberri/diod` | GITHUB | Zu alt: 675d |
| `wix-incubator/obsidian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `z4kn4fein/stashbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Puresharper/Puresharp` | GITHUB | Zu alt: 2748d |
| `xpleemoon/XModulable` | GITHUB | Zu alt: 3110d |
| `MySixGod/SpringImpl_v2.0` | GITHUB | Zu alt: 3324d |
| `exuanbo/di-wise` | GITHUB | Zu alt: 544d |
| `TAKETODAY/today-infrastructure` | GITHUB | IP-Datei 212d alt |
| `Koatty/koatty` | GITHUB | Zu alt: 106d |
| `100nm/python-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbreckmckye/node-typescript-architecture` | GITHUB | Zu alt: 984d |
| `zovajs/zova` | GITHUB | Zu alt: 58d |
| `zzzzbw/doodle` | GITHUB | Zu alt: 1515d |
| `jsuarezruiz/xamarin-forms-perf-playground` | GITHUB | Zu alt: 1341d |
| `shihabmridha/nodejs-repository-pattern-and-ioc` | GITHUB | Zu alt: 520d |
| `401trg/detections` | GITHUB | Zu alt: 1944d |
| `roo-oliv/injectable` | GITHUB | Zu alt: 340d |
| `NullArray/Mimir` | GITHUB | Zu alt: 2736d |
| `ecomfe/uioc` | GITHUB | Zu alt: 3223d |
| `nikku/didi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mnasyrov/ditox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typesoft/container-ioc` | GITHUB | Zu alt: 2389d |
| `ZihanType/rudi` | GITHUB | Zu alt: 587d |
| `AsenaJs/Asena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vercube/vercube` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `scanurag/FoodFrenzy` | GITHUB | Zu alt: 236d |
| `nicolascotton/nject` | GITHUB | Zu alt: 42d |
| `wessberg/DI-compiler` | GITHUB | Zu alt: 648d |
| `dmitryb-dev/waiter` | GITHUB | Zu alt: 909d |
| `uditalias/injex` | GITHUB | Zu alt: 293d |
| `go-spring-rip/spring-core` | GITHUB | Zu alt: 60d |
| `bootsrc/containerx` | GITHUB | Zu alt: 2766d |
| `Rick-van-Dam/Singularity` | GITHUB | Zu alt: 2156d |
| `mbierlee/poodinis` | GITHUB | Zu alt: 214d |
| `conix-security/BTG` | GITHUB | Zu alt: 2813d |
| `go-spring-projects/go-spring` | GITHUB | Zu alt: 94d |
| `opensumi/di` | GITHUB | Zu alt: 332d |
| `absingh31/Tor_Spider` | GITHUB | Zu alt: 3091d |
| `appsquickly/pilgrim` | GITHUB | Zu alt: 1276d |
| `100cm/thunder` | GITHUB | Zu alt: 3744d |
| `PereViader/ManualDi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maou-shonen/hono-simple-DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `di-ninja/di-ninja` | GITHUB | Zu alt: 495d |
| `parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs` | GITHUB | Zu alt: 1947d |
| `HangfireIO/Hangfire.Autofac` | GITHUB | Zu alt: 577d |
| `ChistaDev/Chista` | GITHUB | Zu alt: 814d |
| `modern-python/modern-di` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `krylosov-aa/context-async-sqlalchemy` | GITHUB | Zu alt: 57d |
| `INotfound/Magic` | GITHUB | Zu alt: 939d |
| `zhulik/pal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlyElhaddad/ThunderboltIoc` | GITHUB | Zu alt: 343d |
| `enisn/DotNurseInjector` | GITHUB | Zu alt: 958d |
| `otavia-projects/otavia` | GITHUB | Zu alt: 70d |
| `KnisterPeter/tsdi` | GITHUB | Zu alt: 987d |
| `xiuqianli1996/LSFramework` | GITHUB | Zu alt: 979d |
| `tstromberg/ttp-bench` | GITHUB | Zu alt: 63d |
| `phantom0004/morpheus_IOC_scanner` | GITHUB | Zu alt: 544d |
| `OsmanKandemir/web-wordlist-generator` | GITHUB | Zu alt: 806d |
| `bdqfork/festival` | GITHUB | Zu alt: 2351d |
| `blacktop/docker-yara` | GITHUB | Zu alt: 1407d |
| `0xDanielLopez/TweetFeed_code` | GITHUB | Zu alt: 1358d |
| `inversiland/inversiland` | GITHUB | Zu alt: 599d |
| `sergeysychov/behaviour_inject` | GITHUB | Zu alt: 1058d |
| `aloisdeniel/dioc` | GITHUB | Zu alt: 2302d |
| `d3fvxl/inject` | GITHUB | Zu alt: 2365d |
| `byme8/ZeroIoC` | GITHUB | Zu alt: 447d |
| `assafkip/huntkit` | GITHUB | Zu alt: 35d |
| `red-gold/ts-ui` | GITHUB | Zu alt: 795d |
| `jacoborus/wiremap` | GITHUB | Zu alt: 218d |
| `imnbwd/FriendEditor` | GITHUB | Zu alt: 3433d |
| `wenbo2018/mini-springframework` | GITHUB | Zu alt: 3137d |
| `FarseerNet/Farseer.Net` | GITHUB | Zu alt: 1256d |
| `mjirous/cinject` | GITHUB | Zu alt: 3182d |
| `Ruddernation-Designs/Adobe-URL-Block-List` | GITHUB | Zu alt: 60d |
| `Stevoisiak/Stevos-AI-Blocklist` | GITHUB | Größe: 0 IPs |
| `marteinn/The-Big-Username-Blocklist` | GITHUB | Zu alt: 1762d |
| `DavidMoore/ipfilter` | GITHUB | Zu alt: 192d |
| `ipverse/as-ip-blocks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `equk/windows` | GITHUB | Zu alt: 629d |
| `djkurlander/knock-knock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qundao/mirror-softcnkiller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gardenfence/blocklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Paxxs/Google-Blocklist` | GITHUB | Zu alt: 378d |
| `GroundBarberMend/adaway-studio-boost` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `samber/the-great-gpt-firewall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `greyhat-academy/lists.d` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mhxion/pornaway` | GITHUB | Zu alt: 827d |
| `Reginald-Gillespie/Spotify-AI-Band-Blocker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blockadeio/chrome_extension` | GITHUB | Zu alt: 2073d |
| `WaGi-Coding/WaGis-Mass-IP-Blacklister-Windows` | GITHUB | Zu alt: 828d |
| `DWW256/distracting-websites` | GITHUB | Zu alt: 149d |
| `qcod/laravel-gamify` | GITHUB | Zu alt: 452d |
| `trustgraph/trustgraph` | GITHUB | Zu alt: 648d |
| `johannchopin/stackoverflow-readme-profile` | GITHUB | Zu alt: 633d |
| `ansezz/laravel-gamify` | GITHUB | Zu alt: 1917d |
| `e-m3din4/deep-email` | GITHUB | Zu alt: 1237d |
| `givepraise/praise` | GITHUB | Zu alt: 665d |
| `arian-gogani/nobulex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `interep-project/reputation-service` | GITHUB | Zu alt: 1200d |
| `rainbowdashlabs/reputation-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenNewsLabs/autoEdit_2` | GITHUB | Zu alt: 890d |
| `linux-msm/qdl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Giovix92/EDLUnlock` | GITHUB | Zu alt: 1896d |
| `thefirefox12537/qctools_tff` | GITHUB | Zu alt: 1450d |
| `strongtz/edl-ng` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alephgsm/SAMSUNG-EDL-Loaders` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alephgsm/SAM-unbrick-debrick` | GITHUB | Zu alt: 902d |
| `HadiKhoirudin/Qualcomm-Tool` | GITHUB | Zu alt: 917d |
| `AdaUnlocked/OnePlus-9008-JiuZhuan-Guide` | GITHUB | Zu alt: 205d |
| `tamm2904/MTFLASH_UBL_SNAPDRAGON` | GITHUB | Zu alt: 69d |
| `HadiKhoirudin/Qualcomm-Tool-GUI` | GITHUB | Zu alt: 1342d |
| `Red5d/edlkit` | GITHUB | Zu alt: 897d |
| `Mrivai/Xiaomi-Service-Tool` | GITHUB | Zu alt: 1422d |
| `CosmicDan-Android/MiA1LowLevelBackupRestoreTool` | GITHUB | Zu alt: 1620d |
| `yuriskinfo/cheat-sheets` | GITHUB | Zu alt: 43d |
| `prometheus-community/fortigate_exporter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheTaylorLee/AdminToolbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yuriskinfo/Fortinet-tools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FortiPower/PowerFGT` | GITHUB | Zu alt: 222d |
| `fortinet/fortigate-terraform-deploy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fortinet-solutions-cse/fortiosapi` | GITHUB | Zu alt: 1270d |
| `mbdraks/fortinet-zabbix` | GITHUB | Zu alt: 1510d |
| `fortinet/4D-Demo` | GITHUB | Zu alt: 31d |
| `fortinet-solutions-cse/40ansible` | GITHUB | Zu alt: 2368d |
| `40net-cloud/fortinet-azure-solutions` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sbousseaden/Panache_Sysmon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dhondta/dronesploit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alexey-T/CudaText` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `angea/pocorgtfo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CBHue/PyFuscation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `whickey-r7/grab_beacon_config` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aptnotes/tools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `V33RU/IoTSecurity101` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gtworek/PSBits` | GITHUB | IP-Datei 586d alt |
| `carlospolop/legion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `newsoft/envoye-special-decryptor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lmacken/pyrasite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MISP/MISP-sizer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hamid-K/bookmarks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheBinitGhimire/NtHiM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `theori-io/zer0con2018_singi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evilsocket/quijote` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sailay1996/offsec_WE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `liamg/tfsec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `splunk/SA-ctf_scoreboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Microsoft/MSRC-Security-Research` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `REhints/Publications` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salesforce/DazedAndConfused` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `epinna/weevely3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `opnsense/core` | GITHUB | Größe: 0 IPs |
| `thelinuxchoice/shellphish` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hasherezade/dll_to_exe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `federicodotta/ghidra-scripts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `P0cL4bs/wifipumpkin3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tokyoneon/Armor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CboeSecurity/password_pwncheck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carbonblack/carbon-black-cloud-sdk-python` | GITHUB | IP-Datei 143d alt |
| `nakov/practical-cryptography-for-developers-book` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GluuFederation/oxAuth` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/upvote` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shadowban-eu/shadowban-eu-frontend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `srsLTE/srsLTE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JPCERTCC/ToolAnalysisResultSheet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manoelt/50M_CTF_Writeup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre/attack-navigator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `airbus-seclab/qemu_blog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gdedrouas/Exchange-AD-Privesc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `herrfeder/PandocPentestReport` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fuzzitdev/javafuzz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CoatiSoftware/Sourcetrail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `P1sec/QCSuper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microsoft/DefendTheFlag` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deepinstinct/Lsass-Shtinkering` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mdsecactivebreach/Chameleon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hackplayers/evil-winrm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hasherezade/pe-bear-releases` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BankSecurity/Red_Team` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cisagov/cset` | GITHUB | IP-Datei 865d alt |
| `Netflix/security_monkey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `projectdiscovery/nuclei-templates` | GITHUB | IP-Datei 617d alt |
| `so87/CISSP-Study-Guide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/sanitizers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CaliDog/certstream-server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GouveaHeitor/nipe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `weibell/reverse-shell-generator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `StefanoDeVuono/steghide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `leonjza/tc2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `payloadbox/open-redirect-payload-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `projectsend/projectsend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schollz/find3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CravateRouge/bloodyAD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mullender/python-ntlm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `epi052/OSCE-exam-practice` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MISP/PyMISP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cea-sec/ivre` | GITHUB | IP-Datei 334d alt |
| `AFLplusplus/AFLplusplus` | GITHUB | IP-Datei 427d alt |
| `ehrishirajsharma/SwiftnessX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `infobyte/spoilerwall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `robinhouston/image-unshredding` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenEx-Platform/openex` | GITHUB | IP-Datei 271d alt |
| `D4-project/d4-core` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `denandz/GLORP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `googleprojectzero/symboliclink-testing-tools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `raandree/ManagedPasswordFilter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `infodox/python-pty-shells` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `phackt/stager.dll` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LOLBAS-Project/LOLBAS` | GITHUB | Größe: 0 IPs |
| `ICIJ/datashare` | GITHUB | IP-Datei 2491d alt |
| `abelcheung/rifiuti2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rapid7/metasploitable3` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `snovvcrash/DInjector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ionescu007/r0ak` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CiscoPSIRT/openVulnQuery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `helix-editor/helix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schollz/howmanypeoplearearound` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeremylong/DependencyCheck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `opsxcq/debugger-netwalker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iangcarroll/cookiemonster` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `danluu/post-mortems` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `usnistgov/NFIQ2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blacknbunny/mcreator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Voorivex/pentest-guide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zricethezav/gitleaks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CIRCL/AIL-framework` | GITHUB | IP-Datei 563d alt |
| `Siguza/v0rtex` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fouroctets/Android-Malware-Samples` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gdbinit/evilquest_deobfuscator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `savon-noir/python-libnessus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TryCatchHCF/Cloakify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERTCC-Vulnerability-Analysis/trommel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Microsoft/checkedc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `j00ru/ctf-tasks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MalwareTech/Beginner-Reversing-Challenges` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nshalabi/ATTACK-Tools` | GITHUB | IP-Datei 833d alt |
| `D00MFist/Mystikal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lazenca/Kernel-exploit-tech` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jonathandata1/pegasus_spyware_detection_utils_ios_aos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0ffffffffh/dragondance` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `orlikoski/Skadi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fr0gger/yeti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sysdevploit/put2win` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trimstray/the-book-of-secret-knowledge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `silence-is-best/files` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FrenchYeti/dexcalibur` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThunderGunExpress/BADministration` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ClaudiusDecimius/ioc-ipsets` | GITHUB | Identischer Inhalt wie kraloveckey_ipsets_blocklist_tor_exits |
| `ClaudiusDecimius/ioc-ipsets` | GITHUB | Identischer Inhalt wie kraloveckey_ipsets_blocklist_sblam |
| `Hasi-7/JARVIS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Railly/vcut` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SaltyCarl/socdesk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `git-alves/TCFHelper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jlbisconti2026/jorsat` | GITHUB | IP-Datei 414d alt |
| `esgrindley/landingpage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EduardoChapeco/jah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yagogouvea/dj-maxx-rs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `domcabral9/morpheus-beta` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `espechtsoftware/nfl-predictions` | GITHUB | Größe: 0 IPs |
| `nikita-petrich/project-pilot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sarmista-sami/quickapply` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elanthus/news-briefing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MikeyPetrillo/Agent402` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tannerbroberts/OST-Agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `netvarec/pramen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cruizvargas/eclipse-timer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tylerrosnett/homelab` | GITHUB | Größe: 0 IPs |
| `iamakbarsha1/loadout` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cibstan1999/NBA-Quick-News-2.0` | GITHUB | Größe: 0 IPs |
| `YesterdaysLemon/open-graph-theory-with-prize` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sandy26-spec/GlassWire-Elite-3.3.678-Toolset` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mohanish7777777/TI_Feed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `leizongmin/ZeroWeb` | GITHUB | IP-Datei 63d alt |
| `Dicklesworthstone/eidetic_engine_cli` | GITHUB | IP-Datei 56d alt |
| `flaxnaz/orbital-sentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `umputun/agterm` | GITHUB | Größe: 0 IPs |
| `tokencanopy/e2a` | GITHUB | Größe: 0 IPs |
| `zeuu5/cyber-threat-hub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LEDGRAGENT/aeon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `raabelo/st-addons` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hannosirkel/plepic` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gustavx404/homelab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `constantineedie26-star/The-Planet-s-Prestige-Phishing-Email-Investigation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AmberKittyPublic/Retina` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sajhilodigital/SajiloRestro-PublicPage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rustok-org/mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Oldfartguy/Blocklist_minimal_Serverless-DNS-gateway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ailtonmacedo/gosvc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cfm-miku-en/arp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `averray-agent/agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Rakantor/wow-leave-me-be` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Pupok462/claude-afk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Gensiphone/team9960-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kyawzawaungdevops/payflow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blackoutsecure/bos-automation-hub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `barrygee/Sentry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AlexandreBuen0/StaticWebSite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `platform-base-images/hardened-base` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `miikkij/aimeat-protocol` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stuartjash/macos-malware-kb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `batakers/Niuva` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bsnwgit/pktnode` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bsnwgit/pktsnmp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arunkuttysend/arunkuttysend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DFKHelper/token-goat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hamlettus/trend-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swapnil-agrim/loopsmith` | GITHUB | Größe: 0 IPs |
| `Arkacaraka123/cylance-antivirus-client-bypass` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yashjha024/my-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betianaox/imagostack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Arnold3457/stealth-input-log-v8-5-41` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lucasjustinudin/Free-HighQuality-Proxy-Socks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kkfrlwebdev-wq/resume` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `laypatel13/clutch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mkdahan/globegram-osint-terminal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ayro-CMD/FrostSeek` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alizainpk/indusbridgetrading-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kayaman/bancada` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atomdrift-project/isomer-action` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maximuml/tracker-lp-bits` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fernando143/cashea-challenge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SanazYazdanjoo/IBS_FKTN` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `threebeat/open-source-think-tank` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eoghan2t9/Irongrid-DNS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `relayium/relayium` | GITHUB | Größe: 0 IPs |
| `rikterskale/NetworkForgeAI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dawsonblock/Aaron` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Muhammad-Sajid-Rajput/ThermaX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PANTH2517/PANTH2517` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nightswatchhq/nuthatch` | GITHUB | Größe: 0 IPs |
| `btheis15/mlr-app` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `calobhoy/solana-sniper-bot-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Balty1991/BETPREDICT` | GITHUB | Größe: 0 IPs |
| `V1PEX7/nixos-config` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Reethikaa05/portfolio-sage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mcconnellentllc-cloud/F-HGolf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aditya1v/LedgerCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Spruill-1/DiskClone` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `playstructs/structs-desktop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `scottnathanbvd1897/apex-branding-design-pages` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mittelsdorfkjell01-sys/surfwinddata` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kkrishnaac/sip-and-scholar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skvdhshuk-blip/hao-code` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PrakharChand/Codenest` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AmeerHassouna/ScamRadar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beamgumshoepath/legendary-dota2-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `digifirst-org/egress-rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sakusultan21/time-boss-338001-setup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `cbuijs_hagezi` | GITHUB | 56,883 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 21,392 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 16,047 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 7,911 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,902 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 554 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 18,364 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 464 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 253 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,226 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,884 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,852 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 2,184 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,924 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,671 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,435 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,361 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 745 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 684 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 542 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 282 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 45,299 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 19,772 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 18,660 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,124 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,591 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,574 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 2,864 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 202,936 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,276 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,227 | 2.6% | 116 | 2026-07-05 |
| `breakingtechfr_proxy_free` | GITHUB | 43,636 | 0.6% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_all` | GITHUB | 46,647 | 0.5% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks4` | GITHUB | 16,351 | 1.9% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks5` | GITHUB | 15,547 | 2.2% | 55 | 2026-07-14 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,631 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 118,418 | 0.1% | 1560 | 2026-08-01 |
| `hookzof_socks5_list` | GITHUB | 156 | 22.1% | 1030 | 2026-08-04 |
| `mohammedcha_proxripper` | GITHUB | 53,584 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,871 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,664 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,336 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 91,880 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,559 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,199 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 102,491 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,534 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 88,236 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,184 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 102,874 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 555 | 36.7% | 8 | 2026-07-03 |
| `darzanebor_mikroblack` | GITHUB | 41,628 | 26.6% | 13 | 2026-07-05 |
| `ankaboot_source_email_open_data` | GITHUB | 488,467 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,787 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,992 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 172,556 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 139,991 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 109,344 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 89,002 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 119,760 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 85,219 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 195,129 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 51,952 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 95,779 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 28,695 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 19,835 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,310 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 14,569 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 12,930 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 32,230 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 14,417 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,632 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,953 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 14,086 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 8,290 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,392 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 7,514 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 5,771 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,246 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,845 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 4,244 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,642 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 2,390 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,185 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 3,022 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,794 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 5,346 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 40,286 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,378 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,007 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 51,266 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,341 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,245 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,539 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 865 | 17.2% | 9 | 2026-07-08 |
| `sereinfy_adrules` | GITHUB | 1,365 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 82,369 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 252,125 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 5,503 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 4,589 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 5,657 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,561 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 19 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 68,074 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 74,595 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,133 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 103 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 204,690 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,547 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,683 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 183,060 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 24,514 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 7,560 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 2,618 | 34.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_compromised` | GITHUB | 15,527 | 65.9% | 2 | 2026-08-01 |
| `securitylist1568_fortigate` | GITHUB | 133 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 9,652 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 9,653 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n3` | GITHUB | 9,649 | 76.5% | 3 | 2026-08-09 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,055 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 16,115 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 16,308 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,294 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 50,101 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 53,245 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,440 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 114,628 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 489 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,170 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 192,944 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 113,228 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 131,606 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,106 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,240 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 33,395 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 19,511 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 16,782 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,774 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 6,781 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 5,786 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,674 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,506 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 3,000 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 2,852 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,117 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,526 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 1,947 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,539 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 2,818 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,930 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,775 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,393 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 915 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 867 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 884 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 923 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 734 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,712 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 703 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,458 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 733 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,279 | 6.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_maltrail_scanners` | GITHUB | 16,854 | 14.9% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_iblocklist_cruzit_web_attacks` | GITHUB | 13,871 | 0.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 5,631 | 5.0% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,127 | 24.2% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,440 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,535 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,210 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 11,472 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,001 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 90,885 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 90,340 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 89,849 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 91,148 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 89,310 | 1.4% | 0 | 2026-08-09 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,413 | 50.6% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 87,269 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,746 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 39,818 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 109 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets` | GITHUB | 108,983 | 9.4% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 14,874 | 65.2% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 12,763 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 4,113 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,655 | 5.0% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,690 | 46.3% | 0 | 2026-08-10 |

---
*Generiert: 2026-08-10 20:54 CEST (Europe/Berlin)*