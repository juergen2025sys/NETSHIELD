# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-31 19:19 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **4963** |
| davon GitHub (Topics+Code) | **4893** |
| davon GitLab | **70** |
| davon Awesome-Lists | **1021** |
| Tools/Libraries vor Eval gefiltert | **291** |
| davon Hard-Reject (awesome-Liste etc.) | **120** |
| EVAL-Kandidaten (nach Stratifizierung) | **300** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **300** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **299** |
| Neu angenommene Feed-Dateien | **6** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **157** |
| Abgelehnte Repositories (dieser Run) | **299** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **163** |
| IPs in seen_db bestätigt | **2580178** |
| Neue IPs eingetragen | **425343** |
| seen_db gesamt | **12,621,065** |
| HQ-Referenz-IPs (6 Quellen) | **108693** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Repo zu alt (>30d) | **205** |
| Keine IP-Datei im Repo | **44** |
| IP-Datei veraltet (>30d) | **34** |
| Overlap mit HQ-Feeds zu gering (<20%) | **12** |
| Falsche Größe (<100 / >2,000,000 IPs) | **4** |
| Sonstige | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 2,428 | 4.9% | 0.5% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,462 | 46.7% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,208 | 8.1% | 0.0% | 0 | 🆕 NEU |
| `configserverapps_service_blocklists_blocklist` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 44,202 | 38.5% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_http_1d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 28,577 | 5.1% | 1.5% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_greylist` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 7,304 | 78.1% | 0.0% | 10 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `mthcht/ThreatHunting-Keywords` | GITHUB | Zu alt: 361d |
| `citizenlab/malware-indicators` | GITHUB | Zu alt: 2126d |
| `decal/werdlists` | GITHUB | Zu alt: 999d |
| `michredteam/RTbookNotes` | GITHUB | Zu alt: 999d |
| `curtislbyrd/CyberVault` | GITHUB | Zu alt: 999d |
| `saicharanamaraneni18-source/phishing-mail-incident-response` | GITHUB | Zu alt: 999d |
| `shubham7003/Security-Infrastructure-Observability-Platform` | GITHUB | Zu alt: 999d |
| `bhengubv/CircleAI` | GITHUB | Zu alt: 999d |
| `bitjbullock/SysAdmin` | GITHUB | Zu alt: 999d |
| `servo/servo` | GITHUB | Zu alt: 999d |
| `ankitkumarsh39-sys/email-analyzer-soc-tool` | GITHUB | Zu alt: 999d |
| `Sereinfy/Adrules` | GITHUB | Zu alt: 999d |
| `yuntianze/dmp` | GITHUB | Zu alt: 999d |
| `paulrouget/servo-embedding-example` | GITHUB | Zu alt: 999d |
| `de-otio/agent-safety-pack` | GITHUB | Zu alt: 999d |
| `fabricedesre/servonk` | GITHUB | Zu alt: 999d |
| `WebBluetoothCG/registries` | GITHUB | Zu alt: 999d |
| `humaidq/dotfiles` | GITHUB | Zu alt: 999d |
| `shizukutanaka/Muten` | GITHUB | Zu alt: 999d |
| `allenai/dolma` | GITHUB | Zu alt: 999d |
| `jesuslopezreynosa/useful-scripts` | GITHUB | Zu alt: 999d |
| `seia-soto/dns` | GITHUB | Zu alt: 999d |
| `kakarot-dev/dnsink` | GITHUB | Zu alt: 999d |
| `1Jamie/project-lotus` | GITHUB | Zu alt: 999d |
| `mxmgorin/retsurf` | GITHUB | Zu alt: 999d |
| `yasirhamza/AndroDR` | GITHUB | Zu alt: 999d |
| `matiaselebi/Secure-DNS` | GITHUB | Zu alt: 999d |
| `fx-dev-playground/gecko` | GITHUB | Zu alt: 999d |
| `chaitanyaBytes/Slipstream` | GITHUB | Zu alt: 999d |
| `paulrouget/servofocus` | GITHUB | Zu alt: 999d |
| `jschwe/ServoDemo` | GITHUB | Zu alt: 999d |
| `sagittaurius/malware-list-filter-compiler` | GITHUB | Zu alt: 999d |
| `paulrouget/hnbrowser` | GITHUB | Zu alt: 999d |
| `jialunzhang-psu/SandCell-Artifact` | GITHUB | Zu alt: 999d |
| `ryanyxw/llm-decouple` | GITHUB | Zu alt: 999d |
| `arwunmarona/servo` | GITHUB | Zu alt: 999d |
| `anthonyniqmm/servo` | GITHUB | Zu alt: 999d |
| `webbeef/webviewer` | GITHUB | Zu alt: 999d |
| `justinmichaud/ion` | GITHUB | Zu alt: 999d |
| `moto-browser/moto` | GITHUB | Zu alt: 999d |
| `securesystemslab/pkru-safe-servo` | GITHUB | Zu alt: 999d |
| `fschutt/servo_gui_test` | GITHUB | Zu alt: 999d |
| `Baconana-chan/ferro-browser` | GITHUB | Zu alt: 999d |
| `paulrouget/libsimpleservo` | GITHUB | Zu alt: 999d |
| `karad/my-servo-embedding-example` | GITHUB | Zu alt: 999d |
| `OwnedByWuigi/dactylic` | GITHUB | Zu alt: 999d |
| `galadran/tor-browser` | GITHUB | Zu alt: 999d |
| `Anima-OS/Quokka` | GITHUB | Zu alt: 999d |
| `kinetiknz/gecko` | GITHUB | Zu alt: 999d |
| `BenEgeIzmirli/mozilla_central_in_c` | GITHUB | Zu alt: 999d |
| `jsorg71/waterfox_classic_releases` | GITHUB | Zu alt: 999d |
| `maorsarusi/python_pycharm` | GITHUB | Zu alt: 999d |
| `rivitna/Malware` | GITHUB | Zu alt: 999d |
| `timoschick/form-context-model` | GITHUB | Zu alt: 999d |
| `gsdu8g9/NTP_DDoS_Python` | GITHUB | Zu alt: 999d |
| `EFI-Demo/Endpoint-Forecasting-and-Interpreting` | GITHUB | Zu alt: 999d |
| `eyalmazuz/ThreatIntelligenceCorpus` | GITHUB | Zu alt: 999d |
| `cwbae10-purdue/CTI-EACL24` | GITHUB | Zu alt: 999d |
| `BoiledElectricity/cowrie-honey` | GITHUB | Zu alt: 999d |
| `ultrasaurus/flash-cve-analysis` | GITHUB | Zu alt: 999d |
| `inversify/InversifyJS` | GITHUB | Zu alt: 254d |
| `microsoft/tsyringe` | GITHUB | Zu alt: 191d |
| `anjoy8/Blog.Core` | GITHUB | Zu alt: 106d |
| `ets-labs/python-dependency-injector` | GITHUB | Zu alt: 43d |
| `typestack/typedi` | GITHUB | Zu alt: 275d |
| `jeffijoe/awilix` | GITHUB | Zu alt: 46d |
| `oblac/jodd` | GITHUB | Zu alt: 837d |
| `w3tecch/express-typescript-boilerplate` | GITHUB | Zu alt: 1181d |
| `hellokaton/java-bible` | GITHUB | Zu alt: 1630d |
| `PHP-DI/PHP-DI` | GITHUB | Zu alt: 212d |
| `appsquickly/typhoon` | GITHUB | Zu alt: 2049d |
| `nutzam/nutz` | GITHUB | Zu alt: 276d |
| `unitycontainer/unity` | GITHUB | Zu alt: 922d |
| `gustavopsantos/Reflex` | GITHUB | Zu alt: 43d |
| `deepfence/YaraHunter` | GITHUB | Zu alt: 146d |
| `ForbiddenProgrammer/conti-pentester-guide-leak` | GITHUB | Zu alt: 1809d |
| `cisagov/CHIRP` | GITHUB | Zu alt: 1878d |
| `ClouGence/hasor` | GITHUB | Zu alt: 1325d |
| `danielpalme/IocPerformance` | GITHUB | Zu alt: 1107d |
| `ntxinh/AspNetCore-DDD` | GITHUB | Zu alt: 215d |
| `YairHalberstadt/stronginject` | GITHUB | Zu alt: 396d |
| `forrest-orr/moneta` | GITHUB | Zu alt: 867d |
| `VictorTzeng/Zxw.Framework.NetCore` | GITHUB | Zu alt: 108d |
| `exilon/QuickLib` | GITHUB | Zu alt: 84d |
| `anakic/Jot` | GITHUB | Zu alt: 294d |
| `Patrowl/PatrowlManager` | GITHUB | Zu alt: 143d |
| `golobby/container` | GITHUB | Zu alt: 337d |
| `yoyofx/yoyogo` | GITHUB | Zu alt: 833d |
| `0x27/linux.mirai` | GITHUB | Zu alt: 3451d |
| `SwingFrog/Summer` | GITHUB | Zu alt: 470d |
| `ciscocsirt/GOSINT` | GITHUB | Zu alt: 1179d |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `farseer-go/fs` | GITHUB | Zu alt: 40d |
| `EcsRx/ecsrx` | GITHUB | Zu alt: 406d |
| `suites-dev/suites` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `roadwy/DefenderYara` | GITHUB | Zu alt: 78d |
| `thiagobustamante/typescript-ioc` | GITHUB | Zu alt: 750d |
| `bingcool/swoolefy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheHive-Project/Cortex-Analyzers` | GITHUB | IP-Datei 58d alt |
| `rafaelfgx/DotNetCore` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gendigitalinc/ioc` | GITHUB | Zu alt: 60d |
| `ivlevAstef/DITranquillity` | GITHUB | Zu alt: 85d |
| `pengweiqhca/Xunit.DependencyInjection` | GITHUB | Zu alt: 52d |
| `binghe001/BingheGuide` | GITHUB | Zu alt: 42d |
| `brianway/spring-learning` | GITHUB | Zu alt: 3623d |
| `midwayjs/midway-faas` | GITHUB | Zu alt: 2220d |
| `prodaft/malware-ioc` | GITHUB | Zu alt: 269d |
| `yinguangyao/blog` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `urfnet/URF.Core` | GITHUB | Zu alt: 681d |
| `owja/ioc` | GITHUB | Zu alt: 696d |
| `tshemsedinov/Patterns-JavaScript` | GITHUB | Zu alt: 173d |
| `d1mnewz/interviews` | GITHUB | Zu alt: 1850d |
| `baidu/CarbonGraph` | GITHUB | Zu alt: 634d |
| `ditekshen/detection` | GITHUB | Zu alt: 637d |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Patrowl/PatrowlEngines` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zheksoon/dioma` | GITHUB | Zu alt: 826d |
| `d3fvxl/di` | GITHUB | Zu alt: 958d |
| `testdeck/testdeck` | GITHUB | Zu alt: 555d |
| `gnaeus/react-ioc` | GITHUB | Zu alt: 1002d |
| `mthcht/Purpleteam` | GITHUB | Zu alt: 588d |
| `intentor/adic` | GITHUB | Zu alt: 1817d |
| `urfnet/URF.NET` | GITHUB | Zu alt: 2991d |
| `Go-To-Byte/DouSheng` | GITHUB | Zu alt: 1159d |
| `curated-intel/Log4Shell-IOCs` | GITHUB | Zu alt: 1610d |
| `hidevopsio/hiboot` | GITHUB | Zu alt: 53d |
| `dry-rb/dry-auto_inject` | GITHUB | Zu alt: 66d |
| `molszanski/iti` | GITHUB | Zu alt: 161d |
| `wzhudev/redi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `agileago/vue3-oop` | GITHUB | Zu alt: 406d |
| `assafmo/xioc` | GITHUB | Zu alt: 2294d |
| `aalex954/evilginx2-TTPs` | GITHUB | Zu alt: 471d |
| `artberri/diod` | GITHUB | Zu alt: 665d |
| `wix-incubator/obsidian` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `z4kn4fein/stashbox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Patrowl/PatrowlDocs` | GITHUB | Zu alt: 1571d |
| `microsoft/MinIoC` | GITHUB | Zu alt: 1145d |
| `Puresharper/Puresharp` | GITHUB | Zu alt: 2738d |
| `xpleemoon/XModulable` | GITHUB | Zu alt: 3100d |
| `MySixGod/SpringImpl_v2.0` | GITHUB | Zu alt: 3314d |
| `exuanbo/di-wise` | GITHUB | Zu alt: 534d |
| `Koatty/koatty` | GITHUB | Zu alt: 96d |
| `jbreckmckye/node-typescript-architecture` | GITHUB | Zu alt: 974d |
| `zovajs/zova` | GITHUB | Zu alt: 48d |
| `zzzzbw/doodle` | GITHUB | Zu alt: 1505d |
| `jsuarezruiz/xamarin-forms-perf-playground` | GITHUB | Zu alt: 1331d |
| `shihabmridha/nodejs-repository-pattern-and-ioc` | GITHUB | Zu alt: 510d |
| `401trg/detections` | GITHUB | Zu alt: 1934d |
| `roo-oliv/injectable` | GITHUB | Zu alt: 330d |
| `NullArray/Mimir` | GITHUB | Zu alt: 2726d |
| `vuldb/cyber_threat_intelligence` | GITHUB | Zu alt: 76d |
| `ecomfe/uioc` | GITHUB | Zu alt: 3213d |
| `nikku/didi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mnasyrov/ditox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `typesoft/container-ioc` | GITHUB | Zu alt: 2379d |
| `ZihanType/rudi` | GITHUB | Zu alt: 577d |
| `nicolascotton/nject` | GITHUB | Zu alt: 32d |
| `CYB3RMX/MalwareHashDB` | GITHUB | Zu alt: 549d |
| `scanurag/FoodFrenzy` | GITHUB | Zu alt: 226d |
| `wessberg/DI-compiler` | GITHUB | Zu alt: 638d |
| `dmitryb-dev/waiter` | GITHUB | Zu alt: 899d |
| `uditalias/injex` | GITHUB | Zu alt: 283d |
| `cisagov/ioc-scanner` | GITHUB | Zu alt: 79d |
| `go-spring-rip/spring-core` | GITHUB | Zu alt: 50d |
| `bootsrc/containerx` | GITHUB | Zu alt: 2756d |
| `Rick-van-Dam/Singularity` | GITHUB | Zu alt: 2146d |
| `mbierlee/poodinis` | GITHUB | Zu alt: 204d |
| `conix-security/BTG` | GITHUB | Zu alt: 2803d |
| `go-spring-projects/go-spring` | GITHUB | Zu alt: 84d |
| `opensumi/di` | GITHUB | Zu alt: 322d |
| `absingh31/Tor_Spider` | GITHUB | Zu alt: 3081d |
| `appsquickly/pilgrim` | GITHUB | Zu alt: 1266d |
| `100cm/thunder` | GITHUB | Zu alt: 3734d |
| `di-ninja/di-ninja` | GITHUB | Zu alt: 485d |
| `parthdmaniar/coronavirus-covid-19-SARS-CoV-2-IoCs` | GITHUB | Zu alt: 1937d |
| `HangfireIO/Hangfire.Autofac` | GITHUB | Zu alt: 567d |
| `ChistaDev/Chista` | GITHUB | Zu alt: 804d |
| `krylosov-aa/context-async-sqlalchemy` | GITHUB | Zu alt: 47d |
| `INotfound/Magic` | GITHUB | Zu alt: 929d |
| `davidonzo/apiosintDS` | GITHUB | Zu alt: 778d |
| `AlyElhaddad/ThunderboltIoc` | GITHUB | Zu alt: 333d |
| `enisn/DotNurseInjector` | GITHUB | Zu alt: 948d |
| `KnisterPeter/tsdi` | GITHUB | Zu alt: 977d |
| `otavia-projects/otavia` | GITHUB | Zu alt: 60d |
| `xiuqianli1996/LSFramework` | GITHUB | Zu alt: 969d |
| `tstromberg/ttp-bench` | GITHUB | Zu alt: 53d |
| `OsmanKandemir/web-wordlist-generator` | GITHUB | Zu alt: 796d |
| `phantom0004/morpheus_IOC_scanner` | GITHUB | Zu alt: 534d |
| `bdqfork/festival` | GITHUB | Zu alt: 2341d |
| `blacktop/docker-yara` | GITHUB | Zu alt: 1397d |
| `0xDanielLopez/TweetFeed_code` | GITHUB | Zu alt: 1348d |
| `inversiland/inversiland` | GITHUB | Zu alt: 589d |
| `sergeysychov/behaviour_inject` | GITHUB | Zu alt: 1048d |
| `aloisdeniel/dioc` | GITHUB | Zu alt: 2292d |
| `d3fvxl/inject` | GITHUB | Zu alt: 2355d |
| `byme8/ZeroIoC` | GITHUB | Zu alt: 437d |
| `red-gold/ts-ui` | GITHUB | Zu alt: 785d |
| `assafkip/huntkit` | GITHUB | IP-Datei 107d alt |
| `imnbwd/FriendEditor` | GITHUB | Zu alt: 3423d |
| `TheHive-Project/Zerofox2TH` | GITHUB | Zu alt: 2342d |
| `jacoborus/wiremap` | GITHUB | Zu alt: 208d |
| `wenbo2018/mini-springframework` | GITHUB | Zu alt: 3127d |
| `FarseerNet/Farseer.Net` | GITHUB | Zu alt: 1246d |
| `mjirous/cinject` | GITHUB | Zu alt: 3172d |
| `threat9/routersploit` | GITHUB | Zu alt: 87d |
| `mishakorzik/AllHackingTools` | GITHUB | Zu alt: 257d |
| `Bitwise-01/Instagram-` | GITHUB | Zu alt: 752d |
| `urbanadventurer/Android-PIN-Bruteforce` | GITHUB | Zu alt: 1025d |
| `lcvvvv/kscan` | GITHUB | Zu alt: 1074d |
| `LandGrey/pydictor` | GITHUB | Zu alt: 603d |
| `animir/node-rate-limiter-flexible` | GITHUB | Zu alt: 53d |
| `odedshimon/BruteShark` | GITHUB | Zu alt: 1208d |
| `m0rtem/CloudFail` | GITHUB | Zu alt: 857d |
| `1N3/BruteX` | GITHUB | Zu alt: 712d |
| `assetnote/wordlists` | GITHUB | Zu alt: 154d |
| `t3l3machus/psudohash` | GITHUB | Zu alt: 418d |
| `random-robbie/bruteforce-lists` | GITHUB | Zu alt: 92d |
| `importCTF/Instagram-Hacker` | GITHUB | Zu alt: 1086d |
| `lmammino/jwt-cracker` | GITHUB | Zu alt: 748d |
| `atenreiro/opensquat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `V2RAYCONFIGSPOOL/TELEGRAM_PROXY_SUB` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `utmstack/UTMStack` | GITHUB | IP-Datei 44d alt |
| `rix4uni/fresh-proxy-list` | GITHUB | Identischer Inhalt wie gitrecon1455_fresh_proxy_list |
| `milankappen/k8zner` | GITHUB | IP-Datei 68d alt |
| `ixxeL-DevOps/fullstack` | GITHUB | IP-Datei 96d alt |
| `ankaboot-source/ansible-supabase` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `michaelbeaumont/k8rn` | GITHUB | IP-Datei 214d alt |
| `vowstar/qsoc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MacroPower/homelab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `s0undy/home-ops` | GITHUB | IP-Datei 103d alt |
| `f-bader/DefenderAndSentinelQueries` | GITHUB | IP-Datei 176d alt |
| `gnxD3RfTT2WE/mixed-proxy-list` | GITHUB | Overlap zu gering: 3.8% |
| `mmontes11/k8s-tooling` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Vigil-SOC/vigil` | GITHUB | IP-Datei 100d alt |
| `ErasmusAndre/erasmus.works` | GITHUB | IP-Datei 139d alt |
| `secgroup/Mignis` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `por-cli/por-cli` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `heymaikol/network-doctor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tenhishadow/mbkp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dfroberg/cluster` | GITHUB | IP-Datei 1782d alt |
| `3proxy/3proxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Liana64/home-infra` | GITHUB | IP-Datei 306d alt |
| `secdev/scapy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tylerrosnett/homelab` | GITHUB | IP-Datei 74d alt |
| `nidr0x/k8s-gitops` | GITHUB | IP-Datei 635d alt |
| `JefeDavis/k8s-HomeOps` | GITHUB | IP-Datei 452d alt |
| `batfish/batfish` | GITHUB | IP-Datei 52d alt |
| `mchestr/home-cluster` | GITHUB | IP-Datei 280d alt |
| `alexwaibel/home-ops` | GITHUB | IP-Datei 79d alt |
| `ravilushqa/homelab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `carpenike/k8s-gitops` | GITHUB | IP-Datei 613d alt |
| `aumer-amr/labv2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Euvaz/gitops-home` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MaksimShakavin/flux-homelab` | GITHUB | IP-Datei 195d alt |
| `hcloud-k8s/terraform-hcloud-kubernetes` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mmontes11/k8s-management` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ruifung/rfhome-infrastructure` | GITHUB | IP-Datei 274d alt |
| `budimanjojo/home-cluster` | GITHUB | IP-Datei 175d alt |
| `kOlapsis/maintenant` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `backbay-labs/clawdstrike` | GITHUB | IP-Datei 67d alt |
| `gnxD3RfTT2WE/bot-proxy-list` | GITHUB | Overlap zu gering: 3.4% |
| `budimanjojo/talhelper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alpkeskin/rota` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `toboshii/home-ops` | GITHUB | IP-Datei 1469d alt |
| `gnxD3RfTT2WE/proxy-list-for-scraping` | GITHUB | Overlap zu gering: 1.6% |
| `siderolabs/omni-infra-provider-bare-metal` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `emanuele-em/proxelar` | GITHUB | Größe: 0 IPs |
| `fenio/homelab` | GITHUB | IP-Datei 354d alt |
| `gnxD3RfTT2WE/socks-proxy-list-free` | GITHUB | Overlap zu gering: 2.2% |
| `MISP/misp-galaxy` | GITHUB | Größe: 0 IPs |
| `retroSoC/retroSoC` | GITHUB | Größe: 0 IPs |
| `samuelbartels20/home-ops` | GITHUB | IP-Datei 352d alt |
| `stratosphereips/StratosphereLinuxIPS` | GITHUB | IP-Datei 1276d alt |
| `gnxD3RfTT2WE/free-proxy-list-daily` | GITHUB | Overlap zu gering: 2.8% |
| `copyleftdev/kilo-data` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ffalcinelli/pydivert` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `depalmar/ai_for_the_win` | GITHUB | IP-Datei 223d alt |
| `gnxD3RfTT2WE/txt-proxy-list` | GITHUB | Overlap zu gering: 4.0% |
| `Endika/banlist` | GITHUB | IP-Datei 564d alt |
| `blake-hamm/bhamm-lab` | GITHUB | IP-Datei 493d alt |
| `AlexRosbach/LanLens` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gnxD3RfTT2WE/proxy-feed` | GITHUB | Overlap zu gering: 4.2% |
| `HomelessPhD/BTC32` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yuceltoluyag/GoodProxy` | GITHUB | IP-Datei 823d alt |
| `jeff-nasseri/mikrotik-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gnxD3RfTT2WE/free-rotating-proxies` | GITHUB | Overlap zu gering: 3.4% |
| `etiennetremel/homie-lab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gnxD3RfTT2WE/pipeline-proxy-list` | GITHUB | Overlap zu gering: 3.8% |
| `beenuar/AiSOC` | GITHUB | IP-Datei 87d alt |
| `Nebulock-Inc/agentic-threat-hunting-framework` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hcloud-talos/terraform-hcloud-talos` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `anthr76/infra` | GITHUB | IP-Datei 243d alt |
| `gnxD3RfTT2WE/automation-proxy-list` | GITHUB | Overlap zu gering: 3.8% |
| `leiweibau/Pi.Alert` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TurboRx/Evo-Learn` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sofiaboiko/pfsense-wazuh-project` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gnxD3RfTT2WE/http-socks-proxy-list` | GITHUB | Overlap zu gering: 3.4% |
| `kelchm/home-lab` | GITHUB | Größe: 0 IPs |
| `gnxD3RfTT2WE/proxy-pool-free` | GITHUB | Overlap zu gering: 3.8% |
| `WithSecureLabs/chainsaw` | GITHUB | IP-Datei 628d alt |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `cbuijs_hagezi` | GITHUB | 48,780 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 22,607 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,997 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 7,800 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,471 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 585 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 18,364 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 464 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 253 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,523 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,696 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,555 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,995 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,325 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,470 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https_anonymous` | GITHUB | 5,412 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,793 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,218 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 673 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 634 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 517 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 291 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 31,089 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 7,499 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 5,921 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 8,459 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,018 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,403 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 2,612 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 198,485 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,058 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,282 | 2.6% | 116 | 2026-07-05 |
| `breakingtechfr_proxy_free` | GITHUB | 29,347 | 0.6% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_all` | GITHUB | 32,012 | 0.5% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks4` | GITHUB | 7,200 | 1.9% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks5` | GITHUB | 5,942 | 2.2% | 55 | 2026-07-14 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,635 | 93.4% | 4764 | 2026-07-22 |
| `mohammedcha_proxripper` | GITHUB | 53,311 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,915 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,294 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,363 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 81,312 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,120 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 81,355 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 101,675 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,408 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 109,825 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 104,638 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 586 | 36.7% | 8 | 2026-07-03 |
| `darzanebor_mikroblack` | GITHUB | 41,628 | 26.6% | 13 | 2026-07-05 |
| `ankaboot_source_email_open_data` | GITHUB | 492,425 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,681 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,438 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 172,320 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 139,645 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 106,157 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 87,753 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 106,112 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 80,200 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 136,961 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 42,980 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 67,800 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 29,170 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 18,825 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 32,720 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 21,973 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 15,362 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 13,446 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 27,212 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,053 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,347 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 3,166 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 12,559 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 7,636 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,673 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 6,854 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 5,416 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,988 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,565 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 5,718 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,699 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 1,264 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,457 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 44,202 | 38.5% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 28,577 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 7,304 | 78.1% | 10 | 2026-07-31 |
| `ian_lusule_proxies` | GITHUB | 3,134 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,529 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 865 | 17.2% | 9 | 2026-07-08 |
| `celestialbrain_worldpool` | GITHUB | 81,760 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 254,185 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,277 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,479 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 5,451 | 2.6% | 7 | 2026-07-04 |
| `realizelol_torblocklist` | GITHUB | 1,526 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 34 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 62,079 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 66,353 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,043 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 105 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 196,422 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,755 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,662 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 8,073 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 8,431 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 98,452 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,055 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,955 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 16,517 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,287 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 49,631 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 51,375 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,361 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 117,188 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 382 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 192,269 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 112,471 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 129,107 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 29,556 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 22,922 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 13,813 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,784 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 4,805 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 2,907 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,684 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,261 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 1,500 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 1,443 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,123 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,534 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 1,275 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 1,942 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 1,758 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 3,128 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,841 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,365 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 460 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 440 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 446 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,002 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 373 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,092 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 437 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,437 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 704 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,279 | 6.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_maltrail_scanners` | GITHUB | 16,854 | 14.9% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_iblocklist_cruzit_web_attacks` | GITHUB | 13,871 | 0.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 5,631 | 5.0% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,127 | 24.2% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,382 | 45.4% | 0 | 2026-07-26 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,428 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,462 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,208 | 8.1% | 0 | 2026-07-31 |

---
*Generiert: 2026-07-31 19:19 UTC*