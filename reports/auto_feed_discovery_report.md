# Auto Feed Discovery – Report
**Aktualisiert:** 2026-08-30 09:51 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **11159** |
| davon GitHub (Topics+Code) | **11077** |
| davon GitLab | **82** |
| davon Awesome-Lists | **2198** |
| Tools/Libraries vor Eval gefiltert | **867** |
| davon Hard-Reject (awesome-Liste etc.) | **208** |
| EVAL-Kandidaten (nach Stratifizierung) | **189** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **189** |
| davon angenommene Repositories | **0** |
| davon abgelehnte Repositories | **189** |
| Neu angenommene Feed-Dateien | **3** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **195** |
| Abgelehnte Repositories (dieser Run) | **189** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **198** |
| IPs in seen_db bestätigt | **2381278** |
| Neue IPs eingetragen | **1494572** |
| seen_db gesamt | **11,035,840** |
| HQ-Referenz-IPs (6 Quellen) | **135770** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Repo zu alt (>30d) | **90** |
| Keine IP-Datei im Repo | **66** |
| IP-Datei veraltet (>30d) | **18** |
| Falsche Größe (<30 / >2,000,000 IPs) | **12** |
| Overlap mit HQ-Feeds zu gering (<20%) | **2** |
| Format-Qualität zu niedrig (<30% IP-Zeilen) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `gazpitchy92_ip_blocklist_blacklist` | [gazpitchy92/ip-blocklist](https://github.com/gazpitchy92/ip-blocklist) | GITHUB | 312,813 | 21.0% | 0.0% | 6 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_tor_exits` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 1,409 | 56.1% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_sblam` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 959 | 21.0% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `proshiba/vuln-intel-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `koala73/worldmonitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zyrexnn/Cybermes` | GITHUB | Größe: 0 IPs |
| `Xore/APIARY` | GITHUB | Größe: 0 IPs |
| `Johnng007/Live-Forensicator` | GITHUB | Größe: 0 IPs |
| `stamparm/trails` | GITHUB | Overlap zu gering: 0.5% |
| `SEKOIA-IO/documentation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aboutcode-org/vulnerablecode` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrhenrike/EmbedXPL-Forge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `servo/servo` | GITHUB | Größe: 0 IPs |
| `paulrouget/servo-embedding-example` | GITHUB | Zu alt: 3093d |
| `humaidq/dotfiles` | GITHUB | Overlap zu gering: 0.0% |
| `RaafatTurki/dots` | GITHUB | Größe: 0 IPs |
| `natzarich/servo` | GITHUB | IP-Datei 59d alt |
| `anthonyniqmm/servo` | GITHUB | IP-Datei 59d alt |
| `arwunmarona/servo` | GITHUB | Zu alt: 31d |
| `mickeyszabo/servo` | GITHUB | IP-Datei 59d alt |
| `webbeef/webviewer` | GITHUB | Zu alt: 744d |
| `justinmichaud/ion` | GITHUB | Zu alt: 2870d |
| `moto-browser/moto` | GITHUB | Zu alt: 492d |
| `securesystemslab/pkru-safe-servo` | GITHUB | Zu alt: 1398d |
| `fschutt/servo_gui_test` | GITHUB | Zu alt: 3260d |
| `Baconana-chan/ferro-browser` | GITHUB | Zu alt: 61d |
| `paulrouget/libsimpleservo` | GITHUB | Zu alt: 3253d |
| `karad/my-servo-embedding-example` | GITHUB | Zu alt: 2615d |
| `juergen2025sys/NETSHIELD` | GITHUB | Größe: 0 IPs |
| `elementalsouls/Claude-BugHunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OneUptime/blog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rstierli/fortianalyzer-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexlinos/threat-feed-me` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Shayan-heydarikhah/sheynshield` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `demisto/content` | GITHUB | IP-Datei 178d alt |
| `multani/gcp-changelog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xphox2/Firewall-Monitoring` | GITHUB | IP-Datei 46d alt |
| `Samuelabhinav37/moat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sourceseal-star/Red-team-tauri` | GITHUB | Format: 7.8% |
| `percepteye-ai/netgeniusclaw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OwlsNightCatch/ctipilot` | GITHUB | Größe: 0 IPs |
| `SeniorPotato/ZeroDayDiary` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dvsxm/hermes-skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MicrosoftDocs/azure-docs` | GITHUB | IP-Datei 395d alt |
| `ruvnet/RuView` | GITHUB | IP-Datei 229d alt |
| `NirDiamant/GenAI_Agents` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FreedomIntelligence/OpenClaw-Medical-Skills` | GITHUB | Zu alt: 40d |
| `garrytan/gstack` | GITHUB | Größe: 0 IPs |
| `calesthio/OpenMontage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `affaan-m/ECC` | GITHUB | IP-Datei 152d alt |
| `unclecode/crawl4ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `msitarzewski/agency-agents` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `harvard-edge/cs249r_book` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ggml-org/llama.cpp` | GITHUB | IP-Datei 110d alt |
| `github/spec-kit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `K-Dense-AI/scientific-agent-skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rohitg00/agentmemory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jingyaogong/minimind` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abhigyanpatwari/GitNexus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diegosouzapw/OmniRoute` | GITHUB | Größe: 0 IPs |
| `can1357/oh-my-pi` | GITHUB | IP-Datei 80d alt |
| `leon-ai/leon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `asgeirtj/system_prompts_leaks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vonng/ddia` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elder-plinius/OBLITERATUS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ruvnet/ruflo` | GITHUB | IP-Datei 234d alt |
| `GoogleCloudPlatform/generative-ai` | GITHUB | Größe: 0 IPs |
| `cline/cline` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bmad-code-org/BMAD-METHOD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HKUDS/Vibe-Trading` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `apache/airflow` | GITHUB | IP-Datei 62d alt |
| `HKUDS/DeepCode` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mvanhorn/last30days-skill` | GITHUB | Größe: 0 IPs |
| `shanraisshan/claude-code-best-practice` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FareedKhan-dev/train-llm-from-scratch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PostHog/posthog` | GITHUB | IP-Datei 58d alt |
| `hiyouga/LlamaFactory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bojieli/ai-agent-book` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vxcontrol/pentagi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `garrytan/gbrain` | GITHUB | IP-Datei 97d alt |
| `librenms/librenms` | GITHUB | IP-Datei 455d alt |
| `chaziyu/firewall-migration-tool` | GITHUB | Größe: 0 IPs |
| `batfish/batfish` | GITHUB | IP-Datei 82d alt |
| `noctiro/stormin` | GITHUB | Zu alt: 112d |
| `mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites` | GITHUB | Zu alt: 1049d |
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2180d |
| `inversify/InversifyJS` | GITHUB | Zu alt: 284d |
| `midwayjs/midway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anjoy8/Blog.Core` | GITHUB | Zu alt: 136d |
| `ets-labs/python-dependency-injector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typestack/typedi` | GITHUB | Zu alt: 305d |
| `jeffijoe/awilix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oblac/jodd` | GITHUB | Zu alt: 867d |
| `w3tecch/express-typescript-boilerplate` | GITHUB | Zu alt: 1211d |
| `tsedio/tsed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellokaton/java-bible` | GITHUB | Zu alt: 1660d |
| `samber/do` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PHP-DI/PHP-DI` | GITHUB | Zu alt: 242d |
| `appsquickly/typhoon` | GITHUB | Zu alt: 2079d |
| `nutzam/nutz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `unitycontainer/unity` | GITHUB | Zu alt: 952d |
| `gustavopsantos/Reflex` | GITHUB | Zu alt: 73d |
| `certtools/intelmq` | GITHUB | Zu alt: 124d |
| `zycgit/hasor` | GITHUB | Zu alt: 1355d |
| `reactiveui/splat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `danielpalme/IocPerformance` | GITHUB | Zu alt: 1137d |
| `ntxinh/AspNetCore-DDD` | GITHUB | Zu alt: 245d |
| `YairHalberstadt/stronginject` | GITHUB | Zu alt: 426d |
| `forrest-orr/moneta` | GITHUB | Zu alt: 897d |
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VictorTzeng/Zxw.Framework.NetCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `exilon/QuickLib` | GITHUB | Zu alt: 114d |
| `anakic/Jot` | GITHUB | Zu alt: 324d |
| `golobby/container` | GITHUB | Zu alt: 367d |
| `yoyofx/yoyogo` | GITHUB | Zu alt: 863d |
| `SwingFrog/Summer` | GITHUB | Zu alt: 500d |
| `gracicot/kangaru` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `farseer-go/fs` | GITHUB | Zu alt: 70d |
| `suites-dev/suites` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EcsRx/ecsrx` | GITHUB | Zu alt: 436d |
| `roadwy/DefenderYara` | GITHUB | Zu alt: 108d |
| `Savory/Danet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thiagobustamante/typescript-ioc` | GITHUB | Zu alt: 780d |
| `bingcool/swoolefy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rafaelfgx/DotNetCore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gendigitalinc/ioc` | GITHUB | Zu alt: 90d |
| `ivlevAstef/DITranquillity` | GITHUB | Zu alt: 115d |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pengweiqhca/Xunit.DependencyInjection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `binghe001/BingheGuide` | GITHUB | Zu alt: 72d |
| `brianway/spring-learning` | GITHUB | Zu alt: 3653d |
| `midwayjs/midway-faas` | GITHUB | Zu alt: 2250d |
| `yinguangyao/blog` | GITHUB | Zu alt: 50d |
| `prodaft/malware-ioc` | GITHUB | Zu alt: 299d |
| `mwemuorg/mwemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `urfnet/URF.Core` | GITHUB | Zu alt: 711d |
| `owja/ioc` | GITHUB | Zu alt: 726d |
| `zazoomauro/node-dependency-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tshemsedinov/Patterns-JavaScript` | GITHUB | Zu alt: 203d |
| `inversify/monorepo` | GITHUB | IP-Datei 310d alt |
| `d1mnewz/interviews` | GITHUB | Zu alt: 1880d |
| `eggjs/tegg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ditekshen/detection` | GITHUB | Zu alt: 667d |
| `modern-python/that-depends` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maksimzayats/diwire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loresoft/Injectio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `d3fvxl/di` | GITHUB | Zu alt: 988d |
| `zheksoon/dioma` | GITHUB | Zu alt: 856d |
| `testdeck/testdeck` | GITHUB | Zu alt: 585d |
| `gnaeus/react-ioc` | GITHUB | Zu alt: 1032d |
| `intentor/adic` | GITHUB | Zu alt: 1847d |
| `urfnet/URF.NET` | GITHUB | Zu alt: 3021d |
| `Go-To-Byte/DouSheng` | GITHUB | Zu alt: 1189d |
| `hidevopsio/hiboot` | GITHUB | Zu alt: 83d |
| `dry-rb/dry-auto_inject` | GITHUB | Zu alt: 96d |
| `molszanski/iti` | GITHUB | Zu alt: 191d |
| `wzhudev/redi` | GITHUB | Zu alt: 44d |
| `agileago/vue3-oop` | GITHUB | Zu alt: 436d |
| `assafmo/xioc` | GITHUB | Zu alt: 2324d |
| `aalex954/evilginx2-TTPs` | GITHUB | Zu alt: 501d |
| `artberri/diod` | GITHUB | Zu alt: 695d |
| `wix-incubator/obsidian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `z4kn4fein/stashbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Puresharper/Puresharp` | GITHUB | Zu alt: 2768d |
| `xpleemoon/XModulable` | GITHUB | Zu alt: 3130d |
| `MySixGod/SpringImpl_v2.0` | GITHUB | Zu alt: 3344d |
| `exuanbo/di-wise` | GITHUB | Zu alt: 564d |
| `TAKETODAY/today-infrastructure` | GITHUB | IP-Datei 232d alt |
| `Koatty/koatty` | GITHUB | Zu alt: 126d |
| `100nm/python-injection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbreckmckye/node-typescript-architecture` | GITHUB | Zu alt: 1004d |
| `zovajs/zova` | GITHUB | Zu alt: 78d |
| `zzzzbw/doodle` | GITHUB | Zu alt: 1535d |
| `jsuarezruiz/xamarin-forms-perf-playground` | GITHUB | Zu alt: 1361d |
| `shihabmridha/nodejs-repository-pattern-and-ioc` | GITHUB | Zu alt: 540d |
| `401trg/detections` | GITHUB | Zu alt: 1964d |
| `roo-oliv/injectable` | GITHUB | Zu alt: 360d |
| `NullArray/Mimir` | GITHUB | Zu alt: 2756d |
| `ecomfe/uioc` | GITHUB | Zu alt: 3243d |
| `vercube/vercube` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nikku/didi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mnasyrov/ditox` | GITHUB | Zu alt: 35d |
| `typesoft/container-ioc` | GITHUB | Zu alt: 2409d |
| `AsenaJs/Asena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ZihanType/rudi` | GITHUB | Zu alt: 607d |
| `scanurag/FoodFrenzy` | GITHUB | Zu alt: 256d |
| `nicolascotton/nject` | GITHUB | Zu alt: 62d |
| `wessberg/DI-compiler` | GITHUB | Zu alt: 668d |
| `dmitryb-dev/waiter` | GITHUB | Zu alt: 929d |
| `uditalias/injex` | GITHUB | Zu alt: 313d |
| `go-spring-rip/spring-core` | GITHUB | Zu alt: 80d |
| `bootsrc/containerx` | GITHUB | Zu alt: 2786d |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 30,624 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 14,860 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 10,198 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 13,071 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,648 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,712 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,881 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,950 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,720 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,301 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,280 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,013 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 546 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 585 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 455 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 279 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 53,569 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,308 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 17,045 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 8,952 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,584 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,446 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 2,749 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 213,049 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,185 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,151 | 2.6% | 116 | 2026-07-05 |
| `breakingtechfr_proxy_free` | GITHUB | 43,636 | 0.6% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_all` | GITHUB | 46,647 | 0.5% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks4` | GITHUB | 16,351 | 1.9% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks5` | GITHUB | 15,547 | 2.2% | 55 | 2026-07-14 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,627 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 122,867 | 0.1% | 1560 | 2026-08-01 |
| `hookzof_socks5_list` | GITHUB | 124 | 22.1% | 1030 | 2026-08-04 |
| `mohammedcha_proxripper` | GITHUB | 53,391 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,179 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,880 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,681 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 93,428 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,935 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,255 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 104,030 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,704 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 118,509 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,340 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 117,288 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 536 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 485,527 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,137 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 171,579 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 185,626 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 146,389 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 130,354 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 99,820 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 127,560 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 97,995 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 210,249 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 56,882 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 141,006 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 35,822 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 26,812 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 24,010 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 24,001 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 21,750 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 35,265 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 15,469 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,774 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 6,977 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 17,035 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 9,199 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,353 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 8,796 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 6,240 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,775 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 12,842 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 5,854 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,746 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 1,149 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,313 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,190 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,599 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 3,296 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 72,679 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,738 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,136 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 54,248 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 5,017 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,551 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,862 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 865 | 17.2% | 9 | 2026-07-08 |
| `sereinfy_adrules` | GITHUB | 1,294 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 84,591 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 219,961 | 22.0% | 6 | 2026-07-08 |
| `gazpitchy92_ip_blocklist_blacklist` | GITHUB | 312,813 | 21.0% | 6 | 2026-08-30 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,556 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,481 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 6,716 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,569 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 29 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 81,262 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 91,180 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,344 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 77 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 221,046 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,331 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,702 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 193,574 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 35,054 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 7,432 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 2,758 | 34.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_compromised` | GITHUB | 15,517 | 65.9% | 2 | 2026-08-01 |
| `securitylist1568_fortigate` | GITHUB | 190 | 28.1% | 2 | 2026-08-02 |
| `cyberh4ck3r_free_proxy_list` | GITHUB | 2,967 | 1.7% | 2 | 2026-08-12 |
| `cyberh4ck3r_free_proxy_list_socks4_proxies` | GITHUB | 2,114 | 2.6% | 2 | 2026-08-12 |
| `cyberh4ck3r_free_proxy_list_socks5_proxies` | GITHUB | 1,740 | 3.3% | 2 | 2026-08-12 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 13,431 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 13,433 | 76.5% | 3 | 2026-08-09 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,058 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,952 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 15,232 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,327 | 31.1% | 1 | 2026-07-14 |
| `fwahyui_masifa_ipblacklist` | GITHUB | 126,973 | 91.7% | 1 | 2026-08-16 |
| `idleadmin_threatfeed` | GITHUB | 55,305 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 57,283 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,366 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 126,154 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 466 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 193,987 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,523 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 126,087 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 164,451 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,106 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 30,679 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 493 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 25,122 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 14,042 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,747 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 6,666 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,611 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,655 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,700 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 5,000 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,717 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,123 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,534 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,800 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,906 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 1,297 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,818 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,477 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,430 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,348 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,288 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,272 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 956 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,099 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,006 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 970 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,486 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 731 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,947 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,879 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,467 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 13,121 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,449 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 93,656 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 94,516 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 92,564 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 90,854 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 92,169 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 88,270 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 22,870 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 41,723 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 285 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 12,806 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 4,050 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,046 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,500 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,760 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 43,213 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 20,684 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 13,867 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 5,448 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 51 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 24,509 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 128,082 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 25,310 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,734 | 5.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_tor_exits` | GITHUB | 1,409 | 56.1% | 0 | 2026-08-30 |
| `claudiusdecimius_ioc_ipsets_sblam` | GITHUB | 959 | 21.0% | 0 | 2026-08-30 |

---
*Generiert: 2026-08-30 09:51 CEST (Europe/Berlin)*