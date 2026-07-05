# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-05 11:24 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7655** |
| davon GitHub (Topics+Code) | **7604** |
| davon GitLab | **51** |
| davon Awesome-Lists | **1017** |
| Tools/Libraries vor Eval gefiltert | **1281** |
| davon Hard-Reject (awesome-Liste etc.) | **132** |
| EVAL-Kandidaten (nach Stratifizierung) | **300** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **300** |
| davon angenommene Repositories | **3** |
| davon abgelehnte Repositories | **297** |
| Neu angenommene Feed-Dateien | **7** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **139** |
| Abgelehnte Repositories (dieser Run) | **297** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **146** |
| IPs in seen_db bestätigt | **2543706** |
| Neue IPs eingetragen | **11056** |
| seen_db gesamt | **8,312,859** |
| HQ-Referenz-IPs (6 Quellen) | **140472** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Sonstige | **231** |
| Repo zu alt (>30d) | **45** |
| Falsche Größe (<100 / >2,000,000 IPs) | **11** |
| IP-Datei veraltet (>30d) | **9** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `configserverapps_service_blocklists_sip_365d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 4,217 | 57.4% | 0.0% | 10 | 🆕 NEU |
| `dinoz0rg_proxy_list` | [dinoz0rg/proxy-list](https://github.com/dinoz0rg/proxy-list) | GITHUB | 82,624 | 0.2% | 1.5% | 22 | 🆕 NEU |
| `dinoz0rg_proxy_list_http` | [dinoz0rg/proxy-list](https://github.com/dinoz0rg/proxy-list) | GITHUB | 86,675 | 0.3% | 0.0% | 22 | 🆕 NEU |
| `dinoz0rg_proxy_list_socks5` | [dinoz0rg/proxy-list](https://github.com/dinoz0rg/proxy-list) | GITHUB | 81,274 | 0.2% | 0.0% | 22 | 🆕 NEU |
| `dinoz0rg_proxy_list_http` | [dinoz0rg/proxy-list](https://github.com/dinoz0rg/proxy-list) | GITHUB | 2,335 | 2.6% | 0.0% | 22 | 🆕 NEU |
| `darzanebor_mikroblack` | [darzanebor/mikroblack](https://github.com/darzanebor/mikroblack) | GITHUB | 42,108 | 26.6% | 0.0% | 13 | 🆕 NEU |
| `ian_lusule_proxies` | [Ian-Lusule/Proxies](https://github.com/Ian-Lusule/Proxies) | GITHUB | 3,649 | 2.4% | 0.0% | 9 | 🆕 NEU |
| `ian_lusule_proxies_socks5` | [Ian-Lusule/Proxies](https://github.com/Ian-Lusule/Proxies) | GITHUB | 1,817 | 3.4% | 0.0% | 9 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `samugit83/redamon` | GITHUB | Größe: 0 IPs |
| `parkr/antispam` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tikoci/lsp-routeros-ts` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Hacker-nk/All-hacking-package` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ogtamimi/SOC-Analyst-WriteUp-LetsDefend.io` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `VultureProject/vulture-gui` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Correia-jpv/fucking-android-open-project` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0x41ragorn/cs-discovery` | GITHUB | Zu alt: 691d |
| `boytchev/spam` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `webishdev/fail2ban-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hacefresko/forticrack_v8` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `buter-chkalova/rvbbit-arsenal` | GITHUB | Zu alt: 74d |
| `fuskovic/nw` | GITHUB | Zu alt: 203d |
| `saycc1982/stresscc` | GITHUB | Zu alt: 264d |
| `molangning/fire-av` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mv12star/lista-telefonos-spam` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `devrt/docker-firehol-update-ipsets` | GITHUB | Zu alt: 2700d |
| `Csontikka/ha-mikrotik-extended` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jupyterj0nes/masstin` | GITHUB | Zu alt: 45d |
| `Mattmorris-dev/netwatch-sec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Correia-jpv/fucking-build-your-own-x` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `onedays12/Iris` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dominicgisler/imap-spam-cleaner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `00nx/exodus-decryptor` | GITHUB | Zu alt: 45d |
| `ans-ibrahim/Memento` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pallebone/StrictBlockPAllebone` | GITHUB | Zu alt: 230d |
| `sivvv0/acc-spam-level-probot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `crowdsecurity/cs-haproxy-spoa-bouncer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `migros/fotoobo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ElvisBlue/emotet-deobfuscator` | GITHUB | Zu alt: 1531d |
| `ANONIMO432HZ/ChromiumSpecter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Benamentgerade/Flsasher_USDT_BTC_ETH` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SemanticMediaWiki/SemanticWatchlist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Correia-jpv/fucking-public-apis` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JMousqueton/IoCManager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `puck-security/puck-scout` | GITHUB | Größe: 0 IPs |
| `vmware-labs/emotet-loader` | GITHUB | Zu alt: 1320d |
| `univrsal/waechter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Dynamsoft/mrz-scanner-javascript` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Mr-Meshky/vify` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Regis-Loyaute/hetzner-proxmox-pfsense-opnsense` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Linuxfabrik/firewallfabrik` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `limbang/mirai-console-mcsm-plugin` | GITHUB | Zu alt: 34d |
| `din4e/CtG` | GITHUB | Zu alt: 39d |
| `Argh94/ProxyProwler` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `VAlEqw/TRX-Drainer-Tool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MolotovCherry/stegcloak` | GITHUB | Zu alt: 36d |
| `tholinka/home-ops` | GITHUB | IP-Datei 183d alt |
| `martidu4/honey-ai` | GITHUB | Größe: 0 IPs |
| `paepckehh/opnborg` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `arVahedi/Gl4dius` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `networking-incubator/coraza-kubernetes-operator` | GITHUB | Größe: 0 IPs |
| `vincentkoc/autosecure` | GITHUB | Zu alt: 80d |
| `1Birdo/GoFlood` | GITHUB | Zu alt: 100d |
| `barvhaim/HoneyMCP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ExploitXpErtz/BruteXssh` | GITHUB | Zu alt: 620d |
| `yaencn/safeline-helmchart` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Karib0u/rustinel-rules` | GITHUB | Größe: 0 IPs |
| `Jieyab89/Loader-and-shell-code-AV-Evasion` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sefinek/T-Pot-To-AbuseIPDB` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Phishcan/phishcan-data` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `VibeTensor/attestix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `santhsecurity/wafrift` | GITHUB | IP-Datei 42d alt |
| `RWXstoned/Slack-links-preview-C2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CyrisXD/block-clankers` | GITHUB | Zu alt: 52d |
| `zanesense/abspider-recon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `carvilsi/rubber-dolphy` | GITHUB | Zu alt: 36d |
| `fhoekstra/home-ops` | GITHUB | IP-Datei 140d alt |
| `MagicTeaMC/Minecraft-server-auto-setup` | GITHUB | Zu alt: 302d |
| `ShadowWhisperer/Service-Split` | GITHUB | Zu alt: 573d |
| `alsyundawy/TrustPositif` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `usercode/AspNetCore.Honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `msalihberk/ShadowLab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `djuntgen/firewalla-home-assistant` | GITHUB | Zu alt: 85d |
| `sourcefrenchy/spotexfil` | GITHUB | Zu alt: 76d |
| `JefeDavis/k8s-HomeOps` | GITHUB | IP-Datei 426d alt |
| `anpa1200/adversarygraph` | GITHUB | Größe: 0 IPs |
| `openprotest/protest` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GlueGeomancerStudio/Acunetix-Enterprise` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ghaziwali/Hulios` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `moutonplacide/trickbot` | GITHUB | Zu alt: 2988d |
| `eleboucher/homelab` | GITHUB | IP-Datei 48d alt |
| `binaryn3xus/HomeOps` | GITHUB | Größe: 0 IPs |
| `Correia-jpv/fucking-design-resources-for-developers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SeanLF/still_active` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Opnwall/Mihomo-for-pfSense` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cumakurt/forticheck` | GITHUB | Zu alt: 55d |
| `jkreileder/cf-ips-to-hcloud-fw` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lxrbckl-dev/Project-SelfStack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `K3V1991/How-to-fix-Netflix-Error-15001` | GITHUB | Zu alt: 974d |
| `ScriptTiger/scripttiger.github.io` | GITHUB | Größe: 0 IPs |
| `n3tuk/scripts-mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cecio/EMOTET-2020-Reversing` | GITHUB | Zu alt: 1900d |
| `n3rada/toboggan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `adilhyz/webshells` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ucnl/ucnl.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MagicTeaMC/pterodactyl-tw` | GITHUB | Zu alt: 682d |
| `insomnimus/seo-garbage` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `finos-labs/open-eago` | GITHUB | IP-Datei 109d alt |
| `tatsuyafujisaki/script-cheat-sheet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Opnwall/Sing-box-for-pfSense` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `handeveloper1/DailyProxy---Auto-Update-List` | GITHUB | IP-Datei 276d alt |
| `tg12/OpenMailRelayFuzzer` | GITHUB | Zu alt: 50d |
| `vvswift/P2P-Worm` | GITHUB | Zu alt: 313d |
| `BragatteMAS/os-postinstall-scripts` | GITHUB | IP-Datei 59d alt |
| `skhell/pingtrace` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xamidi/github-followership-scammers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dvershinin/nginx-honeypot` | GITHUB | Zu alt: 31d |
| `fortinet/ibm-fortigate-terraform-deploy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pankuznetsov/Palo-Alto-BASIC-in-Ruby-less-then-in-500-lines` | GITHUB | Zu alt: 2266d |
| `vishnunuk/mikrotik-dual-wan-loadbalance-failover` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `StefanKelm/yara-rules` | GITHUB | Zu alt: 1375d |
| `mastyf-ai/mastyf.ai` | GITHUB | Größe: 0 IPs |
| `danteMorris1/SOAR-Cloud-Cryptojacking-Defense-Threat-Hunting` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `svengo/docker-tor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CIRCL/circl-threat-intel-workshop` | GITHUB | Zu alt: 205d |
| `terrl1nd/PhoenixC2` | GITHUB | Zu alt: 65d |
| `the-hollowclan/LurkerX` | GITHUB | Zu alt: 67d |
| `Teycir/ApiHunter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0xbitx/DEDSEC_TOR-GHOST` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ramazancetinkaya/php-port-scanner` | GITHUB | Zu alt: 250d |
| `JGeek00/crowdsec-monitor-api` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mrodrig/firewalla-apcupsd` | GITHUB | Zu alt: 2030d |
| `ZiMADE/EmoKill` | GITHUB | Zu alt: 1305d |
| `shablin/mtproto-proxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wisepythagoras/honeyshell` | GITHUB | Zu alt: 213d |
| `1-3-7/disrobe` | GITHUB | Größe: 0 IPs |
| `Erikgavs/brutecraber` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BuriXon-code/termux-sources.list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JamesDLD/AzureRm-Template` | GITHUB | Zu alt: 340d |
| `Surfboardv2ray/TGProto` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `noarche/proxylist-socks5-sock4-exported-updates` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Correia-jpv/fucking-Best-websites-a-programmer-should-visit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LordOfPolls/Unifi-Rampart` | GITHUB | Zu alt: 226d |
| `pouriyajamshidi/oxipot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ecency/vision-next` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `KEX001/STORM-SB` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lerjtl/Testfree` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mh37/Argos` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `KaraZajac/SKELETONKEY` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Intevation/intelmq-mailgen` | GITHUB | Zu alt: 57d |
| `JSv4/react-docxodus-viewer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `simonsruggi/StockDock` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vrozaksen/home-ops` | GITHUB | IP-Datei 43d alt |
| `thanosnm/mikrotik-blacklist` | GITHUB | Zu alt: 390d |
| `SagarBiswas-MultiHAT/infosec-vocabulary` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `O-X-L/opnsense-api-client` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nopoz/pfsense-dnscrypt-proxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `H2FSpawn/wazuh-mikrotik-decoder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rblaine95/docker_monero_xmrig` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `b1t0nese/TG-RAT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JiscCTI/misp-docker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fabriziosalmi/nginx-waf-ai` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jakejarvis/sofa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GreyNoise-Intelligence/SA-GreyNoise` | GITHUB | Zu alt: 45d |
| `CriticalPathSecurity/zeek-scripts` | GITHUB | Zu alt: 1944d |
| `lopes/cordyceps` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Neo23x0/yarGen` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jbremer/httpreplay` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `endgameinc/ember` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `williballenthin/python-evt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nbeede/BoomBox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sketchymoose/TotalRecall` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hurricanelabs/machinae` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LordNoteworthy/al-khaser` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lmco/laikaboss` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BromiumLabs/PackerAttacker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hugsy/codebro` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fireeye/stringsifter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RamadhanAmizudin/python-icap-yara` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `williballenthin/EVTXtract` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fireeye/flare-floss` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fireeye/iocs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rieck/malheur` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `longld/peda` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `obitouka/InstagramPrivSniffer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `loseys/Oblivion` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rmusser01/Infosec_Reference` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tomnomnom/waybackurls` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jsvine/waybackpack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kpcyrd/sn0int` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DataSploit/datasploit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hmaverickadams/DeHashed-API-Tool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thewhiteh4t/nexfil` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `khashashin/ogi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lukeslp/antisocial` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shadawck/glit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `misiektoja/github_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tg12/phantomtide` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `snooppr/snoop` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `heldersepu/gmapcatcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `six2dez/reconftw` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `matiash26/steam-osint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gorhill/uBlock` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vognik/maltego-telegram` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `atiilla/geospy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `snooppr/shotstars` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kaifcodec/user-scanner.git` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Lissy93/personal-security-checklist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `s0md3v/Zen` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `finos/perspective` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spmedia/Telegram-Channel-Joiner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `3nock/sub3suite` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `s0md3v/Orbit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sqren/fb-sleep-stats` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `proseltd/Telepathy-Community` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hstsethi/in-mob-prefix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Alaa-abdulridha/SerpScan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GeiserX/Website-Diff` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `atiilla/OsintEye` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NovaCode37/Prism-platform` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FlowingMedia/TimeFlow` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `narkopolo/fb_friend_list_scraper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `misiektoja/spotify_profile_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `drego85/tosint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GreyNoise-Intelligence/pygreynoise` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Bevigil/BeVigil-OSINT-CLI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `akamhy/waybackpy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hamodywe/telegram-scraper-TeleGraphite` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vericle/intellyweave` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zbetcheckin/Security_list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `milo2012/osintstalker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mxrch/GHunt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mantisfury/ArkhamMirror` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tomsec8/IntelHub` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ANG13T/SatIntel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sundowndev/PhoneInfoga` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wireservice/csvkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `david3107/squatm3gator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `momenbasel/keyFinder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `its0x08/duckduckgo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `misiektoja/spotify_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `misiektoja/steam_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `atiilla/gitrecon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `seekr-osint/seekr` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `IvanGlinkin/CCTV` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vflame6/leaker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Berchez/OSINT-steam` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `misiektoja/psn_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `misiektoja/instagram_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `megadose/holehe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ElevenPaths/FOCA` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `l4rm4nd/LinkedInDumper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GeiserX/Wayback-Archive` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `3nock/SpiderSuite` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `projectdiscovery/dnsx` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Datalux/Osintgram` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `owasp-amass/amass` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TeehanLax/Hyperlapse.js` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `amnottdevv/atdork` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `subzeroid/insto` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eth0izzle/the-endorser` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sockysec/Telerecon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ArthurHeitmann/arctic_shift` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `megadose/toutatis` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OSINTI4L/cupidcr4wl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fauvidoTechnologies/PyBrowserAutomation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alaskaintel/alaskaintel-json` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `marcelasp1035/agentskills` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `anniceabsolutistic337/maigret` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Skinned-attention894/anydesk` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tyneplainspoken214/Hades-II-Trainer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aristone9520/loghound` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `blackhandgluon58/Hades-II-Trainer-Max` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sandeepmothukuri/sandeepmothukuri` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `webstockid/webstockid.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Percy2Live/ioBroker.bluetti` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Gitlovess/soc-automation-lab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `most-inaptitude419/Flasher_Crypto` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `deutschemarktoxicdumpsite635/P2.O` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Basicenglishcruisecontrol153/CommiPiste` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ProducerRiyadh/Descargar-Loaris-Trojan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Coriandrumsativumthoracicmedicine670/Acunetix-2026` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `afrivil2644/zan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `prince9594/G-Data-Total-Security-2026` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TaimoorSajjad07/Emsisoft-Anti-Malware-2026` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Bes-js/public-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `notfaj/ester` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `maryamzahra3366/log-sentinel-go` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ganeshphutane-g/scamlens` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `plexusdentalischangtzu246/ai-email-assistant` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tayyabsal8544/mbf-hypixel-macro` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pansyhebephrenic23/NimbusPWN-CVE-2022-29799-29800` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sonale458/Malwarebytes-Premium-2026` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PurpleDefender249/Purple-Labs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `solh8229/osint-recon-hub` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `inadvisable-hibiscusfarragei279/Malware-Sandbox-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `adust-davidgrun268/APT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Genusalsophilaeccehomo626/honey-ai` | GITHUB | Größe: 0 IPs |
| `KANGROO555/hybrid-detection-system` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nwiecz/C2IntelFeedsFGT` | GITHUB | Overlap zu gering: 0.0% |
| `wan03190/CyberSec-Portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Wikid82/Charon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Almaskhan7069/Paralives-Vortex-Extension` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `iwh3n/tg-proxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `horsemanshipprimping590/KustoForge` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | GITHUB | 10,614 | 75.0% | 4721 | 2026-05-28 |
| `cbuijs_hagezi` | GITHUB | 47,187 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 23,865 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,012 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 3,194 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,603 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 627 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 17,378 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 106 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 91 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,213 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,735 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,406 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 2,023 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 4,378 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 4,070 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https_anonymous` | GITHUB | 3,902 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 3,331 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,691 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 1,046 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 852 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 764 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 445 | 12.8% | 60 | 2026-07-04 |
| `leon406_subcrawler` | GITHUB | 110,193 | 0.1% | 1542 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 25,195 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 5,324 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 3,621 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,446 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 7,064 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 5,082 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,404 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 196,551 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,112 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 2,248 | 2.6% | 116 | 2026-07-05 |
| `mohammedcha_proxripper` | GITHUB | 53,893 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,717 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,403 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 114,524 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 82,624 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,335 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 81,274 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 99,882 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,440 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 108,965 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 110,281 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 628 | 36.7% | 8 | 2026-07-03 |
| `darzanebor_mikroblack` | GITHUB | 42,108 | 26.6% | 13 | 2026-07-05 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,478 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,161 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 174,062 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 137,556 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 92,226 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 87,857 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 93,312 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_30d` | GITHUB | 83,990 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 85,720 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 65,355 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 45,699 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_15d` | GITHUB | 47,477 | 47.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 42,702 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 29,794 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 20,620 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 25,023 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,332 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 17,411 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 14,834 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 15,324 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,272 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 11,762 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 8,425 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 9,212 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 9,045 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 6,101 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,580 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 50,311 | 40.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 5,074 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 4,217 | 57.4% | 10 | 2026-07-05 |
| `ian_lusule_proxies` | GITHUB | 3,649 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,817 | 3.4% | 9 | 2026-07-05 |
| `celestialbrain_worldpool` | GITHUB | 79,677 | 0.1% | 8 | 2026-07-05 |
| `officialputuid_proxyforeveryone` | GITHUB | 5,485 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 4,414 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 6,034 | 2.6% | 7 | 2026-07-04 |
| `turntuptechnologies_iocs` | GITHUB | 46 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 52,459 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 93,182 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,594 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 78 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 219,844 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,838 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,678 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 7,026 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 7,303 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 163,301 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 1,984 | 21.9% | 1 | 2026-07-04 |
| `idleadmin_threatfeed` | GITHUB | 50,670 | 41.9% | 0 | 2026-04-09 |
| `turbolabit_zzfirewall` | GITHUB | 99,140 | 66.4% | 0 | 2026-05-03 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 46,037 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,497 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 113,836 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 509 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,168 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 191,758 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,465 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 113,824 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 110,437 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,239 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 31,576 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 493 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 21,062 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 15,089 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,793 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 6,951 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,488 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cps_abusech` | GITHUB | 7,607 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,693 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,636 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 3,958 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,622 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,119 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,535 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 3,256 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,699 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 3,598 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,322 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,984 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,425 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_socks_proxy_7d` | GITHUB | 1,369 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,368 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,257 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,244 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,169 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,105 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 975 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,238 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,214 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 859 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 930 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 877 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 748 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 716 | 40.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 701 | 41.2% | 0 | 2026-07-05 |

---
*Generiert: 2026-07-05 11:24 UTC*