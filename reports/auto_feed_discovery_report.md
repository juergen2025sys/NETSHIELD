# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-05 07:46 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7655** |
| davon GitHub (Topics+Code) | **7604** |
| davon GitLab | **51** |
| davon Awesome-Lists | **1018** |
| Tools/Libraries vor Eval gefiltert | **1282** |
| davon Hard-Reject (awesome-Liste etc.) | **132** |
| EVAL-Kandidaten (nach Stratifizierung) | **300** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **300** |
| davon angenommene Repositories | **4** |
| davon abgelehnte Repositories | **296** |
| Neu angenommene Feed-Dateien | **14** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **118** |
| Abgelehnte Repositories (dieser Run) | **296** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **132** |
| IPs in seen_db bestätigt | **1986144** |
| Neue IPs eingetragen | **545508** |
| seen_db gesamt | **8,298,043** |
| HQ-Referenz-IPs (6 Quellen) | **140333** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Sonstige | **219** |
| IP-Datei veraltet (>30d) | **36** |
| Repo zu alt (>30d) | **23** |
| Falsche Größe (<100 / >2,000,000 IPs) | **9** |
| Overlap mit HQ-Feeds zu gering (<20%) | **9** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 716 | 40.2% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 701 | 41.2% | 0.5% | 0 | 🆕 NEU |
| `configserverapps_service_blocklists_vnc_365d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 6,089 | 62.1% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_attacks_mail` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 5,581 | 49.8% | 0.0% | 10 | 🆕 NEU |
| `ercindedeoglu_proxies` | [ErcinDedeoglu/proxies](https://github.com/ErcinDedeoglu/proxies) | GITHUB | 25,366 | 0.6% | 0.5% | 375 | 🆕 NEU |
| `ercindedeoglu_proxies_socks4` | [ErcinDedeoglu/proxies](https://github.com/ErcinDedeoglu/proxies) | GITHUB | 5,480 | 1.9% | 0.0% | 375 | 🆕 NEU |
| `ercindedeoglu_proxies_socks5` | [ErcinDedeoglu/proxies](https://github.com/ErcinDedeoglu/proxies) | GITHUB | 3,837 | 2.6% | 0.0% | 375 | 🆕 NEU |
| `tuanminpay_live_proxy` | [TuanMinPay/live-proxy](https://github.com/TuanMinPay/live-proxy) | GITHUB | 9,419 | 1.4% | 0.5% | 51 | 🆕 NEU |
| `tuanminpay_live_proxy_http` | [TuanMinPay/live-proxy](https://github.com/TuanMinPay/live-proxy) | GITHUB | 6,959 | 1.9% | 1.0% | 51 | 🆕 NEU |
| `tuanminpay_live_proxy_socks4` | [TuanMinPay/live-proxy](https://github.com/TuanMinPay/live-proxy) | GITHUB | 5,117 | 2.0% | 0.0% | 51 | 🆕 NEU |
| `tuanminpay_live_proxy_socks5` | [TuanMinPay/live-proxy](https://github.com/TuanMinPay/live-proxy) | GITHUB | 3,423 | 2.9% | 0.0% | 51 | 🆕 NEU |
| `gitrecon1455_fresh_proxy_list` | [gitrecon1455/fresh-proxy-list](https://github.com/gitrecon1455/fresh-proxy-list) | GITHUB | 196,901 | 0.2% | 0.0% | 106 | 🆕 NEU |
| `noctiro_getproxy` | [noctiro/getproxy](https://github.com/noctiro/getproxy) | GITHUB | 4,513 | 1.3% | 0.0% | 116 | 🆕 NEU |
| `noctiro_getproxy_socks5` | [noctiro/getproxy](https://github.com/noctiro/getproxy) | GITHUB | 3,375 | 2.6% | 0.0% | 116 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `Homas/ioc2rpz` | GITHUB | IP-Datei 67d alt |
| `cifertech/ESP32-DIV` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `87owo/PYAS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gardenfence/blocklist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aptzer0x/evilurl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Rhacknarok/hacksguard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `beelzebub-labs/beelzebub` | GITHUB | IP-Datei 73d alt |
| `f-bader/DefenderAndSentinelQueries` | GITHUB | IP-Datei 150d alt |
| `0xSteph/pentest-ai` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xsscx/fuzz` | GITHUB | IP-Datei 3765d alt |
| `Chocapikk/wpprobe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bitsadmin/wesng` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wall-flipping/SSV2RayTrojanClashSSR` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OverTheWallNode/SSV2RayTrojanSSRClash` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `silentchainai/SILENTCHAIN` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Marven11/EtherGhost` | GITHUB | Zu alt: 33d |
| `ReaJason/No-One` | GITHUB | Zu alt: 36d |
| `zhaojh329/rtty` | GITHUB | Zu alt: 59d |
| `aels/wso-ng` | GITHUB | Zu alt: 64d |
| `Cvar1984/sussyfinder` | GITHUB | Größe: 0 IPs |
| `yasserbdj96/hiphp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `carloslack/KoviD` | GITHUB | Zu alt: 35d |
| `alphaa1111/proxyscraper` | GITHUB | Overlap zu gering: 0.7% |
| `vakhov/fresh-proxy-list` | GITHUB | IP-Datei 148d alt |
| `MrMarble/proxy-list` | GITHUB | Overlap zu gering: 4.7% |
| `hookzof/socks5_list` | GITHUB | Overlap zu gering: 14.0% |
| `fyvri/fresh-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Surfboardv2ray/TGParse` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `iplocate/free-proxy-list` | GITHUB | Overlap zu gering: 1.0% |
| `berkay-digital/Proxy-Scraper` | GITHUB | Overlap zu gering: 7.5% |
| `sunny9577/proxy-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `elliottophellia/proxylist` | GITHUB | Overlap zu gering: 5.6% |
| `gfpcom/free-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ProxyScraper/ProxyScraper` | GITHUB | Overlap zu gering: 2.0% |
| `papapapapdelesia/Emilia` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `por-cli/por-cli` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alpkeskin/rota` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ruped24/tor_ip_switcher` | GITHUB | Zu alt: 337d |
| `prxchk/proxy-list` | GITHUB | Zu alt: 813d |
| `blacklanternsecurity/cloudcheck` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sherlock-project/sherlock` | GITHUB | IP-Datei 472d alt |
| `HackUnderway/SearchPhone` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SEKOIA-IO/automation-library` | GITHUB | IP-Datei 289d alt |
| `devops-ia/helm-opencti` | GITHUB | IP-Datei 300d alt |
| `ThreatRecall/zettelforge` | GITHUB | IP-Datei 81d alt |
| `fastfire/deepdarkCTI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rulezet/rulezet-core` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mitre-attack/attack-navigator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `7onez/cti-expert` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mitre-attack/attack-website` | GITHUB | IP-Datei 706d alt |
| `mitre-attack/attack-stix-data` | GITHUB | IP-Datei 54d alt |
| `VictoriaMetrics/VictoriaLogs` | GITHUB | IP-Datei 198d alt |
| `FunnyWolf/agentic-soc-platform` | GITHUB | Größe: 0 IPs |
| `call518/LogSentinelAI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `scalytics/kafSIEM` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rabbitstack/fibratus` | GITHUB | IP-Datei 331d alt |
| `HydraDragonAntivirus/HydraDragonAntivirus` | GITHUB | IP-Datei 76d alt |
| `V-i-x-x/kernel-callback-removal` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `backbay-labs/clawdstrike` | GITHUB | IP-Datei 41d alt |
| `niklasr22/BrightIntosh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Xacone/BestEdrOfTheMarket` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `leebaird/discover` | GITHUB | Größe: 0 IPs |
| `rix4uni/scope` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `osamahamad/payout-targets-data` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `soxoj/maigret` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Jieyab89/OSINT-Cheat-sheet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trickest/wordlists` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SOsintOps/Argos` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `7anX/AgentScan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AnonCatalyst/Coeus-OSINT-ToolBox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tdh8316/Investigo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `h4rithd/PrecompiledBinaries` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `n3rada/MSSQLand` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Coff0xc/AutoRedTeam-Orchestrator` | GITHUB | Zu alt: 48d |
| `travisbgreen/hunting-rules` | GITHUB | Zu alt: 59d |
| `ktol1/RedTeam-Agent` | GITHUB | Zu alt: 72d |
| `FalconOpsLLC/goexec` | GITHUB | Zu alt: 102d |
| `GTFOBins/GTFOBins.github.io` | GITHUB | Zu alt: 39d |
| `jaschadub/VectorSmuggle` | GITHUB | Zu alt: 47d |
| `lolexfil/lolexfil.github.io` | GITHUB | Zu alt: 57d |
| `mazen160/xless` | GITHUB | Zu alt: 99d |
| `fulldecent/system-bus-radio` | GITHUB | Zu alt: 109d |
| `t0thkr1s/gtfobins-cli` | GITHUB | Zu alt: 151d |
| `lulzddos/Lulzddos` | GITHUB | IP-Datei 1068d alt |
| `PentestPlaybook/ad-lab-scripts` | GITHUB | Zu alt: 39d |
| `AdrMXR/KitHack` | GITHUB | Zu alt: 501d |
| `Leeon123/CC-attack` | GITHUB | Zu alt: 994d |
| `chen2he/orange-cloud` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bountyyfi/lonkero` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kejilion/sh` | GITHUB | IP-Datei 735d alt |
| `coreruleset/coreruleset` | GITHUB | Größe: 0 IPs |
| `gen0sec/synapse` | GITHUB | IP-Datei 37d alt |
| `SecAegis/SecAutoBan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sefinek/Cloudflare-WAF-Expressions` | GITHUB | Overlap zu gering: 5.0% |
| `corazawaf/libinjection-go` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `crowdsecurity/crowdsec` | GITHUB | Größe: 0 IPs |
| `corazawaf/coraza` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bunkerity/bunkerweb` | GITHUB | IP-Datei 32d alt |
| `fuomag9/caddy-proxy-manager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lancard/nginx-webui` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `macadmins/sofa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vulnerability-lookup/vulnerability-lookup` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hijack1r/CVE_PushService` | GITHUB | IP-Datei 226d alt |
| `sari3l/Poc-Monitor` | GITHUB | IP-Datei 1224d alt |
| `Galeax/CVE2CAPEC` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `briandfoy/cpan-security-advisory` | GITHUB | IP-Datei 869d alt |
| `JMousqueton/github-cve-monitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kunalnagarco/action-cve` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EXP-Tools/threat-broadcast` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `olbat/nvdcve` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OWASP/cve-lite-cli` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sourcentis/mercator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `larlarua/AutoCVE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `karimhabush/cyberowl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OTT-Cybersecurity-LLC/lyrie-ai` | GITHUB | IP-Datei 69d alt |
| `Bert-JanP/Hunting-Queries-Detection-Rules` | GITHUB | IP-Datei 1084d alt |
| `rxerium/rxerium-templates` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JGoyd/iOS-Attack-Chain-CVE-2025-31200-CVE-2025-31201` | GITHUB | Zu alt: 61d |
| `416rehman/DeepZero` | GITHUB | Zu alt: 68d |
| `dmarcguardhq/dmarcguard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `deeztek/Hermes-Secure-Email-Gateway` | GITHUB | Größe: 0 IPs |
| `GhostESP-Revival/GhostESP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lord-alfred/ipranges` | GITHUB | Overlap zu gering: 0.0% |
| `BornToBeRoot/NETworkManager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mennylevinski/core_net_scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vil/H4X-Tools` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HaxL0p4/L0p4Map` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nmap/nmap` | GITHUB | IP-Datei 830d alt |
| `praetorian-inc/nerva` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ddddddO/packemon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `edoardottt/pphack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Marvinxc181/Crypto-Clipper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jnMetaCode/shellward` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OneUptime/oneuptime` | GITHUB | IP-Datei 94d alt |
| `ongridio/ongrid` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `roxy-wi/IncidentRelay` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SecurityBrewery/catalyst` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jmpsec/osctrl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MISP/PyMISP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fhightower/ioc-finder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MISP/misp-objects` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `monarc-project/MOSP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cerebrate-project/cerebrate` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `certd/certd` | GITHUB | IP-Datei 74d alt |
| `CERT-Polska/mwdb-core` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NovaDev404/NexCerts` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CybercentreCanada/assemblyline` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `github/codeql-coding-standards` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CERTCC/VINCE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `utopia-php/abuse` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wallarm/docker-wallarm-node` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `apache/casbin-gateway` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aaPanel/aaWAF` | GITHUB | Zu alt: 32d |
| `dealfluence/adeu` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kizubenda/NjRAT-ShadowEdge-Controller` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fintanpyren-coder/njrat-config-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `graneed/bwpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `naorlivne/dshp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Novetta/delilah` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mrheinen/lophiid` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hatching/vmcloak` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `m4rco-/dorothy2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Marist-Innovation-Lab/PasitheaHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `msurguy/Honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `betheroot/sticky_elephant` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `blaverick62/SIREN` | GITHUB | IP-Datei 3032d alt |
| `ciscocsirt/dhp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gosecure/pyrdp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `morian/blacknet` | GITHUB | IP-Datei 1021d alt |
| `qeeqbox/honeypots` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `urule99/jsunpack-n` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jpyorre/IntelligentHoneyNet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mkishere/sshsyrup` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xiaoxiaoleo/HoneyMysql` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PaulMaddox/gohoney` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OWASP/Python-Honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `honeytrap/honeytrap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `d1str0/drupot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fofapro/fapro` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `phin3has/mailoney` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `schmalle/honeyalarmg2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bartnv/portlurker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mfontani/kippo-stats` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mdp/honeypot.go` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thomaspatzke/Log4Pot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xme/dshield-docker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gbrindisi/wordpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `referefref/modpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `securitygeneration/Honeyport` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sec51/honeymail` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bocajspear1/honeyhttpd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JustinAzoff/ssh-auth-logger` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `johnnykv/heralding` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0x4D31/honeybits` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thinkst/opencanary` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `robertdavidgraham/telnetlogger` | GITHUB | IP-Datei 3536d alt |
| `andrewmichaelsmith/bluepot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SecurityTW/delilah` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kingtuna/go-emulators` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `referefref/honeyfs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ziemeck/bifrozt-ansible` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mrschyte/dockerpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fygrave/honeyntp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `andrewmichaelsmith/manuka` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `referefref/canarytokendetector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nsmfoo/dicompot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `honeynet/phoneyc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nsmfoo/antivmdetection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HoneySat/honeysat-deploy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rubenespadas/DionaeaFR` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fzerorubigd/go0r` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jeremyfritzen/Ethereum-honey-pot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `freak3dot/smart-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cymmetria/honeycomb_plugins` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MartinIngesen/HonnyPotter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ncouture/MockSSH` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `betheroot/pghoney` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `batchmcnulty/Malbait` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `WebDecoy/FCaptcha` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `stamparm/hontel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mushorg/tanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `miguelraulb/spamhat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thinkst/canarytokens` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `schmalle/medpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `deroux/longitudinal-analysis-cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `provos/honeyd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ppacher/honeyssh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sk4ld/gridpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tomchop/malcom` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hiddenillusion/AnalyzePE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `keithjjones/cuckoo-modified-api` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `merces/aleph` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `google/binnavi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `uppusaikiran/yara-finder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `programa-stic/barf-project` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `swwwolf/wdbgark` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ashishb/android-security-awesome` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hiddenillusion/AnalyzePDF` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `extremecoders-re/pyinstxtractor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NationalSecurityAgency/ghidra` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `keydet89/RegRipper2.8` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `radareorg/cutter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hiddenillusion/IPinfo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `KoreLogicSecurity/mastiff` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `joxeankoret/pyew` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `keithjjones/fileintel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CapacitorSet/box-js` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vmt/udis86` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `simsong/bulk_extractor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `malwaremusings/unpacker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OMENScan/AChoir` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Visgean/Zeus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `plasma-disassembler/plasma` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ShaneK2/inVtero.net` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `moyix/panda` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tklengyel/drakvuf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ContextualWisdomLab/waf-ids-ai-soc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Exikle/Artemis-Cluster` | GITHUB | IP-Datei 49d alt |
| `comfyshee/proxmox-homelab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `01rabbit/Azazel-Edge` | GITHUB | IP-Datei 53d alt |
| `nmanoj9/SOC-Project-4-Splunk-SOC-Investigation-Lab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `arieahXxshrek/secwexen.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yuzeguitarist/ParallaX` | GITHUB | Größe: 0 IPs |
| `Prajwalgrathish/TotalOSINT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mauricegift/free-proxies` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `elcattivo66/home-ops` | GITHUB | Größe: 0 IPs |
| `stormsia/proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ashveil1/Elengenix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `andreshdez-18/QQSafeChat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rxhn911/Aero-Nethunter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alonsoir/argus` | GITHUB | IP-Datei 39d alt |
| `AbhinavVijayvergia/Cloud-Trail-Detector` | GITHUB | Größe: 0 IPs |
| `solanyn/home-ops` | GITHUB | IP-Datei 87d alt |
| `Nikopmpm/Fsociety-CVE-2024-0670-CheckMK-LPE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yooaoalannana/ESP8266-WIDS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ch1n3x1/kew` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `slok/stactus-showcase` | GITHUB | IP-Datei 613d alt |
| `quodeq/quodeq` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jorgewgouveia/Cybersecurity-Conferences` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `navin-hariharan/CVE-DATABASE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jwardsmith/Penetration-Testing` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheeAmir/scambuster-preview` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Gberegbe/infrastructure-security-automation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kneha10/cyber-forge` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CHUMENII/COM-UACBypass-Privilege-Escalation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mwakidenis/miktrotik-hotspot-billing` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `seanpor/JA4proxy` | GITHUB | IP-Datei 82d alt |
| `Trivexion/FscanOutput-Beautify` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fahryzaa/burp_history` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vaishnavipawar-29/Moonwalk--` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Tempest-Solutions-Company/threat-feeds` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Bd-Mutant7/Cybersecurity-Threats-Guide` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hnordt/vps-bootstrap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gaga84700/police` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `naixiao/multi-lang-code-audit-skill` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Rajesh660/HomeAssistant-Santa-Tracker` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | GITHUB | 10,622 | 75.0% | 4721 | 2026-05-28 |
| `cbuijs_hagezi` | GITHUB | 47,187 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 25,335 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,012 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 3,226 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,583 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 627 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 17,570 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 162 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 103 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,851 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 4,064 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,430 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 2,347 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 4,930 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 4,563 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https_anonymous` | GITHUB | 4,950 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 4,504 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,546 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 1,008 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 898 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 805 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 509 | 12.8% | 60 | 2026-07-04 |
| `leon406_subcrawler` | GITHUB | 110,185 | 0.1% | 1542 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 25,366 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 5,480 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 3,837 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,419 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,959 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 5,117 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,423 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 196,901 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,513 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,375 | 2.6% | 116 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 99,882 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,440 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 108,965 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 108,357 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 628 | 36.7% | 8 | 2026-07-03 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,478 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,158 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 176,193 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 137,885 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 92,281 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 86,963 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 93,312 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_30d` | GITHUB | 83,684 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 85,720 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 65,287 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 45,735 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_15d` | GITHUB | 47,129 | 47.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 42,650 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 28,998 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 20,584 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 24,981 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,332 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 17,557 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 14,908 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 15,301 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,272 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 11,762 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,181 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 9,175 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 9,045 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 6,089 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,581 | 49.8% | 10 | 2026-07-05 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,063 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 4,869 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 6,079 | 2.6% | 7 | 2026-07-04 |
| `turntuptechnologies_iocs` | GITHUB | 46 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 52,386 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 94,446 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,594 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 78 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 221,848 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,866 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,678 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 7,014 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 7,291 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 163,301 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 1,984 | 21.9% | 1 | 2026-07-04 |
| `idleadmin_threatfeed` | GITHUB | 50,291 | 41.9% | 0 | 2026-04-09 |
| `turbolabit_zzfirewall` | GITHUB | 99,140 | 66.4% | 0 | 2026-05-03 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 46,037 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,497 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 113,836 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 506 | 64.5% | 0 | 2026-05-30 |
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
*Generiert: 2026-07-05 07:46 UTC*