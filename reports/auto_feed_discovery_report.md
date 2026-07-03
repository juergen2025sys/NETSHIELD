# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-03 20:19 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7652** |
| davon GitHub (Topics+Code) | **7601** |
| davon GitLab | **51** |
| davon Awesome-Lists | **1015** |
| Tools/Libraries vor Eval gefiltert | **1150** |
| davon Hard-Reject (awesome-Liste etc.) | **134** |
| EVAL-Kandidaten (nach Stratifizierung) | **300** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluiert | **305** |
| Neu angenommen | **5** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feeds aktualisiert | **51** |
| Abgelehnt (dieser Run) | **300** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **56** |
| IPs in seen_db bestätigt | **1179313** |
| Neue IPs eingetragen | **29774** |
| seen_db gesamt | **5,712,632** |
| HQ-Referenz-IPs (6 Quellen) | **142309** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **244** |
| Repo zu alt (>30d) | **27** |
| IP-Datei veraltet (>30d) | **21** |
| Falsche Größe (<100 / >500k IPs) | **8** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_tor_exits` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,329 | 13.1% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,268 | 13.1% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,213 | 13.1% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,186 | 13.1% | 0.0% | 0 | 🆕 NEU |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | [ziyadnz/threat-intel-ip-feeds](https://github.com/ziyadnz/threat-intel-ip-feeds) | GITHUB | 628 | 36.7% | 0.0% | 8 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `DevTeam/Pure.DI` | GITHUB | Keine IP-Datei |
| `doo/scanbot-sdk-example-android` | GITHUB | IP-Datei 484d alt |
| `greenbone/openvas-scanner` | GITHUB | IP-Datei 78d alt |
| `Ostorlab/oxo` | GITHUB | Keine IP-Datei |
| `manticore-projects/aurscan` | GITHUB | Keine IP-Datei |
| `backstagephp/laravel-seo-scanner` | GITHUB | Keine IP-Datei |
| `securitycipher/penetration-testing-roadmap` | GITHUB | Keine IP-Datei |
| `popcar2/BadWebsiteBlocklist` | GITHUB | Größe: 0 IPs |
| `mandiant/flare-floss` | GITHUB | Keine IP-Datei |
| `andpalmier/makephish` | GITHUB | Keine IP-Datei |
| `StopDDoS/packet-captures` | GITHUB | Keine IP-Datei |
| `DErDYAST1R/EACBypass-CR3ReadyDrv` | GITHUB | Keine IP-Datei |
| `HeadyZhang/agent-audit` | GITHUB | Keine IP-Datei |
| `trailofbits/it-depends` | GITHUB | Keine IP-Datei |
| `jasonish/docker-suricata` | GITHUB | Keine IP-Datei |
| `nshttpd/mikrotik-exporter` | GITHUB | Keine IP-Datei |
| `tikoci/restraml` | GITHUB | IP-Datei 36d alt |
| `FoobarOy/foomuuri` | GITHUB | IP-Datei 94d alt |
| `pymumu/smartdns` | GITHUB | Keine IP-Datei |
| `alexhaydock/pinewall` | GITHUB | Keine IP-Datei |
| `black-desk/cgtproxy` | GITHUB | Keine IP-Datei |
| `voxpupuli/puppet-nftables` | GITHUB | Keine IP-Datei |
| `metal-stack/firewall-controller` | GITHUB | IP-Datei 2262d alt |
| `Pwnzer0tt1/firegex` | GITHUB | Keine IP-Datei |
| `sepandhaghighi/samila` | GITHUB | Keine IP-Datei |
| `dredozubov/hazmat` | GITHUB | Keine IP-Datei |
| `prometheus-community/fortigate_exporter` | GITHUB | Keine IP-Datei |
| `bl4ko/netbox-ssot` | GITHUB | Größe: 0 IPs |
| `40net-cloud/fortinet-azure-solutions` | GITHUB | Keine IP-Datei |
| `TheTaylorLee/AdminToolbox` | GITHUB | Keine IP-Datei |
| `yuriskinfo/cheat-sheets` | GITHUB | Keine IP-Datei |
| `fortinet/fortigate-terraform-deploy` | GITHUB | Keine IP-Datei |
| `vladimirs-git/fortigate-api` | GITHUB | Keine IP-Datei |
| `angela-d/brain-dump` | GITHUB | Zu alt: 69d |
| `fortinet/4D-Demo` | GITHUB | Zu alt: 78d |
| `akshaymane920/pyFortimanagerAPI` | GITHUB | Zu alt: 97d |
| `PaloAltoNetworks/prisma.pan.dev` | GITHUB | Zu alt: 1178d |
| `eworm-de/routeros-scripts` | GITHUB | Keine IP-Datei |
| `EvilFreelancer/docker-routeros` | GITHUB | Keine IP-Datei |
| `ansible-collections/community.routeros` | GITHUB | Keine IP-Datei |
| `beeyev/Mikrotik-RouterOS-automatic-backup-and-update` | GITHUB | Keine IP-Datei |
| `danikf/tik4net` | GITHUB | Keine IP-Datei |
| `luqasz/librouteros` | GITHUB | Keine IP-Datei |
| `tikoci/mikropkl` | GITHUB | Keine IP-Datei |
| `EvilFreelancer/routeros-api-php` | GITHUB | Keine IP-Datei |
| `CA17/TeamsACS` | GITHUB | Keine IP-Datei |
| `hirusha-adi/Data-Recovery` | GITHUB | Zu alt: 468d |
| `NullCode1337/NullRAT` | GITHUB | Zu alt: 119d |
| `por-cli/por-cli` | GITHUB | Keine IP-Datei |
| `alpkeskin/rota` | GITHUB | Keine IP-Datei |
| `koala73/worldmonitor` | GITHUB | Keine IP-Datei |
| `franckferman/MetaDetective` | GITHUB | Keine IP-Datei |
| `ViewTechOrg/Checker-Scammer` | GITHUB | Keine IP-Datei |
| `taranis-ai/taranis-ai` | GITHUB | IP-Datei 80d alt |
| `gebruder/wirken` | GITHUB | IP-Datei 49d alt |
| `grafana/pySigma-backend-loki` | GITHUB | Keine IP-Datei |
| `SigmaHQ/sigma` | GITHUB | IP-Datei 66d alt |
| `stnolting/neorv32` | GITHUB | Keine IP-Datei |
| `l3montree-dev/devguard-web` | GITHUB | Keine IP-Datei |
| `l3montree-dev/devguard` | GITHUB | Größe: 0 IPs |
| `larlarua/AutoCVE` | GITHUB | Keine IP-Datei |
| `tyxak/remotepower` | GITHUB | Keine IP-Datei |
| `TimesysGit/meta-timesys` | GITHUB | Keine IP-Datei |
| `ckotzbauer/vulnerability-operator` | GITHUB | Keine IP-Datei |
| `JMousqueton/github-cve-monitor` | GITHUB | Keine IP-Datei |
| `HolmesGPT/holmesgpt` | GITHUB | IP-Datei 218d alt |
| `qjoly/talosctl-oidc` | GITHUB | Keine IP-Datei |
| `postfinance/topf` | GITHUB | Keine IP-Datei |
| `Correia-jpv/fucking-about-SwiftUI` | GITHUB | Keine IP-Datei |
| `Correia-jpv/fucking-open-source-ios-apps` | GITHUB | Keine IP-Datei |
| `Correia-jpv/fucking-the-book-of-secret-knowledge` | GITHUB | Keine IP-Datei |
| `Enkidu-6/tor-ddos` | GITHUB | Zu alt: 573d |
| `Gi7w0rm/MalwareConfigLists` | GITHUB | Zu alt: 540d |
| `ShadowWhisperer/Remove-MS-Edge` | GITHUB | Keine IP-Datei |
| `metal-stack/nftables-exporter` | GITHUB | Keine IP-Datei |
| `microlinkhq/is-antibot` | GITHUB | Keine IP-Datei |
| `corazawaf/libcoraza` | GITHUB | Keine IP-Datei |
| `JameZUK/os-kea-unbound` | GITHUB | Keine IP-Datei |
| `LdDl/rust-road-traffic` | GITHUB | Keine IP-Datei |
| `ichandkusuma/mikrotik` | GITHUB | Keine IP-Datei |
| `Correia-jpv/fucking-android-security-awesome` | GITHUB | Keine IP-Datei |
| `ShadowWhisperer/AppExorcist` | GITHUB | Zu alt: 154d |
| `jfroy/flatops` | GITHUB | IP-Datei 48d alt |
| `network-evolution/ansible_masterclass` | GITHUB | Zu alt: 85d |
| `Probesys/agentj` | GITHUB | IP-Datei 297d alt |
| `Lubebansokhekel/Pasang` | GITHUB | Keine IP-Datei |
| `owl234/ARL-Next` | GITHUB | IP-Datei 63d alt |
| `codeforsanjose/heartofthevalley` | GITHUB | Zu alt: 117d |
| `linkease/fail2ban-openwrt` | GITHUB | Keine IP-Datei |
| `brat-volk/MagikIndex` | GITHUB | Zu alt: 467d |
| `signalsciences/sigsci-module-golang` | GITHUB | Keine IP-Datei |
| `GuardianWAF/GuardianWAF` | GITHUB | Keine IP-Datei |
| `patoroco/doorkeeper` | GITHUB | Zu alt: 56d |
| `Mazzy-Stars/lain_c2` | GITHUB | Keine IP-Datei |
| `silverwind/dnsbl` | GITHUB | Keine IP-Datei |
| `mrixs/ru_asn_prefixes` | GITHUB | Keine IP-Datei |
| `stillbigjosh/Neo` | GITHUB | Keine IP-Datei |
| `fho/rspamd-iscan` | GITHUB | Keine IP-Datei |
| `Rosa-Luxemburgstiftung-Berlin/ansible-opnsense` | GITHUB | Zu alt: 40d |
| `MISP/cti-transmute` | GITHUB | Keine IP-Datei |
| `scivision/findssh` | GITHUB | Keine IP-Datei |
| `rehiy/isrvd` | GITHUB | Keine IP-Datei |
| `JPCERTCC/CobaltStrike-Config` | GITHUB | Keine IP-Datei |
| `XiaomingX/ddos_attack_script_demo` | GITHUB | Keine IP-Datei |
| `shgew/cs-firewall-bouncer-docker` | GITHUB | Keine IP-Datei |
| `BestBcz/BiliURL` | GITHUB | Keine IP-Datei |
| `emmanuelgjr/genai_incidents` | GITHUB | Größe: 0 IPs |
| `Opnwall/Sing-box-for-OPNsense` | GITHUB | Keine IP-Datei |
| `deedee-ops/home-ops` | GITHUB | Größe: 0 IPs |
| `zsazsa-project/zsazsa` | GITHUB | Keine IP-Datei |
| `Correia-jpv/fucking-lists` | GITHUB | Keine IP-Datei |
| `Goodies365/YandexDecrypt` | GITHUB | Zu alt: 451d |
| `VerifiedJoseph/intruder-alert` | GITHUB | Keine IP-Datei |
| `pfrest/pfsense-vshell` | GITHUB | Keine IP-Datei |
| `Fetcharr/fetcharr` | GITHUB | Keine IP-Datei |
| `adampetrovic/home-ops` | GITHUB | IP-Datei 44d alt |
| `edgenative/mikrotik-irrupdater` | GITHUB | Keine IP-Datei |
| `nightcomdev/opnsense` | GITHUB | Keine IP-Datei |
| `mjcaley/aiospamc` | GITHUB | IP-Datei 1342d alt |
| `OpenFilters/internet-scanners` | GITHUB | Größe: 25 IPs |
| `ClarkFieseln/IPRadar2ForLinux` | GITHUB | Zu alt: 39d |
| `cuducos/airnope` | GITHUB | IP-Datei 380d alt |
| `criblpacks/cribl-palo-alto-networks` | GITHUB | Zu alt: 311d |
| `ttntm/watch3r` | GITHUB | Zu alt: 53d |
| `sjinks/ssh-honeypotd` | GITHUB | Keine IP-Datei |
| `tikoci/rosetta` | GITHUB | Keine IP-Datei |
| `shellkraft/Ledger` | GITHUB | Zu alt: 43d |
| `dcodemaxz/arctryx` | GITHUB | Zu alt: 40d |
| `ShadowWhisperer/TaskKiller` | GITHUB | Zu alt: 135d |
| `altcha-org/altcha-wordpress-next` | GITHUB | Keine IP-Datei |
| `LimerBoy/Soviet-Thief` | GITHUB | Zu alt: 451d |
| `Ostorlab/agent_nmap` | GITHUB | Keine IP-Datei |
| `usethisname1419/HashKiller` | GITHUB | Zu alt: 43d |
| `syed-sameer-ul-hassan/Zenith-Sentry` | GITHUB | Keine IP-Datei |
| `airlock/microgateway` | GITHUB | IP-Datei 51d alt |
| `NotYuSheng/TracePcap` | GITHUB | Keine IP-Datei |
| `tikoci/lsp-routeros-ts` | GITHUB | Keine IP-Datei |
| `VultureProject/vulture-gui` | GITHUB | Keine IP-Datei |
| `Correia-jpv/fucking-android-open-project` | GITHUB | Keine IP-Datei |
| `vshulcz/injex` | GITHUB | Keine IP-Datei |
| `boytchev/spam` | GITHUB | Keine IP-Datei |
| `webishdev/fail2ban-dashboard` | GITHUB | Keine IP-Datei |
| `hacefresko/forticrack_v8` | GITHUB | Keine IP-Datei |
| `AtomTM/Atomic-Mirai` | GITHUB | Zu alt: 49d |
| `26zl/cybersec-toolkit` | GITHUB | Keine IP-Datei |
| `CERT-Polska/karton-classifier` | GITHUB | Zu alt: 42d |
| `nisarnabeel/Multi-Modal-and-Distributed-mmWave-ISAC-Datasets-for-Human-Sensing` | GITHUB | Zu alt: 45d |
| `Mattmorris-dev/netwatch-sec` | GITHUB | Keine IP-Datei |
| `calltelemetry/calltelemetry` | GITHUB | IP-Datei 81d alt |
| `ArtemioPadilla/watchboard` | GITHUB | Keine IP-Datei |
| `Correia-jpv/fucking-build-your-own-x` | GITHUB | Keine IP-Datei |
| `dominicgisler/imap-spam-cleaner` | GITHUB | Keine IP-Datei |
| `Csontikka/ha-mikrotik-extended` | GITHUB | Keine IP-Datei |
| `crowdsecurity/cs-haproxy-spoa-bouncer` | GITHUB | Keine IP-Datei |
| `migros/fotoobo` | GITHUB | Keine IP-Datei |
| `SemanticMediaWiki/SemanticWatchlist` | GITHUB | Keine IP-Datei |
| `Correia-jpv/fucking-public-apis` | GITHUB | Keine IP-Datei |
| `puck-security/puck-scout` | GITHUB | Größe: 0 IPs |
| `network-evolution/Automation-MasterClass-NetworkEvolution` | GITHUB | Zu alt: 85d |
| `univrsal/waechter` | GITHUB | Keine IP-Datei |
| `Konloch/bytecode-viewer` | GITHUB | Keine IP-Datei |
| `endgameinc/ember` | GITHUB | Keine IP-Datei |
| `kevthehermit/VolUtility` | GITHUB | Keine IP-Datei |
| `vduddu/Malware` | GITHUB | Keine IP-Datei |
| `rieck/malheur` | GITHUB | Keine IP-Datei |
| `johnnykv/mnemosyne` | GITHUB | Keine IP-Datei |
| `google/binnavi` | GITHUB | Keine IP-Datei |
| `sleuthkit/scalpel` | GITHUB | Keine IP-Datei |
| `keithjjones/fileintel` | GITHUB | Keine IP-Datei |
| `secretsquirrel/recomposer` | GITHUB | Keine IP-Datei |
| `keithjjones/hostintel` | GITHUB | Keine IP-Datei |
| `hiddenillusion/AnalyzePE` | GITHUB | Keine IP-Datei |
| `sooshie/packerid` | GITHUB | Keine IP-Datei |
| `merces/aleph` | GITHUB | Keine IP-Datei |
| `keithjjones/visualize_logs` | GITHUB | Keine IP-Datei |
| `programa-stic/barf-project` | GITHUB | Keine IP-Datei |
| `jbremer/sflock` | GITHUB | Keine IP-Datei |
| `rocky/python-uncompyle6` | GITHUB | Keine IP-Datei |
| `tklengyel/drakvuf` | GITHUB | Keine IP-Datei |
| `fireeye/flare-vm` | GITHUB | Keine IP-Datei |
| `Defense-Cyber-Crime-Center/DC3-MWCP` | GITHUB | Keine IP-Datei |
| `horsicq/Nauz-File-Detector` | GITHUB | IP-Datei 479d alt |
| `ch3k1/squidmagic` | GITHUB | Keine IP-Datei |
| `pidydx/PyIOCe` | GITHUB | Keine IP-Datei |
| `hiddenillusion/NoMoreXOR` | GITHUB | Keine IP-Datei |
| `joxeankoret/pyew` | GITHUB | Keine IP-Datei |
| `aptnotes/data` | GITHUB | Keine IP-Datei |
| `OMENScan/AChoir` | GITHUB | Keine IP-Datei |
| `fireeye/capa` | GITHUB | Keine IP-Datei |
| `hugsy/codebro` | GITHUB | Keine IP-Datei |
| `katjahahn/PortEx` | GITHUB | Keine IP-Datei |
| `radareorg/cutter` | GITHUB | Keine IP-Datei |
| `Neo23x0/yarGen` | GITHUB | Keine IP-Datei |
| `jbremer/httpreplay` | GITHUB | Keine IP-Datei |
| `unipacker/unipacker` | GITHUB | Keine IP-Datei |
| `a0rtega/pafish` | GITHUB | Keine IP-Datei |
| `simsong/bulk_extractor` | GITHUB | Keine IP-Datei |
| `MITRECND/chopshop` | GITHUB | Keine IP-Datei |
| `ytisf/theZoo` | GITHUB | Keine IP-Datei |
| `devttys0/binwalk` | GITHUB | Keine IP-Datei |
| `moyix/panda` | GITHUB | Keine IP-Datei |
| `F-Secure/see` | GITHUB | Keine IP-Datei |
| `keydet89/RegRipper2.8` | GITHUB | Keine IP-Datei |
| `sketchymoose/TotalRecall` | GITHUB | Keine IP-Datei |
| `sroberts/malwarehouse` | GITHUB | Keine IP-Datei |
| `0xd4d/de4dot` | GITHUB | Keine IP-Datei |
| `JamesHabben/evolve` | GITHUB | Keine IP-Datei |
| `crypto2011/IDR` | GITHUB | Keine IP-Datei |
| `NationalSecurityAgency/ghidra` | GITHUB | Keine IP-Datei |
| `uppusaikiran/generic-parser` | GITHUB | Keine IP-Datei |
| `guelfoweb/peframe` | GITHUB | Keine IP-Datei |
| `sycurelab/DECAF` | GITHUB | Keine IP-Datei |
| `monnappa22/Limon` | GITHUB | Keine IP-Datei |
| `uppusaikiran/malware-organiser` | GITHUB | Keine IP-Datei |
| `volatilityfoundation/volatility` | GITHUB | Keine IP-Datei |
| `JusticeRage/Manalyze` | GITHUB | Keine IP-Datei |
| `omriher/CapTipper` | GITHUB | Keine IP-Datei |
| `ANSSI-FR/polichombr` | GITHUB | Keine IP-Datei |
| `jessek/hashdeep` | GITHUB | Keine IP-Datei |
| `misterch0c/malSploitBase` | GITHUB | Keine IP-Datei |
| `extremecoders-re/pyinstxtractor` | GITHUB | Keine IP-Datei |
| `ytisf/muninn` | GITHUB | Keine IP-Datei |
| `HynekPetrak/javascript-malware-collection` | GITHUB | Keine IP-Datei |
| `fireeye/flare-fakenet-ng` | GITHUB | Keine IP-Datei |
| `plasma-disassembler/plasma` | GITHUB | Keine IP-Datei |
| `mitre/multiscanner` | GITHUB | Keine IP-Datei |
| `elceef/dnstwist` | GITHUB | Keine IP-Datei |
| `KoreLogicSecurity/mastiff` | GITHUB | Keine IP-Datei |
| `504ensicsLabs/DAMM` | GITHUB | Keine IP-Datei |
| `mateuszk87/PcapViz` | GITHUB | Keine IP-Datei |
| `Dynetics/Malfunction` | GITHUB | Keine IP-Datei |
| `quark-engine/quark-engine` | GITHUB | Keine IP-Datei |
| `ispras/qemu` | GITHUB | IP-Datei 3396d alt |
| `williballenthin/EVTXtract` | GITHUB | Keine IP-Datei |
| `maliceio/malice` | GITHUB | Keine IP-Datei |
| `vmt/udis86` | GITHUB | Keine IP-Datei |
| `msuhanov/regf` | GITHUB | Keine IP-Datei |
| `diogo-fernan/malsub` | GITHUB | Keine IP-Datei |
| `jnraber/VirtualDeobfuscator` | GITHUB | Keine IP-Datei |
| `RPISEC/Malware` | GITHUB | Keine IP-Datei |
| `seekr-osint/seekr` | GITHUB | Keine IP-Datei |
| `tg12/phantomtide` | GITHUB | Keine IP-Datei |
| `vericle/intellyweave` | GITHUB | Keine IP-Datei |
| `mxrch/GHunt` | GITHUB | Keine IP-Datei |
| `Berchez/OSINT-steam` | GITHUB | Keine IP-Datei |
| `s0md3v/Orbit` | GITHUB | Keine IP-Datei |
| `s0md3v/Photon` | GITHUB | Keine IP-Datei |
| `subzeroid/insto` | GITHUB | Keine IP-Datei |
| `atiilla/geospy` | GITHUB | Keine IP-Datei |
| `ElevenPaths/FOCA` | GITHUB | Keine IP-Datei |
| `laramies/theHarvester` | GITHUB | Keine IP-Datei |
| `proseltd/Telepathy-Community` | GITHUB | Keine IP-Datei |
| `heldersepu/gmapcatcher` | GITHUB | Keine IP-Datei |
| `khast3x/h8mail` | GITHUB | Keine IP-Datei |
| `GeiserX/Wayback-Archive` | GITHUB | Keine IP-Datei |
| `TeehanLax/Hyperlapse.js` | GITHUB | Keine IP-Datei |
| `projectdiscovery/dnsx` | GITHUB | Keine IP-Datei |
| `megadose/holehe` | GITHUB | Keine IP-Datei |
| `atiilla/OsintEye` | GITHUB | Keine IP-Datei |
| `obitouka/InstagramPrivSniffer` | GITHUB | Keine IP-Datei |
| `Bradro/ICT-Infrastructure-Monitoring-Splunk` | GITHUB | Keine IP-Datei |
| `Samuel411-mbiri/Hancock` | GITHUB | Keine IP-Datei |
| `Judaca73/ghost-os` | GITHUB | Keine IP-Datei |
| `gcve-eu/gcve-enriched-dumps` | GITHUB | Keine IP-Datei |
| `pinkycourse/GhostIntel` | GITHUB | Keine IP-Datei |
| `Catishuge/SplQueryGenerator` | GITHUB | Keine IP-Datei |
| `ciaomah/cyber_studies` | GITHUB | Keine IP-Datei |
| `Hat071/planning-template` | GITHUB | Keine IP-Datei |
| `Loune3213/Wazuh-Openclaw-Autopilot` | GITHUB | IP-Datei 136d alt |
| `MEET-UC/seithar-research` | GITHUB | Keine IP-Datei |
| `Dreamer599/ai-intelligence-hub` | GITHUB | Keine IP-Datei |
| `QuantumS14/DoesTheDogWatchPlex` | GITHUB | Keine IP-Datei |
| `mynameisthis1233/SurfaceMapper` | GITHUB | Keine IP-Datei |
| `zayoi23/openwrt-flowoffload-pbr-mac-misroute` | GITHUB | Keine IP-Datei |
| `Irdk1242s/triagectl` | GITHUB | Keine IP-Datei |
| `1-3-7/disrobe` | GITHUB | Größe: 0 IPs |
| `forsan55/ForzeOS` | GITHUB | Keine IP-Datei |
| `kidrek/VigilIntel` | GITHUB | Keine IP-Datei |
| `tyneplainspoken214/Hades-II-Trainer` | GITHUB | Keine IP-Datei |
| `jokierpro/Top-Conference-Best-Papers` | GITHUB | Keine IP-Datei |
| `kranthi778/footprinting-reconnaissance-project` | GITHUB | Keine IP-Datei |
| `upthatdose/recta-selfhosted-backend` | GITHUB | Keine IP-Datei |
| `Roshenrosha/CBbot` | GITHUB | Keine IP-Datei |
| `jollncoelho/Zhetikal_OSINT_tracker` | GITHUB | Keine IP-Datei |
| `acid5555/pi-hostname` | GITHUB | Keine IP-Datei |
| `IvanAchire/waf-for-gmssh` | GITHUB | Keine IP-Datei |
| `Silakos1/Codex-Windows` | GITHUB | Keine IP-Datei |
| `alexwaibel/home-ops` | GITHUB | IP-Datei 51d alt |
| `danvanbueren/airspace-sim` | GITHUB | Keine IP-Datei |
| `SATiger9300/solo-saas-field-manual` | GITHUB | Keine IP-Datei |
| `Oz134/perishable-inventory-risk-engine` | GITHUB | Keine IP-Datei |
| `ABODR3325/caesar-cipher-python` | GITHUB | Keine IP-Datei |
| `michaelweber52/sherlock-bot-osint` | GITHUB | Keine IP-Datei |
| `michaelweber52/probiv-po-nomeru` | GITHUB | Keine IP-Datei |
| `michaelweber52/probiv-bot-telegram` | GITHUB | Keine IP-Datei |
| `michaelweber52/osint-bot-telegram-2026` | GITHUB | Keine IP-Datei |
| `michaelweber52/glaz-boga-alternative` | GITHUB | Keine IP-Datei |
| `MERUS-J/dictate.sh` | GITHUB | Keine IP-Datei |
| `dasnija/aegis-omega-ids` | GITHUB | Keine IP-Datei |
| `Abhi2109kumar/FaceID` | GITHUB | Keine IP-Datei |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | GITHUB | 10,624 | 75.0% | 4721 | 2026-05-28 |
| `cbuijs_accomplist` | GITHUB | 99,731 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,444 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 118,814 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 110,278 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 628 | 36.7% | 8 | 2026-07-03 |
| `turntuptechnologies_iocs` | GITHUB | 52 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 51,924 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 95,532 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,577 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 115 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 222,171 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,887 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,678 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 6,924 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 7,202 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 166,003 | 18.9% | 1 | 2026-05-28 |
| `idleadmin_threatfeed` | GITHUB | 51,170 | 41.9% | 0 | 2026-04-09 |
| `turbolabit_zzfirewall` | GITHUB | 99,140 | 66.4% | 0 | 2026-05-03 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 45,745 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,434 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 112,235 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 524 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,170 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 191,710 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,461 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 112,223 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 110,371 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 32,107 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 18,571 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 15,367 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,795 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 7,411 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,482 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cps_abusech` | GITHUB | 7,607 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,695 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,610 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 3,968 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,603 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,123 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 3,483 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,747 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 3,048 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,313 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 2,004 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,951 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_socks_proxy_7d` | GITHUB | 1,455 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,329 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,268 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,213 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,186 | 13.1% | 0 | 2026-07-03 |

---
*Generiert: 2026-07-03 20:19 UTC*