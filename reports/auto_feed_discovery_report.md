# Auto Feed Discovery – Report
**Aktualisiert:** 2026-10-11 22:25 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **12027** |
| davon GitHub (Topics+Code) | **11931** |
| davon GitLab | **96** |
| davon Awesome-Lists | **2398** |
| Tools/Libraries vor Eval gefiltert | **1576** |
| davon Hard-Reject (awesome-Liste etc.) | **176** |
| EVAL-Kandidaten (nach Stratifizierung) | **448** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **448** |
| davon angenommene Repositories | **3** |
| davon abgelehnte Repositories | **445** |
| Neu angenommene Feed-Dateien | **11** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **196** |
| Abgelehnte Repositories (dieser Run) | **445** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **207** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **141760** |
| SQLite-Refresh-Cache-Hits | **187/196** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **302** |
| Repo zu alt (>30d) | **101** |
| Falsche Größe (<30 / >2,000,000 IPs) | **22** |
| IP-Datei veraltet (>30d) | **19** |
| Sonstige | **1** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `gazpitchy92_ip_blocklist_blacklist` | [gazpitchy92/ip-blocklist](https://github.com/gazpitchy92/ip-blocklist) | GITHUB | 353,977 | 18.9% | 0.0% | 6 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 2,295 | 5.4% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_90d` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 5,420 | 61.9% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_30d_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 3,154 | 64.8% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_7d_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 930 | 58.9% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_all_24h_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 390 | 44.1% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_standard_v2` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 287 | 25.4% | 0.0% | 0 | 🆕 NEU |
| `brandontroidl_blocklist_aggressive` | [brandontroidl/blocklist](https://github.com/brandontroidl/blocklist) | GITHUB | 152 | 80.9% | 0.0% | 0 | 🆕 NEU |
| `klonet_it_ip_threat_lists` | [klonet-it/ip-threat-lists](https://github.com/klonet-it/ip-threat-lists) | GITHUB | 121,773 | 51.5% | 0.0% | 1 | 🆕 NEU |
| `klonet_it_ip_threat_lists_blocklist_apache` | [klonet-it/ip-threat-lists](https://github.com/klonet-it/ip-threat-lists) | GITHUB | 9,221 | 9.7% | 0.0% | 1 | 🆕 NEU |
| `rix4uni_fresh_proxy_list` | [rix4uni/fresh-proxy-list](https://github.com/rix4uni/fresh-proxy-list) | GITHUB | 214,413 | 0.2% | 0.0% | 126 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `CriticalPathSecurity/Zeek-Intelligence-Feeds` | GITHUB | Identischer Inhalt wie kraloveckey_ipsets_blocklist_bds_atif |
| `Correia-jpv/fucking-the-book-of-secret-knowledge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crowdsecurity/crowdsec-skill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x00F6/eBPF-ip-reputation-firewall` | GITHUB | Größe: 0 IPs |
| `stopipv/isdi` | GITHUB | Zu alt: 35d |
| `Shpigford/knockoff` | GITHUB | Zu alt: 86d |
| `securego/gosec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TW-NCERT/ctifeeds` | GITHUB | Zu alt: 3667d |
| `elliotwutingfeng/Inversion-DNSBL-Blocklists` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ayms/torrent-live` | GITHUB | Zu alt: 2227d |
| `mikeroyal/Digital-Forensics-Guide` | GITHUB | Zu alt: 1011d |
| `eliotsykes/rails-security-checklist` | GITHUB | Zu alt: 1547d |
| `fullstack-spiderman/hulud-scan` | GITHUB | Zu alt: 237d |
| `LillySchramm/KittyScanBlocklist` | GITHUB | Zu alt: 59d |
| `albinowax/ActiveScanPlusPlus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `speed47/qpxtool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Breus/json-masker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `secretsifter/secretsifter-burp` | GITHUB | Zu alt: 48d |
| `blowfishxyz/blocklist` | GITHUB | Zu alt: 116d |
| `Penetrum-Security/Security-List` | GITHUB | Zu alt: 1661d |
| `openseedbox/openseedbox` | GITHUB | Zu alt: 700d |
| `oluwatobicode/suspicious_ip_detetctor` | GITHUB | Zu alt: 530d |
| `natthasath/ispconfig-shell-script` | GITHUB | Zu alt: 69d |
| `xM0kht4r/VEN0m-Ransomware` | GITHUB | Zu alt: 229d |
| `elliotwutingfeng/Inversion-DNSBL-Generator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trailofbits/vsix-audit` | GITHUB | Zu alt: 75d |
| `seamapi/prefixed-api-key` | GITHUB | Zu alt: 608d |
| `clawdsec/clawsec` | GITHUB | Zu alt: 239d |
| `nay-cat/vAnalyzer` | GITHUB | Zu alt: 47d |
| `jorgsouza/npm-malicious-scanner` | GITHUB | Zu alt: 344d |
| `chesio/bc-security` | GITHUB | Zu alt: 60d |
| `better-auth/better-npm` | GITHUB | Zu alt: 185d |
| `ProsusAI/ClawHive` | GITHUB | Zu alt: 96d |
| `ohdearapp/ohdear-php-sdk` | GITHUB | Zu alt: 195d |
| `paulveillard/cybersecurity` | GITHUB | Zu alt: 622d |
| `ibmresilient/resilient-community-apps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beac0n/ruroco` | GITHUB | Zu alt: 77d |
| `AlienMajik/pwnagotchi_plugins` | GITHUB | Zu alt: 47d |
| `veracode/Veracode-Community-Projects` | GITHUB | Zu alt: 215d |
| `Distracted-E421/nixos-cursor` | GITHUB | Zu alt: 249d |
| `P3t3rp4rk3r/Threat_Intelligence` | GITHUB | Zu alt: 856d |
| `UninvitedActivity/UninvitedActivity` | GITHUB | Zu alt: 89d |
| `rfxn/advanced-policy-firewall` | GITHUB | Zu alt: 142d |
| `netrixone/udig` | GITHUB | Zu alt: 93d |
| `CoChatAI/openclaw-carapace` | GITHUB | Zu alt: 223d |
| `hydro13/tandem-browser` | GITHUB | IP-Datei 224d alt |
| `SuiSec/SuiSecBlockList` | GITHUB | Zu alt: 568d |
| `f5devcentral/f5-ja4` | GITHUB | Zu alt: 99d |
| `Genaker/reactmagento2` | GITHUB | Zu alt: 240d |
| `DinoMorphica/safeclaw` | GITHUB | Zu alt: 234d |
| `MicrosoftARMAssembler/Undetected-Easy` | GITHUB | Zu alt: 107d |
| `SHANIB-C-K/virus-checker-chrome-extention` | GITHUB | Zu alt: 337d |
| `EsadCetiner/Secure-Nginx-Config` | GITHUB | Zu alt: 278d |
| `techenthusiast167/D4rk_Intel-OSINT-Investigative-Toolkit` | GITHUB | Zu alt: 48d |
| `lak1z-azk/discord-security-bot` | GITHUB | Zu alt: 69d |
| `1cbyc/phishfinder.pro` | GITHUB | Zu alt: 307d |
| `Miyso/ScamBlocker` | GITHUB | Zu alt: 433d |
| `Agastya910/agentarmor` | GITHUB | Zu alt: 146d |
| `carved4/gokatz` | GITHUB | Zu alt: 182d |
| `raiph-ai/fireclaw` | GITHUB | Zu alt: 168d |
| `akramlatif/AI-Driven-WiFi-Security-Analyzer` | GITHUB | Zu alt: 100d |
| `devartifex/copilot-unleashed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HackingLZ/svg_phishing_tools` | GITHUB | Zu alt: 382d |
| `LetsUpdate/McScraperIpBlocker` | GITHUB | Zu alt: 264d |
| `Alex8791-cyber/cognithor` | GITHUB | IP-Datei 163d alt |
| `CyberGrandpas/cybergrandpa-web-extension-antifraud` | GITHUB | Zu alt: 40d |
| `AnantDhavale/pip-guardian` | GITHUB | Zu alt: 153d |
| `shakenetwork/MalwareAnalysis` | GITHUB | Zu alt: 3209d |
| `QuasarG/taste-bank` | GITHUB | Zu alt: 40d |
| `statushqorg/status` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `digitalcoyote/NuGetDefense` | GITHUB | Zu alt: 60d |
| `GDATASoftwareAG/nextcloud-gdata-antivirus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `paulveillard/cybersecurity-threat-intelligence` | GITHUB | Zu alt: 104d |
| `depahelix2021/nvidia-dgx-spark-magic-factory` | GITHUB | Zu alt: 199d |
| `mercadoalex/TwinSpark-Chronicles` | GITHUB | Zu alt: 135d |
| `shresthadilip/CyberSecurity` | GITHUB | Zu alt: 511d |
| `maltiverse/python-maltiverse` | GITHUB | Zu alt: 122d |
| `samunoske/SOC-Tools` | GITHUB | Zu alt: 57d |
| `zReL06x/Malwirus` | GITHUB | Zu alt: 240d |
| `christinminor459/OnionClaw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `reloading01/certstream-server-rust` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ne0nd0g/merlin` | GITHUB | IP-Datei 2332d alt |
| `frontendnetwork/veganify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `5rahim/seanime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `87owo/PYAS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hounddogai/hounddog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GamehunterKaan/AutoPWN-Suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mondoohq/installer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `h100envy/gem-search` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `steffenfritz/mxcheck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spamscanner/spamscanner` | GITHUB | Größe: 0 IPs |
| `ZupIT/horusec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f-bader/DefenderAndSentinelQueries` | GITHUB | IP-Datei 248d alt |
| `cyb3rmik3/KQL-threat-hunting-queries` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityClaw/SecurityClaw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PatchMon/PatchMon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `typedb/bazel-distribution` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mr-Meshky/vify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kirillskultan-art/Zemana-Threat-Defense-Suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eooce/node-ws` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alireza0/s-ui` | GITHUB | IP-Datei 41d alt |
| `sower-proxy/sower` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Abao130/xingjiabijichang` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SubleXBle/Fail2Ban-Report` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wiresage/mikrotik-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ifritnoises/sara` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tty228/mikrotik-scripts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AliKarami/MikroMCP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drsound/polywan` | GITHUB | Größe: 0 IPs |
| `metal-stack/firewall-controller` | GITHUB | IP-Datei 2362d alt |
| `metal-stack/nftables-exporter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fyvri/fresh-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ProxyScraper/ProxyScraper` | GITHUB | Overlap zu gering: 1.3% |
| `Surfboardv2ray/TGParse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SailorMo0nEpic/soc-automation-update-channel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `8damon/Blackbird` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SOsintOps/Argos` | GITHUB | Größe: 0 IPs |
| `blackhatethicalhacking/SecretOpt1c` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `clickswave/mach` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lockfale/OSINT-Framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NotLoBi/NotLoBi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AynOps/AynOps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `osintshifu/osint-tradecraft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zarcolio/sitedorks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `theonemule/docker-waf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kosty-cloud/kosty` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zentinelproxy/zentinel` | GITHUB | IP-Datei 236d alt |
| `kdwils/envoy-proxy-crowdsec-bouncer` | GITHUB | IP-Datei 193d alt |
| `Mr-xn/BurpSuite-collections` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `imperva/terraform-provider-incapsula` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jx-sec/jxwaf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chen2he/orange-cloud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `therealilyas/pentest-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gojue/ecapture` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `batfish/batfish` | GITHUB | IP-Datei 124d alt |
| `Ringmast4r/OUI-Master-Database` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jarvis2f/netqmon` | GITHUB | Größe: 0 IPs |
| `secdev/scapy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bdg9412/artex-ko-plus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vehagn/homelab` | GITHUB | IP-Datei 432d alt |
| `MacroPower/homelab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DereC4/internships-and-newgrad` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tranquyetdoraemon-beep/MindMap-Exam-Trainer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Oihalitz/xdp-dns-evadeproxy` | GITHUB | Größe: 0 IPs |
| `dreamworkhq/Tech-Internships-2027` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Astrofrogger/pluck` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bounty020299/GSM-Server-Companion-Desktop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `faaththeeman-bit/wardogs-ballistic-solver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Manavarya09/public-apis-live` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NotASithLord/peerd` | GITHUB | Größe: 0 IPs |
| `bl4ckr0ss3/knife` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OSSDrop/OSSDrop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `luishuallpa1202-lab/LummaC2-Reverse-Engineering-Lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KingHsp/vram-sage-training` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dicklesworthstone/frankensim` | GITHUB | Größe: 0 IPs |
| `RudraVerma-0809/Certification-Craft-Playground` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Enkidu-6/tor-ddos` | GITHUB | Zu alt: 673d |
| `Gi7w0rm/MalwareConfigLists` | GITHUB | Zu alt: 640d |
| `ShadowWhisperer/Remove-MS-Edge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BeStrongok/Malicious-Traffic-Classification` | GITHUB | Zu alt: 2277d |
| `rix4uni/medium-writeups` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chainreactors/malice-network` | GITHUB | Zu alt: 36d |
| `infinition/Zombieland` | GITHUB | Zu alt: 46d |
| `Samsung/LPVS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carlospolop/legion` | GITHUB | Zu alt: 92d |
| `gensecaihq/Wazuh-MCP-Server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `voxpupuli/puppet-os_patching` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `D00Movenok/goMalleable` | GITHUB | Zu alt: 881d |
| `BC-SECURITY/Malleable-C2-Profiles` | GITHUB | Zu alt: 1218d |
| `RedSiege/MiddleOut` | GITHUB | Zu alt: 1712d |
| `FunnyWolf/pystinger` | GITHUB | Zu alt: 1838d |
| `swisskyrepo/SharpLAPS` | GITHUB | Zu alt: 2062d |
| `LoneKingCode/free-proxy-db` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OISF/suricata-intel-index` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jasonish/docker-suricata` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mwakidenis/miktrotik-hotspot-billing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mwakidenis/Mpesa-Based_Wi-Fi-Hotspot_Billing_System` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tikoci/routeros-skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tikoci/rosetta` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eset/stadeo` | GITHUB | Zu alt: 1798d |
| `iss4cf0ng/DuplexSpyCS` | GITHUB | Zu alt: 103d |
| `EntySec/Ghost` | GITHUB | Zu alt: 344d |
| `machine1337/pyFUD` | GITHUB | Zu alt: 389d |
| `chaitin/mimicry` | GITHUB | Zu alt: 205d |
| `prodaft/cradle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rix4uni/scope` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trickest/wordlists` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jieyab89/OSINT-Cheat-sheet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `praetorian-inc/nerva` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sherlock-project/sherlockproject.xyz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `S3N4T0R-0X0/BEAR-C2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `reveng007/DareDevil` | GITHUB | Zu alt: 1436d |
| `TryCatchHCF/PacketWhisper` | GITHUB | Zu alt: 1956d |
| `1N3/PowerExfil` | GITHUB | Zu alt: 2424d |
| `f5devcentral/NGINX-Declarative-API` | GITHUB | IP-Datei 267d alt |
| `bunkerity/bunkerweb` | GITHUB | IP-Datei 54d alt |
| `fabriziosalmi/caddy-mib` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Viralmaniar/DDWPasteRecon` | GITHUB | Zu alt: 1646d |
| `CERTCC/VINCE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERTCC/certfuzz` | GITHUB | Zu alt: 438d |
| `divinelabio/Aegis` | GITHUB | Größe: 0 IPs |
| `bunkerity/bunkerweb-plugins` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chaitin/blazehttp` | GITHUB | Zu alt: 832d |
| `cowrie/docker-cowrie` | GITHUB | Zu alt: 1815d |
| `onedr0p/cluster-template` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `siderolabs/extensions` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cozystack/talm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `siderolabs/discovery-service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hex1629/SOCKETEXPLODE_DOSTOOL` | GITHUB | Zu alt: 914d |
| `D4Vinci/PyFlooder` | GITHUB | Zu alt: 1943d |
| `abriginets/wreckuests` | GITHUB | Zu alt: 1972d |
| `wolfSSL/wolfMQTT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wazuh/wazuh-docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wazuh/wazuh-documentation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wazuh/wazuh-dashboard-plugins` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wazuh/wazuh-ansible` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bherbruck/solidcraft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `righettod/website-passive-reconnaissance` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NHAS/egressinator` | GITHUB | Zu alt: 326d |
| `0x44F/discord-zeroclick-exploit` | GITHUB | Zu alt: 1873d |
| `R00tS3c/BootMe.club-Nulled` | GITHUB | Zu alt: 2468d |
| `sneakerhax/C2PE` | GITHUB | Zu alt: 33d |
| `maxgfr/brutifi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nccgroup/SteppingStones` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CodeXTF2/WebcamBOF` | GITHUB | Zu alt: 564d |
| `CodeXTF2/WindowSpy` | GITHUB | Zu alt: 594d |
| `CodeXTF2/Burp2Malleable` | GITHUB | Zu alt: 1284d |
| `CodeXTF2/cobaltstrike-headless` | GITHUB | Zu alt: 1494d |
| `acidvegas/avoidr` | GITHUB | Zu alt: 1068d |
| `spacepatcher/firehol-ip-aggregator` | GITHUB | Zu alt: 1376d |
| `fox-it/cisco-ios-xe-implant-detection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PaloAltoNetworks/prisma.pan.dev` | GITHUB | Zu alt: 1278d |
| `apache/creadur-rat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oasis-open/cti-stix-validator` | GITHUB | IP-Datei 2916d alt |
| `sefinek/Cloudflare-WAF-Expressions` | GITHUB | IP-Datei 76d alt |
| `coreruleset/plugin-registry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eclecticiq/OpenTAXII` | GITHUB | Zu alt: 213d |
| `fleetdm/fleet` | GITHUB | IP-Datei 81d alt |
| `p4pentest/SuperEnum` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x64dbg/Scripts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `santosomar/YASCON` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bw3ll/JOP_ROCKET` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `azsk/DevOpsKit-docs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `usnistgov/NFIQ2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `salesforce/DazedAndConfused` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zrax/pycdc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ernw/ss7MAPer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fox-it/BloodHound.py` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hunters-forge/API-To-Event` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `payloadbox/command-injection-payload-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `secvisogram/secvisogram` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evilsocket/pwnagotchi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bminossi/AllVideoPocsFromHackerOne` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trailofbits/protofuzz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rudSarkar/crlf-injector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bwrsandman/Bless` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IppSec/Kali-Customizations` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carlospolop/hacktricks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cube0x0/SharpMapExec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gelstudios/gitfiti` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `naim94a/lumen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kholia/airspy-utils` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `1lastBr3ath/XSleaks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manifoldco/torus-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trailofbits/manticore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `david3107/graphql-security-labs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vincentcox/bypass-firewalls-by-DNS-history` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evilsocket/kitsune` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `area31/dfss` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pd0wm/pq-flasher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brad-duncan/May-2021-forensic-quiz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `orlikoski/Skadi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/speakeasy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zodiacon/DriverMon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `e-m-b-a/emba` | GITHUB | IP-Datei 40d alt |
| `processhacker/processhacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arc298/instagram-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tharina/BlackHoodie-2018-Workshop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kahunalu/pwnbin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lovasoa/bad_json_parsers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sophos-ai/SOREL-20M` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hackplayers/4nonimizer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rebootuser/LinEnum` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SandboxEscaper/randomrepo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xmachos/mOSL` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `djhohnstein/macos_shell_memory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `P1sec/QCSuper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UnaPibaGeek/ctfr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `strongdm/comply` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zodiacon/WindowsInternals` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitmproxy/mitmproxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `itm4n/PPLdump` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `h2hconference/2018` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MalwareCantFly/Vba2Graph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zodiacon/AllTools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tyranid/DeviceGuardBypasses` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lgcarmo/WPExploitation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `noncomputable/AgentMaps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frohoff/ysoserial` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bitcoin/bitcoin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blackarrowsec/mssqlproxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `plackyhacker/Sys-Calls` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `infosecn1nja/AD-Attack-Defense` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `malwarialabs/DerbyCon2019` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spring-epfl/lightnion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swisskyrepo/GraphQLmap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Viralmaniar/Remote-Desktop-Caching-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `robinhouston/image-unshredding` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ANSSI-FR/bmc-tools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CyberSecurityUP/Guide-CEH-Practical-Master` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blacknbunny/mcreator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `browninfosecguy/ADLab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drduh/YubiKey-Guide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `helix-editor/helix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Z3Prover/FirewallChecker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arphid/arphid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gdbinit/EFISwissKnife` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gerhart01/Hyper-V-Internals` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `preludeorg/community` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RuthGnz/SpyScrap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sleuthkit/sleuthkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `reider-roque/linpostexp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbarcia/Web-Shells` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `XoodooTeam/Xoodoo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Microsoft/DbgShell` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `appsecco/dvna` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lubeskih/enigma-emulator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `calaylin/bda` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaganisildak/malwarescarecrow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evilsocket/takuan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aoii103/DarkNet_ChineseTrading` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trailofbits/rattle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pwndbg/pwndbg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HatBashBR/HatCloud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `al3xtjames/ghidra-firmware-utils` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/scaaml` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CiscoPSIRT/openVulnQuery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERTCC-Vulnerability-Analysis/trommel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `1tayH/noisy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manoelt/50M_CTF_Writeup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0ffffffffh/dragondance` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `needmorecowbell/Hamburglar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `infobyte/evilgrade` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zikusooka/query_huawei_wifi_router` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hasherezade/bearparser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CaliDog/certstream-server` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coruus/safeclib` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ZerBea/hcxdumptool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `david942j/one_gadget` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SnaffCon/Snaffler` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `1ndianl33t/Gf-Patterns` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fuzzitdev/javafuzz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `michaelweber/Macrome` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nezza/SDQAnalyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inversepath/usbarmory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hardik05/Conferences` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheHive-Project/TheHive4py` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `scriptzteam/BitTorrent-Tracker-List` | GITHUB | Größe: 0 IPs |
| `rowan-beep/destroy-the-claude-limit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inn-media/truyn` | GITHUB | IP-Datei 33d alt |
| `jorgeDevEngineer/edtec_lab_landing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tanjeem180hz/180hz_video-downloader` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spellsaif/warifu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ashutosh20git/TrustGate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SouravBeraAkaSpeed/xiryn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Chetan007-cell/the-accidental-man` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jlevy/squares` | GITHUB | Größe: 0 IPs |
| `simongray/podcast-clj` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shubhamtaywade82/ruby-agent-skills` | GITHUB | Größe: 0 IPs |
| `danieloculus0-bot/AIscend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Redev325/Neo-websitebrowser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jackeddisciple/Jaroku` | GITHUB | IP-Datei 81d alt |
| `darthdemono/sl2-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blindgoofball/united-Minecraft` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tar-ive/ML_Newgrad_2027` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ramondevries/kilo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `solzelic/Currency-desk-OS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zeroroot-ai/sdk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `frostybee/irosashi` | GITHUB | Größe: 0 IPs |
| `cybermanju/cybermanju.github.io` | GITHUB | Größe: 0 IPs |
| `NikolayUvarov/gcu_undocumented_func` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ViditGalav/identity-aware-proxy` | GITHUB | Größe: 0 IPs |
| `AK47-1845/blind-panel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aldoreni45/Zenfix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loayelgebale/azure-sentinel-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spectrayan/carefold` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mohamedzop/usdt-lyd-scanner` | GITHUB | Größe: 0 IPs |
| `harrisonjrubin7-cmyk/semester` | GITHUB | Größe: 0 IPs |
| `eigentunnel/eigentunnel-site` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maherjawabreh97/ISkan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codemod/tsr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sephirothx/sketchy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yeteman420-dotcom/SquachScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wiles7-molder/The-Whims-of-the-Gods-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `viktorg1/lore` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `projectbooth/booth-design` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheGorgeousIvorChival/ferrox` | GITHUB | Größe: 0 IPs |
| `teteateteproject/diagnosticoFredy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jevelopers-neatHack-2026/getticketstub.com` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MGT06/eventhub_backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `17yyamada-tech/dealwire_dailyupdate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andypwhite77-create/venture-lab-bet-001` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nicodes/tools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RustSpaceLab/xtce-rs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rewire82evener/Riot-Control-Simulator-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiagokinlevi/CyberABC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brobinson1000/Tsaki-ERC20-Token` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `darrylmosher/mailroom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SaschaP1980/KleinanzeigenRenewer` | GITHUB | Größe: 0 IPs |
| `anbusan19/Nod` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `techie-jatin/ai-for-lawyers-hackathon-team-innov8` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `priyanshubishtme/zen-alert` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xTimberZx/TestSwap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Changyun-Lee/news-radar` | GITHUB | IP-Datei 100d alt |
| `GetSetSold/cms` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nathan1ca/Stablecoin-watch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CorvinLabs/CorvinOS` | GITHUB | Größe: 0 IPs |
| `awdawmip/enterprise-math` | GITHUB | Größe: 0 IPs |
| `omar-alghamdi-tech/qradar-aql-firewall-cheatsheet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ComponentDock/free-react-templates` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jCondeData/minecraft-alive-workplace` | GITHUB | Größe: 0 IPs |
| `mochiyaki/banana-fighter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DirectorLink/DirectorLink-LG-TV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `floriankml/find-postbox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `scratchhax/pewpew` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WildanDeveloper/dantrix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bybumer/fixit-wp-theme` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aadiitya2007/Hack_On_Tracks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `waqaarhussain/dns-control-hub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rteicheira/wp-annefpugh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `robyajo/pasak` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `coyotecontuses341218/Too-Deep-To-Quit-Beta-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ShadowESC95/ELI_v3.0` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `purvamarlecha/TraceDesk-Cybercrime-Analysis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cchew/lex-au` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Phobius-cpu/RKmission` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hobenyamin/etf-srovnani` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beechnutjaundice74065/Dungeons-And-Furry-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `toby-sutor/realbrowser-mcp-gateway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drahmadaliweb/drahmadaliweb.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `utkarshsingh23-byte/PhishGuard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `The-Arjun-Thakor/logguard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jose-guilherme93/sync-win` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ak10082247-max/rugshield-402` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `O-FALLEN-ANGEL-O/test` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sandeepramaswamykashyap-coder/job-search-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

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
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 4,759 | 64.3% | 938 | 2026-09-04 |
| `cbuijs_hagezi` | GITHUB | 28,901 | 38.6% | 127 | 2026-10-11 |
| `rix4uni_fresh_proxy_list` | GITHUB | 214,413 | 0.2% | 126 | 2026-10-11 |
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
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,469 | 64.3% | 10 | 2026-10-11 |
| `ian_lusule_proxies` | GITHUB | 2,951 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,496 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,501 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 362,696 | 22.0% | 6 | 2026-07-08 |
| `gazpitchy92_ip_blocklist_blacklist` | GITHUB | 353,977 | 18.9% | 6 | 2026-10-11 |
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
| `klonet_it_ip_threat_lists` | GITHUB | 121,773 | 51.5% | 1 | 2026-10-11 |
| `klonet_it_ip_threat_lists_blocklist_apache` | GITHUB | 9,221 | 9.7% | 1 | 2026-10-11 |
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
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 2,295 | 5.4% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_all_90d` | GITHUB | 5,420 | 61.9% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_all_30d_v2` | GITHUB | 3,154 | 64.8% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_all_7d_v2` | GITHUB | 930 | 58.9% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_all_24h_v2` | GITHUB | 390 | 44.1% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_standard_v2` | GITHUB | 287 | 25.4% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_aggressive` | GITHUB | 152 | 80.9% | 0 | 2026-10-11 |

---
*Generiert: 2026-10-11 22:25 CEST (Europe/Berlin)*