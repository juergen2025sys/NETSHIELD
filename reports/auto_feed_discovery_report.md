# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-04 16:08 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7653** |
| davon GitHub (Topics+Code) | **7602** |
| davon GitLab | **51** |
| davon Awesome-Lists | **1018** |
| Tools/Libraries vor Eval gefiltert | **1278** |
| davon Hard-Reject (awesome-Liste etc.) | **129** |
| EVAL-Kandidaten (nach Stratifizierung) | **300** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **300** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **298** |
| Neu angenommene Feed-Dateien | **10** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **109** |
| Abgelehnte Repositories (dieser Run) | **298** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **119** |
| IPs in seen_db bestätigt | **2268298** |
| Neue IPs eingetragen | **103538** |
| seen_db gesamt | **7,752,535** |
| HQ-Referenz-IPs (6 Quellen) | **141752** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Sonstige | **260** |
| IP-Datei veraltet (>30d) | **15** |
| Repo zu alt (>30d) | **12** |
| Falsche Größe (<100 / >2,000,000 IPs) | **10** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 741 | 40.9% | 0.5% | 0 | 🆕 NEU |
| `configserverapps_service_blocklists_blocklist` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 49,226 | 42.5% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_level3` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 12,360 | 65.2% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_blacklist_today` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 9,778 | 78.1% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_rdp_365d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 9,034 | 55.4% | 0.0% | 10 | 🆕 NEU |
| `configserverapps_service_blocklists_highrisk` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 9,045 | 2.3% | 0.0% | 10 | 🆕 NEU |
| `leon406_subcrawler` | [Leon406/SubCrawler](https://github.com/Leon406/SubCrawler) | GITHUB | 109,995 | 0.1% | 0.0% | 1542 | 🆕 NEU |
| `officialputuid_proxyforeveryone` | [officialputuid/ProxyForEveryone](https://github.com/officialputuid/ProxyForEveryone) | GITHUB | 4,858 | 2.3% | 0.0% | 7 | 🆕 NEU |
| `officialputuid_proxyforeveryone_https` | [officialputuid/ProxyForEveryone](https://github.com/officialputuid/ProxyForEveryone) | GITHUB | 4,200 | 1.7% | 0.0% | 7 | 🆕 NEU |
| `officialputuid_proxyforeveryone_proxies` | [officialputuid/ProxyForEveryone](https://github.com/officialputuid/ProxyForEveryone) | GITHUB | 3,683 | 2.6% | 0.0% | 7 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `OpenOSINT/OpenOSINT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kaifcodec/user-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ioc-fang/ioc-fanger` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rohitcoder/hawk-eye` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NodeSecure/scanner` | GITHUB | IP-Datei 691d alt |
| `spmedia/Threat-Actor-Usernames-Scrape` | GITHUB | Größe: 0 IPs |
| `trickest/cve` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `openwrt-xiaomi/xmir-patcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mheidari98/.proxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `peasoft/NoMoreWalls` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alireza0/s-ui` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NiREvil/vless` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Mahdi0024/ProxyCollector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sub-store-org/Sub-Store` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `elesiuta/picosnitch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `osquery/osquery` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wazuh/wazuh-docker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wazuh/wazuh-ansible` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wazuh/wazuh-documentation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wazuh/wazuh-dashboard-plugins` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nextcloud/suspicious_login` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wolfSSL/documentation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PowerDNS/weakforced` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Luffy-del/Honeypot-Spam-Buster` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trickest/resolvers` | GITHUB | Overlap zu gering: 0.0% |
| `RozhakDev/Facemash` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `chainreactors/zombie` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `agourlay/zip-password-finder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `praetorian-inc/brutus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `saurabhwadekar/pycrack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spmedia/PhishingSecLists` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `skjolber/3d-bin-container-packing` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `roomcatchateau/Gmail-Tool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mrhenrike/MikrotikAPI-BF` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `joshspeagle/brutus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `anvaka/isect` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HeadyZhang/agent-audit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vinceAmstoutz/symfony-security-auditor` | GITHUB | Größe: 0 IPs |
| `vigolium/vigolium` | GITHUB | IP-Datei 42d alt |
| `artifact-keeper/artifact-keeper` | GITHUB | IP-Datei 35d alt |
| `0sec-labs/foxguard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OWASP/DockSec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `future-architect/vuls` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CERT-Polska/Artemis` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `acepanel/panel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `docker-mailserver/docker-mailserver` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MHSanaei/3x-ui` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sous-chefs/fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tomMoulard/fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `robertdebock/ansible-role-fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DigitalRuby/IPBan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `crazy-max/docker-fail2ban` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shukiv/jabali-panel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheDuffman85/crowdsec-web-ui` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ozark-Connect/NetworkOptimizer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `maxlerebourg/crowdsec-bouncer-traefik-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hhftechnology/crowdsec_manager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `crowdsecurity/crowdsec-docs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jasonish/evebox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jasonish/docker-suricata` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DCSO/balboa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DCSO/fever` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ccdcoe/CDMCS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sous-chefs/snort` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mwakidenis/Mpesa-Based_Wi-Fi-Hotspot_Billing_System` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Davie3/mikrotik-cloudflare-iplist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `2GT-Media-Group-LLC/mikrotik-manager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sakib-m/IP-Prefix-List` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nshttpd/mikrotik-exporter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mirceanton/external-dns-provider-mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rekryt/iplist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tomaae/homeassistant-mikrotik_router` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mirceanton/mikrotik-terraform` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `browningluke/terraform-provider-opnsense` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Opnwall/Mihomo-for-OPNsense` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `browningluke/opnsense-go` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `opnsense/docs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EvilBit-Labs/opnDossier` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `travisghansen/hass-opnsense` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `onzack/grafana-dashboards` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pfrest/pfSense-pkg-saml2-auth` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pfrest/pfSense-pkg-RESTAPI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gensecaihq/pfsense-mcp-server` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `duggytuxy/syswarden` | GITHUB | Größe: 0 IPs |
| `Derssa/Torollo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cloudnativelabs/kube-router` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `miniupnp/miniupnp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `heiher/hev-socks5-tproxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hknutzen/Netspoc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jaymzh/iptstate` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `htrgouvea/nipe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `qoomon/docker-host` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `x-way/iptables-tracer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Anipaleja/nginx-defender` | GITHUB | IP-Datei 343d alt |
| `pymumu/smartdns` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alexhaydock/pinewall` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `black-desk/cgtproxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `voxpupuli/puppet-nftables` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Pwnzer0tt1/firegex` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sepandhaghighi/samila` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dredozubov/hazmat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bl4ko/netbox-ssot` | GITHUB | Größe: 0 IPs |
| `prometheus-community/fortigate_exporter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `40net-cloud/fortinet-azure-solutions` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheTaylorLee/AdminToolbox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yuriskinfo/cheat-sheets` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fortinet/fortigate-terraform-deploy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vladimirs-git/fortigate-api` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eworm-de/routeros-scripts` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EvilFreelancer/docker-routeros` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ansible-collections/community.routeros` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `beeyev/Mikrotik-RouterOS-automatic-backup-and-update` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `danikf/tik4net` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `luqasz/librouteros` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tikoci/mikropkl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EvilFreelancer/routeros-api-php` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CA17/TeamsACS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Winds-Studio/Leaf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DreamVoid/MiraiMC` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FloatTech/ZeroBot-Plugin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Quan666/ELF_RSS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Colter23/bilibili-dynamic-mirai-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `YunYouJun/mirai-ts` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MadokaProject/Madoka` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GraiaProject/Ariadne` | GITHUB | Zu alt: 89d |
| `jstrosch/malware-samples` | GITHUB | Zu alt: 903d |
| `Da2dalus/The-MALWARE-Repo` | GITHUB | Zu alt: 923d |
| `Princekin/malware-database` | GITHUB | Zu alt: 1145d |
| `eset/stadeo` | GITHUB | Zu alt: 1699d |
| `ion-storm/emotet-malware-killer` | GITHUB | Zu alt: 2334d |
| `hasherezade/malware_analysis` | GITHUB | Zu alt: 274d |
| `fabrimagic72/malware-samples` | GITHUB | Zu alt: 1753d |
| `glockinhand/navi-multitool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `VisoXC/VisoRAT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mategol/PySilon` | GITHUB | Zu alt: 34d |
| `cisamu123/CyberEye` | GITHUB | Zu alt: 125d |
| `shadowctrl/crypto-miner` | GITHUB | Zu alt: 705d |
| `ylvachifu1992/Silent-Crypto-Miner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xmrig/xmrig` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lpsm-dev/docker-crypto-miner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gupax-io/gupax` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xmrig/xmrig-proxy` | GITHUB | Zu alt: 58d |
| `apache/creadur-rat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cryakl/Ultimate-RAT-Collection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ladysnake/RATs-Mischief` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vxaboveground/Overlord` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `iss4cf0ng/DuplexSpyCS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Hacker-nk/online-hackings` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Hacker-nk/online-hacking` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `loafiieee/Lo4f-Malware` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Pericena/Droidjack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `marlkiller/rust-desk-light` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bia-technologies/rat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MCSManager/MCSManager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ReaJason/MemShellParty` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `iss4cf0ng/NebulaPulsar` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `WangYihang/Webshell-Sniper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sagsooz/Webshell-bypass` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zhaojh329/rttys` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Joss-Steward/honeypotDisplay` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lcashdol/WAPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mycert/ESPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cymmetria/MTPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ivre/masscanned` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alexbredo/honeypot-ftp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yuchincheng/HpfeedsHoneyGraph` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `upa/ofpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `secureworks/dcept` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `andrewmichaelsmith/honeypot-setup-script` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ashmckenzie/go-sshoney` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fw42/honeymap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hbhzwj/imalse` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LogoiLab/honeyup` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MattCarothers/mhn-core-docker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kungfuguapo/HoneyPress` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `andrew-morris/kippo_detect` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `IllusiveNetworks-Labs/WebTrap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `johestephan/VerySimpleHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `honeynet/ghost-usb-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dmpayton/django-admin-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `desaster/kippo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GetPageSpeed/nginx-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `threatstream/shockpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0x4D31/galah` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eymengunay/EoHoneypotBundle` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dutchcoders/troje` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Phype/telnet-iot-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shiva-spampot/shiva` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `f0rw4rd/potsnitch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `madirish/kojoney2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aelth/ddospot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sahilm/hived` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `threatstream/mhn` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `freak3dot/wp-smart-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MalwareTech/CitrixHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hexgolems/schem` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Zeerg/helix-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `citronneur/rdpy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lnslbrty/potd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kryptoslogic/rdppot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tillmannw/honeytrap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Marist-Innovation-Lab/DolosHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cymmetria/weblogic_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `magisterquis/sshlowpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cryptix720/HUDINX` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `androguard/androguard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dtag-dev-sec/tpotce` | GITHUB | Größe: 0 IPs |
| `katkad/Glastopf-Analytics` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `schmalle/Nodepot` | GITHUB | IP-Datei 4069d alt |
| `schmalle/servletpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mushorg/conpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fnzv/YAFH` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `UHH-ISS/honeygrove` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0x4D31/honeyku` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cymmetria/StrutsHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mariocandela/beelzebub` | GITHUB | IP-Datei 72d alt |
| `WebDecoy/wordpress-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DataSoft/Nova` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yunginnanet/HellPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jedie/django-kippo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `czardoz/hornet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cymmetria/ciscoasa_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RevengeComing/DemonHunter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mushorg/glutton` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `packetflare/amthoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CERT-Polska/HSN-Capture-HPC-NG` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tnich/honssh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `joda32/owa-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `huuck/ADBHoney` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `torque59/nosqlpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `oguzy/ovizart` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shbhmsingh72/Honeypot-Research-Papers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `traetox/sshForShits` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jesparza/peepdf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gregcmartin/Kippo_JunOS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mushorg/glastopf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hgascon/acapulco` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jordan-wright/elastichoney` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sefcom/honeyplc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SneakersInc/HoneyMalt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gfoss/phpmyadmin_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cypwnpwnsocute/RedisHoneyPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ajackal/arctic-swallow` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CHH/stack-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `buffer/thug` | GITHUB | IP-Datei 1278d alt |
| `schmalle/MysqlPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cossacklabs/acra` | GITHUB | IP-Datei 663d alt |
| `christophe77/express-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ayrus/afterglow-cloud` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `balte/TelnetHoney` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rep/hpfeeds` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pjlantz/Hale` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jaksi/sshesame` | GITHUB | IP-Datei 1839d alt |
| `shjalayeri/pwnypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mushorg/snare` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `knalli/honeypot-for-tcp-32764` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SentryPeer/SentryPeer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `inguardians/toms_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `darkarnium/kako` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dapperdivers/dapper-cluster` | GITHUB | Größe: 0 IPs |
| `itcmsgr/nftban` | GITHUB | IP-Datei 40d alt |
| `RUTHRAN-SEC/Cloud-Security-Monitoring-Hardening-in-AWS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nasenov/homelab` | GITHUB | IP-Datei 48d alt |
| `Tanguille/cluster` | GITHUB | Größe: 0 IPs |
| `Katirinata/CMD-Exploit-CVE-2024-RCE-AboRady-FUD-25765-Injection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `janennacircumpolar374/repo-intel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Janealm7195/NWO-Analyse-Recherche-Stalking-Mobbing-Cyberraum` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Radcliffeinsubordinate572/youtube-poop-video-maker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xcii-heaviness774/yes.md` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wqh7798/Slay-the-Spire-2-Drawing` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `showy-headteacher114/cve-2025-66398` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jasonpanosso/selfhosted` | GITHUB | IP-Datei 69d alt |
| `xbxh6452/-ARP-Spoofing-Detection-Active-Injection-Technique` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Isolable-confutation802/TraceAnalyzer-main` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dwoitzik/homelab-infrastructure` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GnomeMan4201/GnomeMan4201` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Stripmined-reflation431/testing-business-ideas-with-claude` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `armmammothermography417/ContextOS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vestalterrace911/python-check-updates` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TerNiqkaE/Proxy-HTTP-SOCKS-Get-Pool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `brunnels/home-ops` | GITHUB | Größe: 0 IPs |
| `demnalatsabidze-arch/GhostBullet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `securenza/SecurityFeed` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mchestr/home-cluster` | GITHUB | IP-Datei 253d alt |
| `dada63924/deribit-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Trustbustinggleefulness546/Argus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bilkulsahi1235/agent-egress-bench` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aktfyjnzy-ui/cloud-honeynet-aws` | GITHUB | IP-Datei 119d alt |
| `heavybullets8/heavy-ops` | GITHUB | IP-Datei 248d alt |
| `soapbucket/sbproxy` | GITHUB | Größe: 0 IPs |
| `ayushgowda121/opencode-anthropic-oauth` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xunholy/k8s-gitops` | GITHUB | Größe: 0 IPs |
| `RogoLabs/cve.icu` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Hgghllliji/MikroDash` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cybersparks/Threat-Intel-Feeds` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ishika-0101/entropy-chaos` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `elsalitasafitri21/v2.0` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `isra-osvaldo/Evasion-SubAgents` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | GITHUB | 10,622 | 75.0% | 4721 | 2026-05-28 |
| `cbuijs_hagezi` | GITHUB | 46,339 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 25,288 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,067 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 3,144 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,613 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 627 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 17,497 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 502 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 300 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,200 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,568 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,517 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,924 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 4,408 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 4,027 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https_anonymous` | GITHUB | 4,129 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 3,289 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,464 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 1,004 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 924 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 804 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 504 | 12.8% | 60 | 2026-07-04 |
| `leon406_subcrawler` | GITHUB | 109,995 | 0.1% | 1542 | 2026-07-04 |
| `cbuijs_accomplist` | GITHUB | 99,805 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,444 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 101,092 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 110,137 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 628 | 36.7% | 8 | 2026-07-03 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,478 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,142 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 172,824 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 137,930 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 92,874 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 87,651 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 93,010 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_30d` | GITHUB | 84,307 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 84,712 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 64,890 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 47,820 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_15d` | GITHUB | 47,135 | 47.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 42,448 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 30,859 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 21,707 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 24,781 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 22,287 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 18,907 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 16,250 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 15,215 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,228 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 49,226 | 42.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 12,360 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 9,778 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 9,034 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 9,045 | 2.3% | 10 | 2026-07-04 |
| `officialputuid_proxyforeveryone` | GITHUB | 4,858 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 4,200 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 3,683 | 2.6% | 7 | 2026-07-04 |
| `turntuptechnologies_iocs` | GITHUB | 29 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 52,227 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 94,256 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,578 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 121 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 221,020 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,872 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,678 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 6,988 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 7,263 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 166,003 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 1,984 | 21.9% | 1 | 2026-07-04 |
| `idleadmin_threatfeed` | GITHUB | 51,321 | 41.9% | 0 | 2026-04-09 |
| `turbolabit_zzfirewall` | GITHUB | 99,140 | 66.4% | 0 | 2026-05-03 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 45,915 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,534 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 111,134 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 525 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,168 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 191,733 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,461 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 112,223 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 111,001 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,235 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 32,107 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 493 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 19,953 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 15,367 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,793 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 7,411 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,488 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cps_abusech` | GITHUB | 7,607 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,693 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,649 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 3,958 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,622 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,120 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,534 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 3,483 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,741 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 3,355 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,313 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 2,004 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,425 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_socks_proxy_7d` | GITHUB | 1,461 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,354 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,263 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,204 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,179 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,116 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 980 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,238 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,214 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 842 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 924 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 887 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 741 | 40.9% | 0 | 2026-07-04 |

---
*Generiert: 2026-07-04 16:08 UTC*