# Auto Feed Discovery – Report
**Aktualisiert:** 2026-10-04 12:45 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **11571** |
| davon GitHub (Topics+Code) | **11479** |
| davon GitLab | **92** |
| davon Awesome-Lists | **2399** |
| Tools/Libraries vor Eval gefiltert | **1578** |
| davon Hard-Reject (awesome-Liste etc.) | **187** |
| EVAL-Kandidaten (nach Stratifizierung) | **461** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **461** |
| davon angenommene Repositories | **0** |
| davon abgelehnte Repositories | **461** |
| Neu angenommene Feed-Dateien | **4** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **194** |
| Abgelehnte Repositories (dieser Run) | **461** |
| davon GitLab abgelehnt | **1** |
| Feeds gesamt (aktiv) | **198** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **144099** |
| SQLite-Refresh-Cache-Hits | **4/198** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **331** |
| IP-Datei veraltet (>30d) | **62** |
| Repo zu alt (>30d) | **47** |
| Falsche Größe (<30 / >2,000,000 IPs) | **20** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_cps_log4j` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 25,278 | 6.8% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,415 | 63.9% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_tor_exits` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 1,398 | 64.5% | 0.0% | 0 | 🆕 NEU |
| `claudiusdecimius_ioc_ipsets_sblam` | [ClaudiusDecimius/ioc-ipsets](https://github.com/ClaudiusDecimius/ioc-ipsets) | GITHUB | 1,162 | 26.8% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `sandbox-quantum/switch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `silversword411/GRC_SecurityNow_Files` | GITHUB | Zu alt: 159d |
| `platformbuilds/SpamhausIPLists` | GITHUB | Zu alt: 950d |
| `ErcinDedeoglu/crypto-market-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ErcinDedeoglu/WhisperDock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wolffcatskyy/crowdsec-unifi-bouncer` | GITHUB | Größe: 0 IPs |
| `wolffcatskyy/crowdsec-blocklist-import` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecureWithUmer/Exploit-Index` | GITHUB | IP-Datei 88d alt |
| `777genius/social-monitor` | GITHUB | IP-Datei 64d alt |
| `activecm/rita` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `grisuno/LazyOwn` | GITHUB | IP-Datei 72d alt |
| `kdfgjijkdtfh-cmyk/AQW-Packet-Insight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `justcallmekoko/ESP32Marauder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cyanfish/naps2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `librats/rats-search` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manuc66/node-hp-scan-to` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrjackwills/havn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RetireJS/retire.js` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `doo/scanbot-sdk-example-web` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ramonvermeulen/whosthere` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `doo/scanbot-sdk-example-android` | GITHUB | IP-Datei 577d alt |
| `doo/scanbot-sdk-example-ios` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ossappscollective/OSS-DocumentScanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shadow1ng/fscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maravento/blackip` | GITHUB | IP-Datei 460d alt |
| `Homas/ioc2rpz` | GITHUB | IP-Datei 158d alt |
| `pengakuza/seed-phrase-generator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ninoseki/mihari` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elastic/detection-rules` | GITHUB | Größe: 0 IPs |
| `sublime-security/sublime-rules` | GITHUB | Größe: 0 IPs |
| `ethack/tht` | GITHUB | IP-Datei 1583d alt |
| `osintbrazuca/osint-brazuca` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dpmb/dpmb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aleksibovellan/opnsense-suricata-nmaps` | GITHUB | Zu alt: 328d |
| `mhyrzt/xrat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qr243vbi/nekobox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ProxyPanel/ProxyPanel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hidden-Node/proxy-builder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `seramo/v2ray-config-modifier` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `youshandefeiyang/sub-web-modify` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jichangzhu/JichangTuijian` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wobqqq/oc-fortify-smart-ip-blocker-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FCSC-FR/shovel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecOps-7/MikroDash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hotspotbilling/phpnuxbill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `buananetpbun/buananetpbun.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EvilFreelancer/docker-routeros` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pfelk/pfelk` | GITHUB | IP-Datei 1280d alt |
| `firewalld/firewalld` | GITHUB | IP-Datei 5142d alt |
| `splify2/steer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `onyks-os/TransparentTorProxy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jstrosch/malware-samples` | GITHUB | Zu alt: 995d |
| `Princekin/malware-database` | GITHUB | Zu alt: 1237d |
| `shadowctrl/crypto-miner` | GITHUB | Zu alt: 797d |
| `cisamu123/CyberEye` | GITHUB | Zu alt: 217d |
| `Tocsiop/R8HEX` | GITHUB | Zu alt: 407d |
| `Cr4sh/s6_pcie_microblaze` | GITHUB | Zu alt: 211d |
| `tgmtproxy/telegram-mtproto-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sherlock-project/sherlock` | GITHUB | IP-Datei 563d alt |
| `K2SOsint/Legendary_OSINT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stnolting/neorv32` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `j3ssie/osmedeus` | GITHUB | IP-Datei 57d alt |
| `nikitastupin/orgs-data` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zyrexnn/Cybermes` | GITHUB | IP-Datei 46d alt |
| `KatrielMoses/MailAccess` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GTFOBins/GTFOBins.github.io` | GITHUB | Zu alt: 130d |
| `lolexfil/lolexfil.github.io` | GITHUB | Zu alt: 148d |
| `ingres-si/caddy-proxy-manager` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lancard/nginx-webui` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x86byte/Stuxnet-Rootkit` | GITHUB | Zu alt: 750d |
| `Ares-X/VulWiki` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `greyhat-academy/lists.d` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `emanuele-em/proxelar` | GITHUB | IP-Datei 71d alt |
| `biandratti/huginn-net` | GITHUB | Größe: 0 IPs |
| `NYAN-x-CAT/njRAT-0.7d-Stub-CSharp` | GITHUB | Zu alt: 2576d |
| `001123/lab-ipxe-os` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nicolerenee/infra` | GITHUB | Größe: 0 IPs |
| `rafaribe/home-ops` | GITHUB | IP-Datei 362d alt |
| `mchestr/home-cluster` | GITHUB | IP-Datei 345d alt |
| `dfroberg/cluster` | GITHUB | IP-Datei 1847d alt |
| `qjoly/GitOps` | GITHUB | IP-Datei 64d alt |
| `budimanjojo/home-cluster` | GITHUB | IP-Datei 240d alt |
| `hcloud-k8s/terraform-hcloud-kubernetes` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xunholy/k8s-gitops` | GITHUB | Größe: 0 IPs |
| `Terra-Online/Atlos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zimmertr/TJs-Kubernetes-Service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anthr76/infra` | GITHUB | IP-Datei 308d alt |
| `qjoly/talosctl-oidc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Luzilla/dnsbl_exporter` | GITHUB | IP-Datei 354d alt |
| `matteocorti/check_rbl` | GITHUB | Zu alt: 188d |
| `dmippolitov/pydnsbl` | GITHUB | Zu alt: 558d |
| `rhaym-tech/Exploits` | GITHUB | Zu alt: 211d |
| `sammwyy/R2SAE` | GITHUB | Zu alt: 302d |
| `miyagaw61/exgdb` | GITHUB | Zu alt: 902d |
| `jollheef/lpe` | GITHUB | Zu alt: 2118d |
| `ins1gn1a/Frampton` | GITHUB | Zu alt: 2506d |
| `XiaoRavpa/IP-STRESSER` | GITHUB | Zu alt: 60d |
| `nocturne-cybersecurity/Nocturne-Attack` | GITHUB | Zu alt: 156d |
| `filippofinke/layer7-dstat` | GITHUB | Zu alt: 1578d |
| `sepehrdaddev/Xerxes` | GITHUB | Zu alt: 2311d |
| `Suraj151/pdi-framework` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `daq-tools/kotori` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jonnor/embeddedml` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `happytm/BatteryNode` | GITHUB | Zu alt: 111d |
| `hiveeyes/terkin-datalogger` | GITHUB | Zu alt: 1401d |
| `LSIR/gsn` | GITHUB | Zu alt: 1748d |
| `smerdov/eSports_Sensors_Dataset` | GITHUB | Zu alt: 2155d |
| `waydabber/BetterDisplay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dCache/oncrpc4j` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `niklasr22/BrightIntosh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `itshamzabendelladj/AIGuardSIEM` | GITHUB | Zu alt: 73d |
| `alin23/Lunar` | GITHUB | Zu alt: 82d |
| `socprime/Uncoder_IO` | GITHUB | Zu alt: 86d |
| `NoobishSVK/fm-dx-webserver` | GITHUB | Zu alt: 176d |
| `lawndoc/AdvancedHuntingQueries` | GITHUB | Zu alt: 236d |
| `bgenev/impulse-xdr` | GITHUB | Zu alt: 255d |
| `starkdmi/BrightXDR` | GITHUB | Zu alt: 291d |
| `Maarckz/Inventory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LunarWerxs/AgentHydra` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sk2andy/candy-browser` | GITHUB | IP-Datei 75d alt |
| `bilalpeera86/claude-session-flow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sdogruyol/gcry` | GITHUB | IP-Datei 59d alt |
| `NetizenNemo/Aether_OptExt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Soniavasseur/Wallet-Risk-Scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kejiland/qingyu-blog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omacom/omarchy-plugin-marketplace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sujal708/Bluestacks-5-Kitsune-Root` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tarboh/S-MU2000` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `openpi-dev/openpi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LivXue/dsh-plugin-shop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cocofhu/grasp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `igttttma/GTA_auto_hack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alumarobalino/lumma-trace-forensics` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zXfantasmaXz/solar-harvest-arena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aminekago-web/Paradigm-Survival-Arena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kc1t/alethe-agents` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaha33166-a11y/Endfield-Trainer-Suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stof-dorof/fretwise-listener` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `govinda25072003-ai/pbi-amazon-sales-dash` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jianruntech/geo-score` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cporter202/coreclaw-api-directory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Correia-jpv/fucking-open-source-mac-os-apps` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Correia-jpv/fucking-about-SwiftUI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `actuallymentor/battery` | GITHUB | Zu alt: 221d |
| `axllent/mailpit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `axllent/mailpit-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `axllent/wireguard-vanity-keygen` | GITHUB | Zu alt: 95d |
| `axllent/silverstripe-version-truncator` | GITHUB | Zu alt: 540d |
| `hslatman/caddy-crowdsec-bouncer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jgamblin/KEV_EPSS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jgamblin/OpenClawCVEs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jgamblin/monthlyCVEStats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jgamblin/CVElk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jgamblin/isthisipbad` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jgamblin/MacOS-Config` | GITHUB | Zu alt: 66d |
| `jgamblin/quickinstall` | GITHUB | Zu alt: 67d |
| `jgamblin/MacOS-Maid` | GITHUB | Zu alt: 158d |
| `jgamblin/Mirai-Source-Code` | GITHUB | Zu alt: 353d |
| `rshipp/python-nut2` | GITHUB | Zu alt: 1602d |
| `rshipp/webNUT` | GITHUB | Zu alt: 2009d |
| `rshipp/python-codacycov` | GITHUB | Zu alt: 2303d |
| `0x1uke/lurker` | GITHUB | Zu alt: 191d |
| `EC-DIGIT-CSIRC/credentialLeakDB` | GITHUB | Zu alt: 1230d |
| `mitre/cti` | GITHUB | IP-Datei 60d alt |
| `Neo23x0/signature-base` | GITHUB | IP-Datei 34d alt |
| `cuckoosandbox/cuckoo` | GITHUB | IP-Datei 3432d alt |
| `cert-se/megatron-java` | GITHUB | IP-Datei 4836d alt |
| `CyberMonitor/APT_CyberCriminal_Campagin_Collections` | GITHUB | IP-Datei 1621d alt |
| `STIXProject/openioc-to-stix` | GITHUB | IP-Datei 4722d alt |
| `syphon1c/Threatelligence` | GITHUB | IP-Datei 4506d alt |
| `blaverick62/SIREN` | GITHUB | IP-Datei 3123d alt |
| `SAP/cloud-active-defense` | GITHUB | IP-Datei 164d alt |
| `buffer/thug` | GITHUB | IP-Datei 1370d alt |
| `InnerWarden/innerwarden` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jaksi/sshesame` | GITHUB | IP-Datei 1931d alt |
| `GovCERT-CZ/Wordpot-Frontend` | GITHUB | IP-Datei 3981d alt |
| `robertdavidgraham/telnetlogger` | GITHUB | IP-Datei 3627d alt |
| `morian/blacknet` | GITHUB | IP-Datei 1112d alt |
| `rabbitstack/fibratus` | GITHUB | IP-Datei 422d alt |
| `cossacklabs/acra` | GITHUB | IP-Datei 755d alt |
| `mariocandela/beelzebub` | GITHUB | Größe: 0 IPs |
| `GovCERT-CZ/Shockpot-Frontend` | GITHUB | IP-Datei 3988d alt |
| `schmalle/Nodepot` | GITHUB | IP-Datei 4161d alt |
| `InQuest/python-sandboxapi` | GITHUB | IP-Datei 1081d alt |
| `ispras/qemu` | GITHUB | IP-Datei 3489d alt |
| `horsicq/Nauz-File-Detector` | GITHUB | IP-Datei 572d alt |
| `idaholab/Malcolm` | GITHUB | IP-Datei 48d alt |
| `smicallef/spiderfoot` | GITHUB | IP-Datei 1643d alt |
| `taranis-ai/taranis-ai` | GITHUB | Größe: 0 IPs |
| `kpcyrd/sn0int` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KatrielMoses/voidaccess` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `laramies/theHarvester` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `log2timeline/plaso` | GITHUB | IP-Datei 1443d alt |
| `airbnb/streamalert` | GITHUB | IP-Datei 2381d alt |
| `libyal/winreg-kb` | GITHUB | IP-Datei 1443d alt |
| `countercept/chainsaw` | GITHUB | IP-Datei 693d alt |
| `SigmaHQ/sigma` | GITHUB | IP-Datei 312d alt |
| `matanolabs/matano` | GITHUB | IP-Datei 1219d alt |
| `phantomcyber/playbooks` | GITHUB | IP-Datei 443d alt |
| `OTRF/ThreatHunter-Playbook` | GITHUB | IP-Datei 1482d alt |
| `JPCERTCC/SysmonSearch` | GITHUB | IP-Datei 2951d alt |
| `olafhartong/sysmon-modular` | GITHUB | IP-Datei 1559d alt |
| `sublime-security/sublime-platform` | GITHUB | IP-Datei 1346d alt |
| `deepfence/PacketStreamer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codeyourweb/fastfinder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bountyyfi/lonkero` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oasis-open/cti-python-stix2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AltraMayor/gatekeeper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drduh/macOS-Security-and-Privacy-Guide` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ninoseki/mitaka` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `x64dbg/yarasigs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `volexity/threat-intel` | GITHUB | IP-Datei 1089d alt |
| `hvs-consulting/ioc_signatures` | GITHUB | IP-Datei 1637d alt |
| `intezer/yara-rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cisco-Talos/IOCs` | GITHUB | IP-Datei 1228d alt |
| `reversinglabs/reversinglabs-yara-rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `botherder/targetedthreats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elastic/protections-artifacts` | GITHUB | IP-Datei 31d alt |
| `bonnetn/vba-obfuscator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mentebinaria/retoolkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `adulau/active-scanning-techniques` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iosiro/baserunner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OWASP/NodeGoat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xSobky/Regaxor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EricZimmerman/KapeFiles` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vaguileradiaz/tinfoleak` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `REhints/Publications` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `felixweyne/imaginaryC2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Arno0x/DivertTCPconn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3xpl01tc0d3r/ProcessInjection` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NVISOsecurity/MagiskTrustUserCerts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `i3visio/usufy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Top-Hat-Sec/thsosrtl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sharkdp/hexyl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `opnsense/core` | GITHUB | IP-Datei 70d alt |
| `chrisallenlane/novahot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `facebookincubator/python-nubia` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RUB-SysSec/syntia` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ZephrFish/DockerAttack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s4n7h0/Practical-Reverse-Engineering-using-Radare2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NickstaDB/SerializationDumper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bohops/WSMan-WinRM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bytebutcher/decoder-plus-plus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrphrazer/r2con2020_deobfuscation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bagder/http2-explained` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `woj-ciech/Kamerka-GUI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microsoft/ProcDump-for-Linux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hypfer/Valetudo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mitre-attack/attack-scripts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dbohdan/structured-text-tools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrew-d/static-binaries` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Netflix/security-bulletins` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ganapati/RsaCtfTool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `microsoft/New-KrbtgtKeys.ps1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `detroitenglish/pw-pwnage-cfworker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cispa/osiris` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lgandx/Responder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ernw/hardening` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `marcnewlin/presentation-clickers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GrrrDog/weird_proxies` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chesire-cat/smbAutoRelay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `helviojunior/shellcodetester` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `liamg/tfsec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CATx003/opsec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mkearney/resist_oped` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bradwood/glsnip` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DissectMalware/pyxlsb2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `intelstormteam/Papers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `quarkslab/QBDI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `liyasthomas/postwoman` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BishopFox/zigdiggity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uds-se/fuzzingbook` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `H1R0GH057/Anonymous` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DimopoulosElias/alpc-mmc-uac-bypass` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MichaelGrafnetter/DSInternals` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nickvourd/Windows-Local-Privilege-Escalation-Cookbook` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CCob/SylantStrike` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `richardjrossiii/iOSAppInAssembly` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Microsoft/SpeculationControl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SimplySecurity/SimplyTemplate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `volatilityfoundation/profiles` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diego-treitos/linux-smart-enumeration` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `herrfeder/PandocPentestReport` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:bloodhunterd-labs/tools/pi-hole-blocklists-deletion_scheduled-51902190` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nazca13/PulseHQ` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AliTalhaOruc/autonomous_security` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nsozturk/cve-threat-intelligence-hub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aryaman0906/project-irl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alijonzardov97-cmyk/TS-NEW` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ARoyalcoder/pawanputraakhandbharatprivatelimited` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `erikalmeidakaos/speed-monkey-escape-timing-helper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aindrila123glitch/ECOEAR1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gni/maquis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kharbashpriyanshu/ForenSight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `YellowFoxH4XOR/f5data` | GITHUB | Größe: 0 IPs |
| `ujwalsingh2026-igl/Ai_project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mikedisdimitris-debug/archon-technology-intelligence-distribution` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nulvex-Security/nulvex-detections` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Samar0-star/sol-inquisitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `finklousennessa914/Last-Hope-Zombie-Sniper-3d-Full-Version-Unlocked` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nschawla/a2r-dos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mahmoud217TR/Vaultsort` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ridwanyazid13/Total-Security-Xtreme-Optimizer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `certpilot/certpilot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `justinahiggins614-cmyk/cyber-patent-catalog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ayhanjasbi/RogueKiller-15-12-0-Utility` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mahitss/Arc_micro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `callum87-Lab/Ka-Ching` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Muhipo-Dev/simasmuh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `furkanyesildag/cogladius` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AvinashMalladi/zen_ai_assistant` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rahulrkr95/Rachna-Desktop` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bolknote/Register` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sawalreuu/sihadir` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Harshitahusts/GRC-Ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ARP224/ArtificialGirlfriend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ingo-eichhorst/factory` | GITHUB | Größe: 0 IPs |
| `idoadjadjajdada/Orbital` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vishwateja0411/Eventhub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rameshjavali/fleetops` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LSUDOKO/CargoFlow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MakazhanAlpamys/soup-wall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ahma-labs/ahma` | GITHUB | Größe: 0 IPs |
| `bytx88/meme-fast` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TamarindValleyCollective/website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Allmight2002/Gestion-de-donn-es-m-dicales` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `heydrsubha-del/SMART-INDIA-HACKATHON-PROJECT-26106` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aarya-lahamage/find-the-intruder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sola21/solahelm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vivekray898/safartour` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cafaye/kit` | GITHUB | Größe: 0 IPs |
| `newarsamir/Freefire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bubbub2025-coder/techivation-m-de-esser-2-edition` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bangash40/portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hamicod/web-app` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `koppensb/ai-stack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ClairVoyanceMedium/pgi-telecom-audiotelpremiumpro.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `M-o-m-e-n/Momkn-pay-backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmmmmDeee/HSE-BLE-API-` | GITHUB | Größe: 0 IPs |
| `dortort/wawarden` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andikaputradev/wedding-invitation-nextjs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zay8t/MYEYES_STORE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pratikdesai472006/SHAPNEST_1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Adrien-Leteinturier/gaming-copilot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uusa98351-web/uvk-ultra-vk-11-10-11-0-release` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `boostengine001/packages` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pvpchouaib-art/bitdefender-total-security-27-0-30-release` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Staid01/7` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pinku1502/cyberThreatDetectionDashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Krishankumar674/bitwiper-data-eraser-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jma49/Open-CR-Agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `digitaleflex/hashcode_reboot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `muzzascan-creator/pallet-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magnus919/SlopSearX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beanpool-org/beanpool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `slimissa/exchange-calendar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeylabshq/akin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mithunchandrasutradhar/asset-management-module-perfexcrm` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drsumaiya/drsumaiya.com-upptime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `parsasohrab1/inno-Jam-Petrochemical-polymerization-digitwin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DPS-Turkiye/product-studio-landing` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Kaustubh-Barad-007/vette` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ajayeeesolutions-lang/SPK-KPR-SMART-Method-Web-Application` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zimin0/CureMe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `benmarte/talos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `proxmint/free-proxy-list` | GITHUB | Overlap zu gering: 2.7% |
| `zkasuran/nightjar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SeCherkasov/SkerrySSH` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trikko/neverstored` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `basitalisandhu/llm-agent-control-plane` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lazyxu/xdrive` | GITHUB | Größe: 0 IPs |
| `converse231/dexora` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fenics555/creo-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tallpbx/tallpbx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FanOfLitov/JavaGuard-IPS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Nagaram-Kridey/QR-transfer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JHP0418/taxax-legal-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kaiizer777/SIH26146` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fuyuki0/unlimitedpipe-feeds` | GITHUB | Größe: 0 IPs |
| `parsasohrab1/Mili-Multi-Mode-Adaptive-Decision-System` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arumes31/noxa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ramravitej/Cura` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maan-oss/Better-India-Defence` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FlairAutoMate/era-story` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Omerhrr/AnimeOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rekusissu/registrar-ai-system` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dheeraj-lonely/cybervault-project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ZackSecurity/Zack-LocalScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cs1504900-cloud/PDF-Shield-Utility` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `michaldaniszewski03-hash/sidekick` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Mjonirdesi/gullfoss-theory-emulator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SalimB-source/Let-s-Play` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `happyc0der/gtnh-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bellonbits/aqivo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ronasimi/mcp-gateway` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `optest2345v/SIH26146` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dbrckk/xbow-perso` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `haranguearraign-325/Among-Shadows-Beta-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hnmasiya/cybersecurity-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ExiledPortals/ExiledSector` | GITHUB | Größe: 0 IPs |
| `Mubashir4564/uxpin-pro-edition-full` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rodriguesDEVcmd/yamicsoft-windows10-manager-pro-ultimate-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ShaDevPro/O-R-B-I-S-net` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MarcelWeissgerberIT/SimpleCMS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mboworks/xff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitRedSThub/WorldCenter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `medhu0505/quantum-ascent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Anshika55861/analysis_ai_project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lutfiwidianto/x-finder-releases` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rfxn/responder-tx` | GITHUB | Größe: 0 IPs |
| `jaxxtrend/faf-dualgap-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ProofOfTechOrg/anchorage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ismail-2001/AI-support-operations-platform-for-Shopify-stores` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `junaid08697/eset-security-v880-custom-release` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vizsh/Jarvis_Hedge_Fund` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `antrathent-sys/Chill-Grill-DroneNet` | GITHUB | Größe: 0 IPs |
| `Rakintoch/crypto-screener` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dnpp73/vsix-supply-chain-scan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `P-Max168/thai-news-kr` | GITHUB | Größe: 0 IPs |
| `absolutezero-25/Dark-Void` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HOANGGLEEE/Messenger1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `surkhettimes05-boop/saanjh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bitNtech/Bitntechmain` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sankar243/Cybersecurity-Daily-News` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tafa47/gv-edius-workflow-experiment` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arhancanli/canlicapital` | GITHUB | Größe: 0 IPs |
| `prashanta-dev7/blog-agent-v2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CEODRIF/ausbildung-hunter-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nocturney/velvetos-core` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RagePeanut/babelarr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `websale734-cpu/trade-in-orbit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `badboy1959/I-Know-This` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Seven-creater/agentic-video` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `desienkz-slp/sentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `garb-heap74/Wardens-of-Avalon-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `moraines-81129-sancta/Cleaner-Company-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Easyere/cubacadabra-wasm-runtime` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Jersyfi/hubtask` | GITHUB | IP-Datei 48d alt |
| `realibrahimsql/Gocat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sundries-634galling/Mirage-Rebellion-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Swenty0/wifi-guard-pro-tools` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bony0-madrasa/KVLT-Devlog-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dweadon/prooflog` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pintoale2002/zenmap-v7.95.0-analysis-tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dilates/beaconwatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iyas-muzakki/avast-security-pro-24.5.6115` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Stoppedwumm/WII-UU` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `niathackathon3-debug/btc-pathfinder-pro-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HuyXCheckerx/arbbotstable` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `blandest-liner22392/Curious-Sorceress-Grimoire-Of-Sex-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sayali1357/SalesIQ` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tang-vu/keryx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SmittyWerbenn/tracking-system` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kosar2410/Telegram-Desktop-Delight` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aloganferiii/eset-security-generator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Samarth-Chaudhary/creditbridge` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Project-NIC/NIC-Heimdall` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lloir/gt-tampermonkey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fleur41/FluxPay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `davvoz/magic8-tcg` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atik65/Digital-Product-Selling-System-Backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 7,967 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 16,398 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 10,278 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 5,036 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,859 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,753 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,743 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,934 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,950 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,519 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,061 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,083 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 652 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 504 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 507 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 449 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 249 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,209 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,575 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 18,735 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 11,454 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 7,202 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,996 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 5,284 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 213,504 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,278 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 4,786 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,639 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 2,836 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,717 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 11,778 | 64.3% | 938 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 53,368 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,971 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,616 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 116,968 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 91,537 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,161 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,906 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 107,045 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,667 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 93,184 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,628 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 117,304 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 621 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 471,181 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,515 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 172,910 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 155,639 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 137,778 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 159,558 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 77,437 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 109,058 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 76,639 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 243,896 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 43,201 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 187,679 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 17,095 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 10,434 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 21,299 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 4,974 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 15 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 178,574 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 11,693 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 11,694 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,711 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 22,423 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 14,137 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 11,755 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 7,562 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,192 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 11,432 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,617 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,467 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 1,295 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 4,628 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 2,571 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,299 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,627 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 111,771 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,019 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 27,198 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,693 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 4,019 | 79.4% | 10 | 2026-09-24 |
| `ian_lusule_proxies` | GITHUB | 3,405 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,492 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,526 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 372,875 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 7,922 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 6,787 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 7,396 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,572 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 92 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 99,429 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 89,551 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,702 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 115 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 89,137 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,914 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,688 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 280 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 18,144 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 17,878 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 23,055 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,371 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 39,918 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 64,602 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,869 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 109,705 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 376 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,168 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 195,943 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,537 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 109,695 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 208,483 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,103 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,237 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 32,377 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 494 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 9,040 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 16,495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,721 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 8,845 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,086 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,631 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 6,013 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,460 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,115 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,529 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 3,731 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,834 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 1,397 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 4,061 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,112 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,396 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,381 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,321 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,348 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,188 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,192 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,538 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,159 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,547 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 714 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,385 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,760 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,182 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 10,745 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 92,453 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 91,688 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 92,445 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 90,793 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 92,561 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 94,531 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 90,272 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 22,706 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 25,454 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 11,418 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 4,022 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,621 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,020 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 53,251 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 30,704 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 11,403 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 17,177 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 30 | 63.9% | 0 | 2026-08-12 |
| `zgzyh_malicious_website_detection` | GITHUB | 30,771 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 5,019 | 54.9% | 0 | 2026-08-23 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,190 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 16,404 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 4,837 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,619 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 1,062 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 242 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 238 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 6,006 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 91,733 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 94,027 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 90,987 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 87,762 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 90,650 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 27,324 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 1,612 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 1,594 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_20` | GITHUB | 184 | 92.3% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 405 | 76.9% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_2026_09_24` | GITHUB | 157 | 90.4% | 0 | 2026-09-25 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,278 | 6.8% | 0 | 2026-10-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,415 | 63.9% | 0 | 2026-10-04 |
| `claudiusdecimius_ioc_ipsets_tor_exits` | GITHUB | 1,398 | 64.5% | 0 | 2026-10-04 |
| `claudiusdecimius_ioc_ipsets_sblam` | GITHUB | 1,162 | 26.8% | 0 | 2026-10-04 |

---
*Generiert: 2026-10-04 12:45 CEST (Europe/Berlin)*