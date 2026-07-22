# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-22 20:13 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7843** |
| davon GitHub (Topics+Code) | **7773** |
| davon GitLab | **70** |
| davon Awesome-Lists | **1021** |
| Tools/Libraries vor Eval gefiltert | **1273** |
| davon Hard-Reject (awesome-Liste etc.) | **134** |
| EVAL-Kandidaten (nach Stratifizierung) | **200** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **200** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **199** |
| Neu angenommene Feed-Dateien | **9** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **150** |
| Abgelehnte Repositories (dieser Run) | **199** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **159** |
| IPs in seen_db bestätigt | **2568896** |
| Neue IPs eingetragen | **383751** |
| seen_db gesamt | **12,642,568** |
| HQ-Referenz-IPs (6 Quellen) | **114532** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Sonstige | **153** |
| IP-Datei veraltet (>30d) | **34** |
| Falsche Größe (<100 / >2,000,000 IPs) | **14** |
| Repo zu alt (>30d) | **3** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `kraloveckey_ipsets_blocklist_cps_log4j` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 25,279 | 6.5% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_maltrail_scanners` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 16,854 | 14.9% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_iblocklist_cruzit_web_attacks` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 13,871 | 0.5% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 5,631 | 5.0% | 0.0% | 0 | 🆕 NEU |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | [kraloveckey/ipsets-blocklist](https://github.com/kraloveckey/ipsets-blocklist) | GITHUB | 1,127 | 24.2% | 0.0% | 0 | 🆕 NEU |
| `ziyadnz_threat_intel_ip_feeds_ipv4_blacklist` | [ziyadnz/threat-intel-ip-feeds](https://github.com/ziyadnz/threat-intel-ip-feeds) | GITHUB | 107,173 | 48.7% | 0.5% | 8 | 🆕 NEU |
| `configserverapps_service_blocklists_blocklist` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 49,265 | 45.6% | 0.5% | 10 | 🆕 NEU |
| `gazpitchy92_ip_blocklist_blacklist` | [gazpitchy92/ip-blocklist](https://github.com/gazpitchy92/ip-blocklist) | GITHUB | 290,978 | 22.2% | 0.0% | 6 | 🆕 NEU |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) | GITHUB | 10,635 | 93.4% | 0.0% | 4764 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `PaloAltoNetworks/Unit42-timely-threat-intel` | GITHUB | IP-Datei 121d alt |
| `lolc2/lolc2.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thalesgroup-cert/Watcher` | GITHUB | IP-Datei 86d alt |
| `eggjs/tegg` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zazoomauro/node-dependency-injection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hynek/svcs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `greenbone/openvas-scanner` | GITHUB | IP-Datei 97d alt |
| `wpscanteam/wpscan` | GITHUB | IP-Datei 2856d alt |
| `awslabs/automated-security-helper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mrousavy/react-native-vision-camera` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `doo/scanbot-sdk-example-flutter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ossappscollective/OSS-DocumentScanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Symph0nia/CyberEdge` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Samsung/CredSweeper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kel-z/HSR-Scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Tencent/AI-Infra-Guard` | GITHUB | IP-Datei 219d alt |
| `Marven11/Fenjing` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `doo/scanbot-sdk-example-ios` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `5rahim/seanime` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `manuc66/node-hp-scan-to` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mondoohq/installer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CodeDead/Advanced-PortChecker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Stevoisiak/Stevos-AI-Blocklist` | GITHUB | Größe: 0 IPs |
| `rickmark/mojo_thor` | GITHUB | IP-Datei 2204d alt |
| `mitchellkrogza/nginx-ultimate-bad-bot-blocker` | GITHUB | Identischer Inhalt wie mitchellkrogza_nginx_ultimate_bad_bot_blocker |
| `mitchellkrogza/nginx-ultimate-bad-bot-blocker` | GITHUB | Identischer Inhalt wie mitchellkrogza_nginx_ultimate_bad_bot_blocker |
| `mitchellkrogza/nginx-ultimate-bad-bot-blocker` | GITHUB | Identischer Inhalt wie mitchellkrogza_nginx_ultimate_bad_bot_blocker |
| `mitchellkrogza/nginx-ultimate-bad-bot-blocker` | GITHUB | Identischer Inhalt wie mitchellkrogza_nginx_ultimate_bad_bot_blocker |
| `mitchellkrogza/nginx-ultimate-bad-bot-blocker` | GITHUB | Identischer Inhalt wie mitchellkrogza_nginx_ultimate_bad_bot_blocker |
| `malwaredb/malwaredb-rs` | GITHUB | IP-Datei 32d alt |
| `MISP/misp-galaxy` | GITHUB | Größe: 0 IPs |
| `CERT-Polska/drakvuf-sandbox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `owasp-dep-scan/blint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mandiant/flare-floss` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `phishingclub/phishingclub` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Altify-Developing/Altify-Developing-Main` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `t4d/PhishingKit-Yara-Rules` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `infinition/Bjorn` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dynatrace-oss/koney` | GITHUB | IP-Datei 205d alt |
| `SecurityClaw/SecurityClaw` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `WithSecureLabs/chainsaw` | GITHUB | IP-Datei 619d alt |
| `rami3l/pacaptr` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sanbir/evm-hack-registry` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xsscx/fuzz` | GITHUB | IP-Datei 3782d alt |
| `SIA-IOTechnology/Kittysploit-framework` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `htrgouvea/spellbook` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `openwrt-xiaomi/xmir-patcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DataDog/KubeHound` | GITHUB | IP-Datei 659d alt |
| `pcaversaccio/malleable-signatures` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spearchucker667/kimiko` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pcaversaccio/reentrancy-attacks` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Kwisma/Sub-Store-node` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sub-store-org/Sub-Store` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Mahdi0024/ProxyCollector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `v2rayA/v2rayA` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Alvin9999-newpac/Sing-Box-Plus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zhaoweih/Shadowsocks-Tutorial` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `youshandefeiyang/sub-web-modify` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `itshamzabendelladj/AIGuardSIEM` | GITHUB | Größe: 0 IPs |
| `lorenzo9uerra/GraphIDS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wazuh/wazuh-ansible` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Corgea/Sighthound` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trailofbits/it-depends` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xalgord/xalgorix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `popey/grummage` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shuvonsec/claude-bug-bounty` | GITHUB | IP-Datei 31d alt |
| `SHAdd0WTAka/Zen-Ai-Pentest` | GITHUB | IP-Datei 137d alt |
| `vigolium/vigolium` | GITHUB | IP-Datei 60d alt |
| `zan8in/afrog` | GITHUB | IP-Datei 206d alt |
| `e-m-b-a/emba` | GITHUB | Größe: 0 IPs |
| `gensecaihq/Shai-Hulud-2.0-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cisagov/Malcolm` | GITHUB | IP-Datei 70d alt |
| `DCSO/balboa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Vadims06/topolograph` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `felixhaeberle/pfsense-captive-portal` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NullCode1337/NullRAT` | GITHUB | Zu alt: 138d |
| `Fahrj/reverse-ssh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cr4sh/s6_pcie_microblaze` | GITHUB | Zu alt: 137d |
| `dpangestuw/Free-Proxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `koala73/worldmonitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ringmast4r/Epstein` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Jieyab89/OSINT-Cheat-sheet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sec0ps/va-pt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Hack23/cia` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dootss/shodan-dorks` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dedsec1121fk/DedSec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `arn-c0de/Crawllama` | GITHUB | IP-Datei 271d alt |
| `panther-labs/panther-analysis` | GITHUB | IP-Datei 841d alt |
| `google/secops-wrapper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fabriziosalmi/wildbox` | GITHUB | IP-Datei 390d alt |
| `SEKOIA-IO/documentation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `akamai/uls` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lukeswitz/AntiHunter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `praetorian-inc/julius` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Zarcolio/sitedorks` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `j3ssie/osmedeus` | GITHUB | IP-Datei 51d alt |
| `freelabz/secator` | GITHUB | IP-Datei 90d alt |
| `lockfale/OSINT-Framework` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pzaino/thecrowler` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `projectdiscovery/public-bugbounty-programs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `olizimmermann/s3dns` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `stanislav-web/OpenDoor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aziontech/azion-console-kit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `coreruleset/go-ftw` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nemesida-waf/waf-bypass` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fuomag9/caddy-proxy-manager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aboutcode-org/vulnerablecode` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ossf/cve-bin-tool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sourcentis/mercator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `owasp-dep-scan/dep-scan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vulnerability-lookup/vulnerability-lookup` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EXP-Tools/threat-broadcast` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ra1nb0rn/search_vulns` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `righel/ms-exchange-version-nse` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `larlarua/AutoCVE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `guacsec/trustify` | GITHUB | IP-Datei 218d alt |
| `infobyte/faraday` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `heymaikol/network-doctor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `batfish/batfish` | GITHUB | IP-Datei 43d alt |
| `3proxy/3proxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mennylevinski/core_net_scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `osociety/network_tools` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HolmesGPT/holmesgpt` | GITHUB | IP-Datei 237d alt |
| `jestasecurity/thumper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pranshuparmar/witr` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bb1nfosec/Information-Security-Tasks` | GITHUB | IP-Datei 61d alt |
| `jmpsec/osctrl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fredotran/traffic-sign-detector-yolov4` | GITHUB | Zu alt: 253d |
| `siderolabs/extensions` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `siderolabs/discovery-service` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `budimanjojo/talhelper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jeet-ganguly/birdy-edwards` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `squid-protocol/gitgalaxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RavinduRathnayaka/LiveThreatMap-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `blake-hamm/bhamm-lab` | GITHUB | IP-Datei 484d alt |
| `flswld/halo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `doo/scanbot-sdk-example-capacitor-ionic` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `middelink/mikrotik-fwban` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fenio/homelab` | GITHUB | IP-Datei 345d alt |
| `26zl/cybersec-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `profullstack/threatcrush` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `K4N3CO-LABS/Lab-RATS` | GITHUB | Größe: 0 IPs |
| `LeakIX/LeakIXClient-Python` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `scivision/findssh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CodePagol/ISP-Mikrotik-Billing` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `muhammadzidane632/Hopeless` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zacheryph/k8s-gitops` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MathisVerstrepen/letterboxd-jellyfin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fuscher/open-shield` | GITHUB | IP-Datei 42d alt |
| `JuliaLang/SecurityAdvisories.jl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `retroSoC/retroSoC` | GITHUB | Größe: 0 IPs |
| `Hack23/European-Parliament-MCP-Server` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `githubabcs/gh-abcs-admin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `skka3134/Free-servers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `form3tech-oss/terraform-provider-chronicle` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fish-not-phish/open-vbrowser` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wudidike/pentest_skill` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `StormWorld0/storm-framework` | GITHUB | IP-Datei 105d alt |
| `heisenburgah/HYDROXIDE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ArtemioPadilla/watchboard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `networking-incubator/coraza-kubernetes-operator` | GITHUB | IP-Datei 34d alt |
| `cristianzsh/triager` | GITHUB | Größe: 0 IPs |
| `sketchain/Nfuse` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jeet-ganguly/birdy-edwards-lite` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gabrielcosi/home-ops` | GITHUB | Größe: 0 IPs |
| `SerenPasaoglu/Multi-City-Enterprise-Network` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `johncarmack1984/promptward` | GITHUB | Größe: 0 IPs |
| `Sentinel-Archetecht/The-Remote-Viewer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `omeryemba/mcp-hayabusa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `The333tech/The333-bgp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `airomhq/airom` | GITHUB | Größe: 0 IPs |
| `doit4everyone/utmstack-lab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NIKX-Tech/karshipta` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zig-utils/zig-waf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `divisionseven/pkg-defender` | GITHUB | Größe: 0 IPs |
| `NullOperatorr/Creating-Splunk-Rules-for-Web-Attacks-in-a-Home-Lab-From-Attack-to-Detection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DNSZLSK/muad-dib` | GITHUB | IP-Datei 58d alt |
| `abdelrano/sentinelle-routage` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cparnin/polaris` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `codelassey/cybersecurity-labs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NullOperatorr/Detecting-Command-Injection-using-Snort` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `koensmink/ncsc-advisory-watcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hackerdogs-ai/hd-mcpservers-docker` | GITHUB | IP-Datei 129d alt |
| `jerzy99jerzy/cve-digest` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PWintima/SecureVoiceSystem` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `beeswaxpat/chronoverify-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ncreighton/2aa140e3-blockchain-smart-contract-audi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `machismo0311/Home-Lab` | GITHUB | Größe: 0 IPs |
| `shubhanshupandey46-coder/ScamShield-AI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ravikirank29/Enterprise-SSH-Threat-Monitoring` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sebastianlutycz/lumina-waf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Tuxmint-Open-Source/misp-docker-lifecycle-manager` | GITHUB | Größe: 0 IPs |
| `kaerbr/beehive` | GITHUB | IP-Datei 125d alt |
| `KrasiKirov/freshet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SuperMarioYL/agentguard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Akshay7273/skill-advisories` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wim-de-groot/4546B` | GITHUB | IP-Datei 408d alt |
| `nwarila-platform/secure-wazuh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BDenizKoca/Neislios` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `grave0x/gitprops` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Menno-MBA/infosec-council` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SreejaPuthan/ICEBERG-Threat-Intel-updator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PerIPan/explorer-plus` | GITHUB | Größe: 0 IPs |
| `Waytts-ai/wifi-attack-diagrams` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `cbuijs_hagezi` | GITHUB | 46,992 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 24,258 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,097 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 3,347 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 5,833 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 589 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 18,364 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 464 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 253 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,507 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,897 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,563 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 2,213 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 6,198 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 5,503 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https_anonymous` | GITHUB | 5,500 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 4,701 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,539 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 902 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 866 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 668 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 352 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 24,759 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 4,901 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 3,182 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,191 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,791 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,926 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,173 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 196,824 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,540 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,365 | 2.6% | 116 | 2026-07-05 |
| `breakingtechfr_proxy_free` | GITHUB | 29,347 | 0.6% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_all` | GITHUB | 32,012 | 0.5% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks4` | GITHUB | 7,200 | 1.9% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks5` | GITHUB | 5,942 | 2.2% | 55 | 2026-07-14 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,635 | 93.4% | 4764 | 2026-07-22 |
| `mohammedcha_proxripper` | GITHUB | 55,137 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,669 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 118,862 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,351 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 82,780 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,946 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 81,472 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 101,054 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,427 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 107,148 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 106,581 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 590 | 36.7% | 8 | 2026-07-03 |
| `ziyadnz_threat_intel_ip_feeds_ipv4_blacklist` | GITHUB | 107,173 | 48.7% | 8 | 2026-07-22 |
| `darzanebor_mikroblack` | GITHUB | 42,108 | 26.6% | 13 | 2026-07-05 |
| `ankaboot_source_email_open_data` | GITHUB | 495,706 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,585 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,307 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 171,551 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 138,815 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 105,510 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 89,397 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 99,605 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 83,017 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 85,060 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 50,569 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 57,712 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 33,961 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 25,125 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 30,998 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 24,346 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 20,942 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 18,979 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 26,659 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,114 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 12,749 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 8,591 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 11,876 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 14,382 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 7,302 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,403 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 6,522 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 5,171 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,818 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 9,506 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 4,926 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,857 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 2,989 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,997 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 49,265 | 45.6% | 10 | 2026-07-22 |
| `ian_lusule_proxies` | GITHUB | 3,762 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,706 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 743 | 17.2% | 9 | 2026-07-08 |
| `celestialbrain_worldpool` | GITHUB | 81,823 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 297,655 | 22.0% | 6 | 2026-07-08 |
| `gazpitchy92_ip_blocklist_blacklist` | GITHUB | 290,978 | 22.2% | 6 | 2026-07-22 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,367 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,508 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 6,328 | 2.6% | 7 | 2026-07-04 |
| `realizelol_torblocklist` | GITHUB | 1,541 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 61 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 58,514 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 67,172 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,942 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 124 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 197,013 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,748 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,665 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 7,709 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 7,983 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 167,919 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,056 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 16,510 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 17,335 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,274 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 55,830 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 48,234 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,416 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 110,877 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 418 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,167 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 191,950 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,502 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 110,867 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 127,824 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 33,072 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 20,665 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 18,178 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,784 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 7,749 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 464 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,684 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,073 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 218 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 250 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,122 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,536 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,325 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 909 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 3,507 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,684 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,887 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,421 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 48 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 50 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 50 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,000 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 49 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 908 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 160 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,422 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 753 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,279 | 6.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_maltrail_scanners` | GITHUB | 16,854 | 14.9% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_iblocklist_cruzit_web_attacks` | GITHUB | 13,871 | 0.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 5,631 | 5.0% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,127 | 24.2% | 0 | 2026-07-22 |

---
*Generiert: 2026-07-22 20:13 UTC*