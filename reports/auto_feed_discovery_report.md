# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-08 19:47 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7650** |
| davon GitHub (Topics+Code) | **7599** |
| davon GitLab | **51** |
| davon Awesome-Lists | **1022** |
| Tools/Libraries vor Eval gefiltert | **1260** |
| davon Hard-Reject (awesome-Liste etc.) | **131** |
| EVAL-Kandidaten (nach Stratifizierung) | **296** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **296** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **295** |
| Neu angenommene Feed-Dateien | **2** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **151** |
| Abgelehnte Repositories (dieser Run) | **295** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **153** |
| IPs in seen_db bestätigt | **2977674** |
| Neue IPs eingetragen | **415** |
| seen_db gesamt | **9,263,422** |
| HQ-Referenz-IPs (6 Quellen) | **138832** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Sonstige | **212** |
| Repo zu alt (>30d) | **44** |
| IP-Datei veraltet (>30d) | **26** |
| Falsche Größe (<100 / >2,000,000 IPs) | **10** |
| Overlap mit HQ-Feeds zu gering (<20%) | **3** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `configserverapps_service_blocklists_botscout_30d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 4,084 | 4.6% | 0.0% | 10 | 🆕 NEU |
| `realizelol_torblocklist` | [realizelol/torblocklist](https://github.com/realizelol/torblocklist) | GITHUB | 1,511 | 40.4% | 0.0% | 3 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `efxtv/L3MON` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hugsy/gef-extras` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `koala73/worldmonitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ringmast4r/Epstein` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RavinduRathnayaka/LiveThreatMap-dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hrbrmstr/cisa-known-exploited-vulns` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `oscaromeu/home-ops` | GITHUB | IP-Datei 86d alt |
| `ArtemioPadilla/watchboard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `UjsGit/Notes-on-OSINT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `univrsal/waechter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `chrede88/home-ops` | GITHUB | IP-Datei 52d alt |
| `SecurityRonin/issen` | GITHUB | Größe: 0 IPs |
| `intelseclab/poc-archive` | GITHUB | IP-Datei 51d alt |
| `Kicksecure/repository-dist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Jonaskouame/Phone-Number-Tracker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `security-force-monitor/research-handbook` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Enkidu-6/snowflake` | GITHUB | Zu alt: 715d |
| `MagicTeaMC/ChatGPT-playground-chinese` | GITHUB | Zu alt: 950d |
| `ShadowWhisperer/AbuseIPDB_Reporter` | GITHUB | Zu alt: 960d |
| `begineer-py/SKRpyASM` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cairnscore/cairn-score-skill` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `batmanpriv/Vandor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zhangjiayang6835-cyber/honeycode-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hett-patell/ShardLure` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thomasleveil/doco-maltrail` | GITHUB | Zu alt: 3309d |
| `gvatsal60/Linux-Aliases` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gvatsal60/Linux-All-In-One-Update-Script` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Flowtriq/ftagent` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cassamajor/Erratum` | GITHUB | Zu alt: 2387d |
| `lopes/lantana` | GITHUB | IP-Datei 40d alt |
| `snowx-dev/SnowFastULP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Hatchepsoute/sigma-rules` | GITHUB | IP-Datei 142d alt |
| `metno/edrisobaric` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thrive-spectrexq/nxc-rs` | GITHUB | IP-Datei 75d alt |
| `luckyPipewrench/agent-egress-bench` | GITHUB | Größe: 0 IPs |
| `TryMightyAI/citadel-guard-openclaw` | GITHUB | Zu alt: 147d |
| `nico-ralf-ii-fpuna/tfg` | GITHUB | Zu alt: 1098d |
| `sjinks/node-modsecurity` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tyabus/banned_ips` | GITHUB | Größe: 0 IPs |
| `Wootehfook/BoxdBuddies` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nidr0x/k8s-gitops` | GITHUB | IP-Datei 612d alt |
| `MagicTeaMC/rpz-detector` | GITHUB | Zu alt: 152d |
| `MojiWasp/WordgenMoji` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `winebarrel/apt-transport-s3-go` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gerlero/apt-install` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `iamaryanbhalsing/OverLoadX` | GITHUB | Overlap zu gering: 0.0% |
| `JerryCauser/tcp-exists` | GITHUB | Zu alt: 674d |
| `CameronCodesStuff/pyemailspammer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aishee/Yukio` | GITHUB | Zu alt: 2810d |
| `speisekatze/sandbagger` | GITHUB | Zu alt: 1302d |
| `pfrest/ansible-collection-pfsense` | GITHUB | IP-Datei 84d alt |
| `mbierman/Firewalla-NUT` | GITHUB | Zu alt: 128d |
| `Mapiiik/Watcher-NMS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spcookie/erii` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xmrig-zero-donation/xmrig-zero-donation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BlacKSnowDot0/Proxy-Pulse` | GITHUB | Overlap zu gering: 2.3% |
| `cystack/stealer-fingerprints` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sgofferj/mailblocklist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vrikodar/Wizard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Alexsaphir/Talos-Flux` | GITHUB | IP-Datei 476d alt |
| `Correia-jpv/fucking-golang-open-source-projects` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `viglianesed/ip-blocklist` | GITHUB | Zu alt: 1508d |
| `tertiarycourses/TGS-2024049211-CySAPlus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wrefgtzweve/combo-gen` | GITHUB | Zu alt: 873d |
| `mousta8559/DarkSword` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `marksowell/nmap-tailwind-xsl` | GITHUB | Zu alt: 615d |
| `HandyPlugins/simply-disable-comments` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sugan0927/easyinstallvps` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `strangelookingnerd/fail2ban-map` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `chrisvgt/ansible-rathole-webguard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `henriquesebastiao/mkx` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wyre-technology/avanan-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `santost12/nftables-examples` | GITHUB | Zu alt: 37d |
| `thsvkd/yoloTracker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `s0undy/home-ops` | GITHUB | IP-Datei 80d alt |
| `Correia-jpv/Correia-jpv` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Gi7w0rm/fileshare` | GITHUB | Zu alt: 847d |
| `JBlond/ban_em_all` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DevPrice/karambit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ice-wzl/light_house` | GITHUB | Zu alt: 35d |
| `Nomadiction62/DDoser` | GITHUB | Zu alt: 808d |
| `Parthiban-seenu/phishing-detection` | GITHUB | Zu alt: 1892d |
| `Rudxain/dotfiles` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gigante/sh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0xSums/SVB` | GITHUB | Zu alt: 672d |
| `8891689/Mnemonic-Recovery-CUDA` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ssr6125/SRC-Hunter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cybersight-Security/Global-Threat-Map` | GITHUB | Zu alt: 98d |
| `msiuser47/Secure-Network-with-pfSense` | GITHUB | Zu alt: 34d |
| `buildplan/cs-caddy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aaronphifer/triagewall` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ADORSYS-GIS/wazuh-snort` | GITHUB | Zu alt: 56d |
| `hermanwjacobsen/hfortix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tamersaid2022/firewall-policy-automator` | GITHUB | Zu alt: 156d |
| `eleboucher/mktxp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `arnstein99/tinypot` | GITHUB | Zu alt: 55d |
| `parental-control-system/parental-app` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `diego-mediane/RodentManualScorer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `i-am-unbekannt/BLITZPROXY` | GITHUB | IP-Datei 352d alt |
| `miraunreformable550/pentest-with-LLM` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `8andit0/BanditBox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `n3rada/sapsxpg` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mauricelambert/PyWCGIshell` | GITHUB | Zu alt: 1716d |
| `aws-samples/route53resolver-dns-firewall-automation-bring-your-own-lambda` | GITHUB | Zu alt: 1476d |
| `NavyStack/ipranges` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `4kamruzzaman/r2upload-architecture` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `farsight-lol/farsight` | GITHUB | Overlap zu gering: 0.0% |
| `clolomagico123/ai-security-lab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Shikkanime/core` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dseomn/rock-paper-sand` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Stake2/Websites` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dotcomscripts/k8s-gitops` | GITHUB | IP-Datei 50d alt |
| `Gi7w0rm/Blogposts` | GITHUB | Zu alt: 129d |
| `Gi7w0rm/RansomwareKeys` | GITHUB | Zu alt: 780d |
| `LittleJake/animate-image-crawler` | GITHUB | Zu alt: 1721d |
| `MagicTeaMC/math` | GITHUB | Zu alt: 227d |
| `ShadowWhisperer/Bitwarden_Contacts` | GITHUB | Zu alt: 796d |
| `mateusdias96cs/aegis-threat-intelligence` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `clairmont32/cred-harvester-stuffer` | GITHUB | Zu alt: 2848d |
| `luanbonito02/windows` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hophtien/CVE-2025-54424` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `KH-Danial/my.vtoray.con` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `giantswarm/falco-app` | GITHUB | Größe: 0 IPs |
| `jaywire/RBL-Checker` | GITHUB | Zu alt: 2385d |
| `akyriako/osh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `esrat-services/remote-admin-tool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hackingyseguridad/fuzzer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ibnaleem/vtscan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Senaraufi/Security-Log-Analyser` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zykooooooooo/SeekMoney-ai` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SalmanAmin22/ghost-dir` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `schmug/dmarc.mx` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `p7cq/dns-bl` | GITHUB | Zu alt: 453d |
| `TheDeepOpc/nullsight` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `c0depool/c0depool-k8s-ops` | GITHUB | IP-Datei 239d alt |
| `Gi7w0rm/yara_rulez` | GITHUB | Zu alt: 1741d |
| `MagicTeaMC/ServerStatusDiscordBot` | GITHUB | Zu alt: 434d |
| `rumeshmadhusanka/SEP-api-gateway` | GITHUB | Zu alt: 1261d |
| `judedusk/findns` | GITHUB | IP-Datei 122d alt |
| `sgofferj/sipblocklist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Bossthetigan/NOLO` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Astoritin/Targeter` | GITHUB | Zu alt: 78d |
| `dirtybits/agentvouch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Bendr-20/helixa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `davccavalcante/bayestruth` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Chimamwow/Encryptix-Crypter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sediklaabidi/Passive-Guide` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aleff-github/TorWatchdog` | GITHUB | Zu alt: 369d |
| `andrewmichaelsmith/flux` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rahadbhuiya/cnsl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `johackim/docker-maltrail` | GITHUB | Zu alt: 1869d |
| `ransomNews/RedACT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `8linkz-sec/Ransomware-Bot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jbox-web/apt-larder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `siakhooi/shed` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Mark44928/Termux-TUI-Package-Store` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rafosw/DesyncRAT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dvz/mybb-breachshield` | GITHUB | Zu alt: 768d |
| `sindastra/passwnd` | GITHUB | Zu alt: 893d |
| `dogoncouch/LogESP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `evilsocket/opensnitch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lunasec-io/lunasec` | GITHUB | IP-Datei 1268d alt |
| `khast3x/Redcloud` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dev-sec/ansible-os-hardening` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pry0cc/axiom` | GITHUB | IP-Datei 1033d alt |
| `spectralops/preflight` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spectralops/teller` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rapid7/metasploit-framework` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RIPE-NCC/hadoop-pcap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lirantal/is-website-vulnerable` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Zigrin-Security/CakeFuzzer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zaproxy/zaproxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GrapheneOS/hardened_malloc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cossacklabs/themis` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tfsec/tfsec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `StackExchange/blackbox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fingerprintjs/fingerprint-android` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dtag-dev-sec/t-pot-autoinstall` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `google/google-authenticator` | GITHUB | IP-Datei 5613d alt |
| `rfunix/Pompem` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `baalmor/cve-ape` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eset/malware-ioc` | GITHUB | IP-Datei 3347d alt |
| `fireeye/sunburst_countermeasures` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `awslabs/git-secrets` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CrowdStrike/automactc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `muxinc/certificate-expiry-monitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sonatype-nexus-community/repo-diff` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spaceraccoon/manuka` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `containers/bubblewrap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tonarino/innernet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `google/gvisor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `darkbitio/mkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jtesta/ssh-audit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Apr4h/CobaltStrikeScan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sensepost/ruler` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `theupdateframework/notary` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `opensourcesec/CIRTKit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `securitywithoutborders/hardentools` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ossf/allstar` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alichtman/stronghold` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `keikoproj/kube-forensics` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `censys/censys-python` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `drduh/macOS-Security-and-Privacy-Guide` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nccgroup/PMapper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nccgroup/ScoutSuite` | GITHUB | IP-Datei 855d alt |
| `firstlookmedia/gpgsync` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Neo23x0/sigma` | GITHUB | IP-Datei 71d alt |
| `hadojae/DATA` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `snyk-labs/snync` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `x0rz/phishing_catcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `VirusTotal/yara` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AltraMayor/gatekeeper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `google/ukip` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `apiiro/combobulator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `realparisi/WMI_Monitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `linuz/Sticky-Keys-Slayer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `serain/mailspoof` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JupiterOne/starbase` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LogRhythm-Labs/PIE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `codeexpress/respounder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mikeperry-tor/vanguards` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `slackhq/nebula` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bitnami-labs/sealed-secrets` | GITHUB | IP-Datei 856d alt |
| `sensepost/notruler` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cruise-automation/k-rail` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Yelp/osxcollector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `coreos/clair` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nsacyber/GRASSMARLIN` | GITHUB | IP-Datei 3298d alt |
| `certsocietegenerale/swordphish-awareness` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cloudflare/mitmengine` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `oasis-open/cti-python-stix2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PlumHound/PlumHound` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `google/tsunami-security-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `google/santa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pellegre/libcrafter` | GITHUB | Größe: 0 IPs |
| `cisagov/untitledgoosetool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `darkoperator/Posh-VirusTotal` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nsacyber/Windows-Secure-Host-Baseline` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `latchset/clevis` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `toniblyx/prowler` | GITHUB | Größe: 0 IPs |
| `opsgenie/kubernetes-event-exporter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `facebook/osquery` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `opensourcesec/Forager` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ThreatResponse/aws_ir` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fireeye/red_team_tool_countermeasures` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `latchset/tang` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ANSSI-FR/AD-control-paths` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SSLMate/certspotter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `apple/password-manager-resources` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `certsocietegenerale/NotifySecurity` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Infocyte/PSHunt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NetSPI/SpoofSpotter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `securestate/king-phisher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `genuinetools/bane` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `technosophos/helm-gpg` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ewatkins/talos-cluster` | GITHUB | Größe: 0 IPs |
| `32u-nd/Spamhaus-DROP` | GITHUB | IP-Datei 118d alt |
| `badchars/fingerprint-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Altyaerau/Heroes-of-Mavia-Hack-Game-Bot-Auto-Farm-Clicker-Crypto-Token-Api-Cheat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cyclonite69/shadowcheck-web` | GITHUB | IP-Datei 62d alt |
| `Omnivorts/Tomarket-Hack-Game-Bot-Auto-Farm-Clicker-Crypto-Telegram-Api-Cheat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Chrenavete/Axie-Infinity-Bot-Crypto-Cheat-Auto-Farm-Clicker-Game-Api-Hack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `teststuffstash/homelab` | GITHUB | Größe: 0 IPs |
| `dryvist/ansible-splunk` | GITHUB | IP-Datei 122d alt |
| `Extenedi/DeleteShadowCopies` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Jancarow/BypassNeo-reGeorg` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Fluxenn/Cyber-Finance-Game-Bot-Auto-Farm-Clicker-Crypto-CFI-Telegram-Hack-Cheat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kondanta/homelab` | GITHUB | IP-Datei 185d alt |
| `SreejaPuthan/ICEBERG-Threat-Intel-updator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zeuu5/cyber-threat-hub` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eudaldgr/homelab` | GITHUB | Größe: 0 IPs |
| `Romil2112/log-analyzer` | GITHUB | Größe: 0 IPs |
| `D4rumanDev/synology-nas-scripts` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Attuque/adobe-network-restrictions` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Sengathirmcse/sigil-guardian` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `voytas75/sourcetrace` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sjinks/wazuh-ar-ipset` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nreynolds-pub-git/exposureiq` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `am-hotstuff819/cve-watch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hotru6999/Email-Security-Auditor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Jadarelaxed973/cyanide` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wian4268/fortress-auth` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Youcefyo2585/vibe-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `qmfire18-source/DEEP-STATE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `irawany304-gif/ASNforge` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spreaderwangle568/threat-detection-` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ecolihazardousness497/cambrian-p` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `watery-esq538/AfnRiskScan-CE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vkxxxii99/The-Witcher-3-DLC-Unlocker-Cross-Platform-Koalageddon-ScreamAPI-` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `populated-spindle594/ocsfkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kongma1891/microsoft-style-skill` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Symbolic-restaurantchain424/Fsociety_Operations_Logs.dat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Afolabiebu4567/-MetaSkins-Access-All-In-Game-Skins-Exclusive-Custom-Sets` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thomdefinable658/sentinel-detection-engine` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `watercoursedoroteoarango523/taintwatch` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | GITHUB | 10,638 | 75.0% | 4721 | 2026-05-28 |
| `cbuijs_hagezi` | GITHUB | 49,881 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 28,764 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,852 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 3,280 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 5,162 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 644 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 17,628 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 476 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 323 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 5,695 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,502 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,597 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,775 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 5,988 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 5,170 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https_anonymous` | GITHUB | 5,167 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 4,933 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,431 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 854 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 787 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 689 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 415 | 12.8% | 60 | 2026-07-04 |
| `leon406_subcrawler` | GITHUB | 110,774 | 0.1% | 1542 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 25,939 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 5,824 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 4,147 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,230 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,805 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,989 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,256 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 196,952 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,537 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,227 | 2.6% | 116 | 2026-07-05 |
| `mohammedcha_proxripper` | GITHUB | 55,083 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,792 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 118,534 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,031 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 82,618 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,921 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 81,302 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 100,081 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,429 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 112,317 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 108,624 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 645 | 36.7% | 8 | 2026-07-03 |
| `darzanebor_mikroblack` | GITHUB | 42,108 | 26.6% | 13 | 2026-07-05 |
| `ankaboot_source_email_open_data` | GITHUB | 500,503 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,472 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,140 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 173,866 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 137,077 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 101,949 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 92,624 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 92,568 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_30d` | GITHUB | 85,372 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 84,583 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 68,362 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 54,872 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_15d` | GITHUB | 49,917 | 47.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 43,740 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 36,762 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 27,152 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 25,945 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,994 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 23,981 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 21,911 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 18,866 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 14,068 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,424 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 11,537 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 9,770 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 11,724 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 6,354 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,161 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 51,730 | 40.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 5,403 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 4,394 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 6,223 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 8,916 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 5,087 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 4,084 | 4.6% | 10 | 2026-07-08 |
| `ian_lusule_proxies` | GITHUB | 3,678 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,718 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 734 | 17.2% | 9 | 2026-07-08 |
| `celestialbrain_worldpool` | GITHUB | 79,285 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 270,421 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 4,935 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 3,682 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 4,816 | 2.6% | 7 | 2026-07-04 |
| `realizelol_torblocklist` | GITHUB | 1,511 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 59 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 53,657 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 91,736 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,689 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 88 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 218,479 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,783 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,677 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 7,158 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 7,446 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 159,692 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,056 | 21.9% | 1 | 2026-07-04 |
| `idleadmin_threatfeed` | GITHUB | 58,032 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 46,465 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,481 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 110,650 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 504 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,168 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 191,744 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,467 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 114,074 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 121,117 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 32,147 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 494 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 21,960 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 15,454 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,793 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 7,111 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,993 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cps_abusech` | GITHUB | 7,607 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,693 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,511 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,210 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,903 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,121 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 3,199 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,764 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 4,342 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,627 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,971 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,406 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_socks_proxy_7d` | GITHUB | 1,490 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,383 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,289 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,222 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,197 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,060 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 978 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,240 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,209 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 850 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 984 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 892 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 758 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 732 | 40.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 719 | 41.2% | 0 | 2026-07-05 |

---
*Generiert: 2026-07-08 19:47 UTC*