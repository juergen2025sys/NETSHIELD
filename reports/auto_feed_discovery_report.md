# Auto Feed Discovery – Report
**Aktualisiert:** 2026-07-08 17:57 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7641** |
| davon GitHub (Topics+Code) | **7590** |
| davon GitLab | **51** |
| davon Awesome-Lists | **1022** |
| Tools/Libraries vor Eval gefiltert | **1259** |
| davon Hard-Reject (awesome-Liste etc.) | **131** |
| EVAL-Kandidaten (nach Stratifizierung) | **300** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **300** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **298** |
| Neu angenommene Feed-Dateien | **3** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **148** |
| Abgelehnte Repositories (dieser Run) | **298** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **151** |
| IPs in seen_db bestätigt | **2866847** |
| Neue IPs eingetragen | **110671** |
| seen_db gesamt | **9,263,007** |
| HQ-Referenz-IPs (6 Quellen) | **138583** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Sonstige | **213** |
| Repo zu alt (>30d) | **51** |
| IP-Datei veraltet (>30d) | **25** |
| Falsche Größe (<100 / >2,000,000 IPs) | **9** |
| Overlap mit HQ-Feeds zu gering (<20%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `configserverapps_service_blocklists_abusers_1d` | [ConfigServerApps/service-blocklists](https://github.com/ConfigServerApps/service-blocklists) | GITHUB | 5,087 | 4.1% | 0.0% | 10 | 🆕 NEU |
| `tscci_threatips` | [TScci/threatips](https://github.com/TScci/threatips) | GITHUB | 734 | 17.2% | 0.0% | 9 | 🆕 NEU |
| `gazpitchy92_ip_blocklist` | [gazpitchy92/ip-blocklist](https://github.com/gazpitchy92/ip-blocklist) | GITHUB | 270,421 | 22.0% | 0.0% | 6 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `PaloAltoNetworks/Unit42-timely-threat-intel` | GITHUB | IP-Datei 680d alt |
| `wpscanteam/wpscan` | GITHUB | IP-Datei 2842d alt |
| `greenbone/openvas-scanner` | GITHUB | IP-Datei 83d alt |
| `mandiant/flare-floss` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bia-pain-bache/BPB-Worker-Panel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `silverwind/tcpie` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Libre-Diagnosctic/libre-automotive-diagnostic` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `goksenpasli/GpScanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DNSZLSK/muad-dib` | GITHUB | IP-Datei 44d alt |
| `swar09/aigis-zero` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `exiv703/Shield-Eye-Core` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rameerez/moderate` | GITHUB | Zu alt: 35d |
| `QabasAK/AWS-HaaS` | GITHUB | Zu alt: 42d |
| `wravoc/harden-dragonflybsd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CriticalPathSecurity/zeek-threat-intel-parser` | GITHUB | Zu alt: 2266d |
| `joeavanzato/recent_c2_infrastructure` | GITHUB | Overlap zu gering: 0.2% |
| `mtheuma/epson2paperless` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ericcornelissen/js-regex-security-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ashleykleynhans/ipset` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kristuff/abuseipdb` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Sh1r0ko11/AndroCrypt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `astroicers/Athena` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0xdea/ttyinject-rs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eobot-rat/Asur-Rat` | GITHUB | Zu alt: 61d |
| `DanielLavrushin/asuswrt-merlin-idefix` | GITHUB | Zu alt: 86d |
| `yourworstnightmare1/proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `archived-by-mrugesh/alfred-tor` | GITHUB | Zu alt: 1551d |
| `MaximeWewer/wazuh-operator` | GITHUB | IP-Datei 42d alt |
| `aaaastark/Intrusion-Detection-System` | GITHUB | Zu alt: 981d |
| `airlock/microgateway-running-example` | GITHUB | IP-Datei 281d alt |
| `jkerai1/DMARC-WallOfShame` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gfazioli/netfox-website` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Sewer2K/Vuln-Scanner-Exploit-Combo` | GITHUB | Zu alt: 99d |
| `pinoyvendetta/pv-go-layer-7` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `krahlos/matrix-webhook-bridge` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mathis2001/Files-upload` | GITHUB | Zu alt: 63d |
| `HyperSecurityLabs/oxide-communityedition-v8.6.9` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `waftester/waftester` | GITHUB | Zu alt: 33d |
| `Strappazzon/tor-exit-page` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ShadowWhisperer/Fix-WinUpdates` | GITHUB | Zu alt: 201d |
| `pop-ecx/rango` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ali-hey-0/FSociety` | GITHUB | Zu alt: 227d |
| `Olafsengerandesens/Clipper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CyberKiska/lxmf-vanity-address-generator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `femboyisp/blackwall` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cgzones/apt-cacher-rs` | GITHUB | IP-Datei 50d alt |
| `yusuf-husayn/dos-ddos-lab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `phor3nsic/graphqlBrute` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FSP-Labs/FSP.DMRCrack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jgmdev/stopspam` | GITHUB | Zu alt: 2602d |
| `Zilleali/mikrotik-laravel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `netlayer-id/radius_server` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tkreagan/os-kea-ubnd-ddns` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mbierman/homebridge-installer` | GITHUB | Zu alt: 200d |
| `EduContin/chrome-bypass` | GITHUB | Zu alt: 455d |
| `MadExploits/GECKO-FILE-MANAGER` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `unlock-security/wshell` | GITHUB | Zu alt: 58d |
| `SobralCybersec/APIKeyScanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vsxsentry/vsxsentry.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Jenderal92/CVE-2026-41940` | GITHUB | Zu alt: 39d |
| `abdulboyprogramming-arch/crypto-price-tracker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tscibilia/home-ops` | GITHUB | Größe: 0 IPs |
| `Huluti/ossatrisk` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `akmalovaa/mikroseclist` | GITHUB | Zu alt: 80d |
| `edyatl/winbox4-install-helper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Syn2Much/telnet_loader` | GITHUB | Zu alt: 112d |
| `herbiezimmerman/2017-11-15-Emotet-Malspam` | GITHUB | Zu alt: 3156d |
| `nastaso/xmrig-zero` | GITHUB | Zu alt: 101d |
| `ApliNi/IpacPanel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Senku002/ObuscatedBOT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `oabdrabo/DisplayDeck` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vyrox-security/vyrox-proxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mmontes11/k8s-tooling` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Gi7w0rm/Underground_Stories` | GITHUB | Zu alt: 1154d |
| `MagicTeaMC/Orange-Dog` | GITHUB | Zu alt: 163d |
| `ShadowWhisperer/NoGreenWin` | GITHUB | Zu alt: 638d |
| `tn3w/IPBlocklist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Shadow8021/darkwaves` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `teran/archived` | GITHUB | IP-Datei 703d alt |
| `ross/haproxy-mapper` | GITHUB | Zu alt: 1801d |
| `essambarghsh/mikrotik-hotspot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `x-way/ctrmd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MiraiTravel/MiraiTravel` | GITHUB | Zu alt: 63d |
| `mrflw-coder/Webshell-Bypass` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Yagami200/free-mtproto-proxies` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `peterhanily/maccrab` | GITHUB | IP-Datei 53d alt |
| `litemars/EDRHookDetector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nigelhorne/CGI-Info` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `a11mut3d/FullMute` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `smbonn2005/HomeOps` | GITHUB | Größe: 0 IPs |
| `ravilushqa/homelab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `S-L1/ti_scraper` | GITHUB | Zu alt: 106d |
| `elliotwutingfeng/rstthreatsall` | GITHUB | IP-Datei 688d alt |
| `secwexen/security-playbooks` | GITHUB | Größe: 0 IPs |
| `djnnvx/mic` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `linickx/HomeDetector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `subashjaganathan/windows-dfir-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Flowtriq/nethawk` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Bad-Behaviour/badbehaviour` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `subzerobo/dare-devil` | GITHUB | Zu alt: 2525d |
| `MaximeWewer/os-sso` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `oneclickvirt/webvirtcloud` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mchinchilla/NetFirewall` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EvanJ4536/Harmony-Discord-RAT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `abusaeeidx/TazaProxy-Troxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lidless-labs/maltego-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `password123456/nvd-cve-database` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Hack23/lambda-in-private-vpc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ricardocasares/next-https` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ZongXR/2024HHGJ-AItraining` | GITHUB | Zu alt: 228d |
| `LittleJake/server-monitor` | GITHUB | Zu alt: 184d |
| `MagicTeaMC/CatchBall2` | GITHUB | Zu alt: 74d |
| `peerhub-org/peerhub` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `v0rl0x/CPP-SSH-Bruteforce` | GITHUB | Zu alt: 753d |
| `noarche/brute` | GITHUB | Zu alt: 638d |
| `Rosa-Luxemburgstiftung-Berlin/ansible-opnsense-plugpack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `monobilisim/pfsense-5651` | GITHUB | Zu alt: 36d |
| `Defaultik/telegram-stealer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `inf0s3clol/inf0s3c-Grabber` | GITHUB | Zu alt: 466d |
| `Niam3231/monero-miner` | GITHUB | Zu alt: 34d |
| `chrismattmann/drat` | GITHUB | Zu alt: 31d |
| `fr4nsyz/KernelHarbor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `daedalus/sqlblindextract` | GITHUB | Zu alt: 101d |
| `zyw-286/HoneyGPT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jonhadfield/ipscout` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `heavybullets8/heavy-ops` | GITHUB | IP-Datei 252d alt |
| `Serp07/updater_list_for_mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jeonghanlee/epics-ioc-runner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gazpitchy92/ip-blocklist` | GITHUB | Identischer Inhalt wie gazpitchy92_ip_blocklist |
| `sefinek/Blacklisted-Emails` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FactorioAntigrief/FactorioAntigrief` | GITHUB | Zu alt: 1038d |
| `haraka/haraka-plugin-asn` | GITHUB | Zu alt: 40d |
| `abneeeees/ablist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `demining/ChatGPT-Bitcoin` | GITHUB | Zu alt: 1155d |
| `codelassey/cybersecurity-labs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `robertdebock/ansible-role-apt_repository` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Jenderal92/PoC-AutoSync` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EthanC/N31L` | GITHUB | Zu alt: 37d |
| `joho1968/Fail2WP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JGeek00/crowdsec-monitor-ios` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zelon88/Emotet_Analysis-2` | GITHUB | Zu alt: 2165d |
| `mikopbx/ModuleCTIClient` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Dashlane/dashlane-audit-logs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ERO-HACK/WP-Ateck` | GITHUB | Zu alt: 962d |
| `omobolajiadeyan/phishguard-ai` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Jenderal92/CVE-2026-8732` | GITHUB | Zu alt: 38d |
| `mr-coder20/FireScan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CriticalPathSecurity/Zeek-Intelligence-File-Names` | GITHUB | Zu alt: 967d |
| `MillipedeStrut/Malwarebytes-Premium-Anti-Malware-Pro-Edition` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Soontao/cds-rate-limit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mr-addams/arxsentinel` | GITHUB | Größe: 0 IPs |
| `NITISHMG/talos-hetzner-k8s` | GITHUB | Zu alt: 51d |
| `sanderzegers/fortigate-extcap` | GITHUB | Zu alt: 67d |
| `AizonF/Webhook-Searcher` | GITHUB | Zu alt: 477d |
| `devano12/Kryptex-miner` | GITHUB | Zu alt: 496d |
| `pol4ir/MovementHound` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `limithit/modsecurity-rule` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `juliobsz/twinboxd` | GITHUB | Zu alt: 37d |
| `osnabrugge/home-ops` | GITHUB | IP-Datei 54d alt |
| `Foundstone/ExpertInvestigationGuides` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Netflix/dispatch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `unfetter-analytic/unfetter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `op7ic/BlueTeam.Lab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MHaggis/sysmon-dfir` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `olafhartong/ThreatHunting` | GITHUB | IP-Datei 1370d alt |
| `mvelazc0/Oriana` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ocsf/ocsf-schema` | GITHUB | Größe: 0 IPs |
| `mdsecactivebreach/SharpShooter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EmpireProject/Empire` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Shuffle/Shuffle` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Yelp/elastalert` | GITHUB | IP-Datei 2540d alt |
| `infosecn1nja/Red-Teaming-Toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sbousseaden/PCAP-ATTACK` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rusty-ferris-club/shellclear` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nxgn-kd01/react2shell-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `apps/guardrails` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sergiomarotco/Network-segmentation-cheat-sheet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trustedsec/ptf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cloudflare/redoctober` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `insidersec/insider` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `isgasho/finshir` | GITHUB | IP-Datei 2630d alt |
| `nil0x42/phpsploit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tijme/angularjs-csti-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kai5263499/container-security-awesome` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `marcwebbie/passpie` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lanmaster53/recon-ng` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `spectralops/netz` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `v8blink/Chromium-based-XSS-Taint-Tracking` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `endgameinc/binarypig` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pfq/PFQ` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `docbleach/DocBleach` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GoVanguard/legion` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rozgo/anevicon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Khadinxc/Sigma2KQL` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ptswarm/reFlutter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `padok-team/cognito-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zaproxy/zap-api-nodejs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Khadinxc/Sigma2SPL` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mozilla/sops` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lyft/confidant` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Khadinxc/TerraSigma` | GITHUB | IP-Datei 126d alt |
| `iBotPeaches/Apktool` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `firezone/firezone` | GITHUB | Größe: 0 IPs |
| `owasp/nodegoat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `UDcide/udcide` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `KishanBagaria/padding-oracle-attacker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nxgn-kd01/shai-hulud-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ClickSecurity/data_hacking` | GITHUB | IP-Datei 4422d alt |
| `google/rekall` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aboul3la/Sublist3r` | GITHUB | IP-Datei 2376d alt |
| `RedTeamPentesting/monsoon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `simsong/tcpflow` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cloudsecurelab/security-acronyms` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `starkandwayne/safe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `amocrenco/owasp-testing-checklist-v4-markdown` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jtpereyda/boofuzz` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `k4m4/movies-for-hackers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `USArmyResearchLab/Dshell` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jery0843/torforge` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pompelmi/pompelmi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SpectralOps/keyscope` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `marshyski/sshwatch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `curiefense/curiefense` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `retracedhq/retraced` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `baidu/openrasp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zeroq/amun` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `codeyourweb/fastfinder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `frida/frida` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `deepfence/PacketStreamer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `selefra/selefra` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Storyyeller/enjarify` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OpenSOC/opensoc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ConradIrwin/dotgpg` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fugue/credstash` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kurolabs/stegcloak` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `skylot/jadx` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `marcinguy/scanmycode-ce` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `segmentio/chamber` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kai5263499/osx-security-awesome` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RustScan/RustScan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fingerprintjs/fingerprintjs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `apache/incubator-spot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `undeadlist/trust-scan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `51j0/Android-Storage-Extractor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nbs-system/naxsi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Checkmarx/kics` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gamelinux/passivedns` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `uptimejp/sql_firewall` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `deepfence/SecretScanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OWASP/owasp-mstg` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rusty-ferris-club/recon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jnv/lists` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `99designs/aws-vault` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `deepfence/ThreatMapper` | GITHUB | IP-Datei 744d alt |
| `Bearer/bearer` | GITHUB | IP-Datei 751d alt |
| `kaplanelad/shellfirm` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bridgecrewio/checkov` | GITHUB | IP-Datei 945d alt |
| `ir193/AMExtractor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `504ensicsLabs/LiME.git` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nwarila-platform/talos-cluster` | GITHUB | IP-Datei 37d alt |
| `nickconway/homelab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jorgeflmendes/TACACS-8021X-AAA-Lab` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jorgeflmendes/Cisco-ZBPF-Firewall-DoS-Lab` | GITHUB | Größe: 0 IPs |
| `pete731/sati` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Alexinaja/public-api-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `stevewm/homelab` | GITHUB | IP-Datei 45d alt |
| `faceseek-online/catfish-detector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Alan-Jowett/HardwareAbstractionIR` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `8884361/CHNRoute-for-FortiOS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FAlhumaid/DFIR_Radar_RSS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `balongbesuk/MikhPay` | GITHUB | Größe: 0 IPs |
| `0x4272616E646F6E/homelab` | GITHUB | IP-Datei 90d alt |
| `sim0nx/euvdlist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MustardSeedNetworks/seed` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `scottmartinanderson/clearfront` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AleksaMCode/pnls-data-collector` | GITHUB | IP-Datei 51d alt |
| `coramb2/network-traffic-analyzer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gcve-eu/gcve-enriched-dumps` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Abhayparashar31/KRAKEN` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mr-yifeiwang/bfilter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Zantirim/Seekers-of-Tokane-Cheat-Crypto-Bot-Auto-Farm-Clicker-Game-Api-Hack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Altyaerau/Legends-of-Elumia-Hack-Game-Bot-Auto-Farm-Clicker-Crypto-Elumia-Api-Cheat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thattelecomtech/CypherFox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `romeorone/ShellStrike` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `WRG-11/wrg-sigma-rules` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yiJayzhiming/CypherFox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ahmedsaifullah/WebPwn` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Estarking57/Scripts` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ConnarE92/-SOC-Engineering-and-Detection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `supermhel/argus` | GITHUB | Größe: 0 IPs |
| `SDCofA/mena-threat-index` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kiw13299/portkill` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bossxz238/Wordpress-Bruter-And-Upload-Shell` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `soloobr/z-loops` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Limozacloud/nvd-mirror` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `novadyne-hq/epss-cve-feed` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `poopmoh1/DisasterM3` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Czaprac/soc-triage-notes` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jn-s3s/proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |

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
| `skillter_proxygather` | GITHUB | 18,025 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 573 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 411 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 5,696 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,505 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,514 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,775 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 6,287 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 5,789 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https_anonymous` | GITHUB | 5,731 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 5,186 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,474 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 883 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 784 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 686 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 424 | 12.8% | 60 | 2026-07-04 |
| `leon406_subcrawler` | GITHUB | 110,774 | 0.1% | 1542 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 25,286 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 5,404 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 3,708 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 8,971 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,575 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,740 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,027 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 196,637 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,087 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 2,426 | 2.6% | 116 | 2026-07-05 |
| `mohammedcha_proxripper` | GITHUB | 55,067 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,755 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 118,396 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 114,987 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 82,442 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,193 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 80,990 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 100,081 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,429 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 112,317 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 108,020 | 36.7% | 8 | 2026-05-28 |
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
| `ian_lusule_proxies` | GITHUB | 3,697 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,887 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 734 | 17.2% | 9 | 2026-07-08 |
| `celestialbrain_worldpool` | GITHUB | 79,599 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 270,421 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 4,816 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 3,679 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 4,646 | 2.6% | 7 | 2026-07-04 |
| `turntuptechnologies_iocs` | GITHUB | 59 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 53,657 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 91,421 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,689 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 88 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 218,200 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,780 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,677 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 7,157 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 7,445 | 12.7% | 2 | 2026-05-24 |
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
*Generiert: 2026-07-08 17:57 UTC*