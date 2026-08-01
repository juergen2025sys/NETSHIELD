# Auto Feed Discovery – Report
**Aktualisiert:** 2026-08-01 03:41 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7123** |
| davon GitHub (Topics+Code) | **7052** |
| davon GitLab | **71** |
| davon Awesome-Lists | **2288** |
| Tools/Libraries vor Eval gefiltert | **517** |
| davon Hard-Reject (awesome-Liste etc.) | **168** |
| EVAL-Kandidaten (nach Stratifizierung) | **400** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **400** |
| davon angenommene Repositories | **3** |
| davon abgelehnte Repositories | **397** |
| Neu angenommene Feed-Dateien | **4** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **161** |
| Abgelehnte Repositories (dieser Run) | **397** |
| davon GitLab abgelehnt | **1** |
| Feeds gesamt (aktiv) | **165** |
| IPs in seen_db bestätigt | **2799120** |
| Neue IPs eingetragen | **363564** |
| seen_db gesamt | **13,950,446** |
| HQ-Referenz-IPs (6 Quellen) | **106932** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **230** |
| Repo zu alt (>30d) | **120** |
| IP-Datei veraltet (>30d) | **34** |
| Falsche Größe (<100 / >2,000,000 IPs) | **12** |
| Klon-Verdacht (Overlap >95%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `ziyadnz_threat_intel_ip_feeds_ipv4_blacklist` | [ziyadnz/threat-intel-ip-feeds](https://github.com/ziyadnz/threat-intel-ip-feeds) | GITHUB | 100,530 | 47.2% | 0.0% | 8 | 🆕 NEU |
| `bitwire_it_ip_list_fetch` | [bitwire-it/ip_list_fetch](https://github.com/bitwire-it/ip_list_fetch) | GITHUB | 33,916 | 24.7% | 0.0% | 0 | 🆕 NEU |
| `leon406_subcrawler` | [Leon406/SubCrawler](https://github.com/Leon406/SubCrawler) | GITHUB | 115,979 | 0.1% | 1.5% | 1560 | 🆕 NEU |
| `serp07_dude_blacklist_ip` | [Serp07/dude_blacklist_ip](https://github.com/Serp07/dude_blacklist_ip) | GITHUB | 4,628 | 31.6% | 0.0% | 0 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `JasonLovesDoggo/caddy-defender` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `skydiver/laravel-route-blocker` | GITHUB | Zu alt: 2151d |
| `OpenCTI-Platform/opencti` | GITHUB | IP-Datei 262d alt |
| `fastfire/deepdarkCTI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mikeroyal/Digital-Forensics-Guide` | GITHUB | Zu alt: 940d |
| `kaifcodec/user-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ninoseki/mitaka` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trickest/inventory` | GITHUB | Zu alt: 533d |
| `mandiant/flare-learning-hub` | GITHUB | Zu alt: 123d |
| `emalderson/ThePhish` | GITHUB | Zu alt: 730d |
| `Te-k/harpoon` | GITHUB | Zu alt: 75d |
| `OpenOSINT/OpenOSINT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mrwadams/attackgen` | GITHUB | Größe: 4 IPs |
| `mukul975/cve-mcp-server` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `daprofiler/DaProfiler` | GITHUB | Zu alt: 1039d |
| `toolswatch/vFeed` | GITHUB | Zu alt: 1891d |
| `ninoseki/mihari` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `curated-intel/Ukraine-Cyber-Operations` | GITHUB | Zu alt: 1132d |
| `dev-lu/osint_toolkit` | GITHUB | Zu alt: 95d |
| `aw-junaid/Hacking-Tools` | GITHUB | Zu alt: 107d |
| `chadi0x/TheBigBrother` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `r1cksec/cheatsheets` | GITHUB | Zu alt: 42d |
| `t4d/StalkPhish` | GITHUB | Zu alt: 873d |
| `RansomLook/RansomLook` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MISP/misp-warninglists` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Virus-Samples/Malware-Sample-Sources` | GITHUB | Zu alt: 2002d |
| `advanced-threat-research/Yara-Rules` | GITHUB | Zu alt: 501d |
| `OpenCTI-Platform/connectors` | GITHUB | IP-Datei 253d alt |
| `matamorphosis/Scrummage` | GITHUB | Zu alt: 576d |
| `Perkins-Fund/Malware-Bible` | GITHUB | Zu alt: 97d |
| `NoblerWorks-HQ/IRONSIGHT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cristianzsh/freki` | GITHUB | Zu alt: 915d |
| `utkusen/baitroute` | GITHUB | Zu alt: 564d |
| `rf-peixoto/phishing_pot` | GITHUB | Zu alt: 42d |
| `MISP/misp-training` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `7onez/cti-expert` | GITHUB | Größe: 0 IPs |
| `crocodyli/ThreatActors-TTPs` | GITHUB | Zu alt: 184d |
| `bartblaze/Yara-rules` | GITHUB | Zu alt: 185d |
| `volexity/threat-intel` | GITHUB | IP-Datei 1025d alt |
| `JMousqueton/ransomware.live` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `prodaft/cradle` | GITHUB | Zu alt: 75d |
| `Darksight-Analytics/tgspyder` | GITHUB | Zu alt: 230d |
| `lolc2/lolc2.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `opencybersecurityalliance/kestrel-lang` | GITHUB | Zu alt: 673d |
| `wolffcatskyy/crowdsec-blocklist-import` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mandiant/xrefer` | GITHUB | Zu alt: 38d |
| `Elemental-attack/Elemental` | GITHUB | Zu alt: 1332d |
| `NewBee119/Ti_Collector` | GITHUB | Zu alt: 3199d |
| `nasbench/MindMaps` | GITHUB | Zu alt: 1722d |
| `badchars/darknet-mcp-server` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `owl234/ARL-Next` | GITHUB | IP-Datei 92d alt |
| `opencybersecurityalliance/stix-shifter` | GITHUB | Zu alt: 36d |
| `HaoY-l/threat-intel-hub` | GITHUB | Zu alt: 214d |
| `unknownhad/CloudIntel` | GITHUB | Zu alt: 628d |
| `Securonix/AutonomousThreatSweeper` | GITHUB | Zu alt: 197d |
| `t4d/PhishingKitHunter` | GITHUB | Zu alt: 2749d |
| `phishdestroy/ScamIntelLogs` | GITHUB | Zu alt: 153d |
| `cybercdh/kitphishr` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MISP/misp-playbooks` | GITHUB | Zu alt: 291d |
| `coolacid/docker-misp` | GITHUB | Zu alt: 932d |
| `decoderloop/rust-malware-gallery` | GITHUB | Zu alt: 88d |
| `christinminor459/OnionClaw` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `miunasu/IDA-Skill` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jackaduma/SecBERT` | GITHUB | Zu alt: 1191d |
| `MISP/misp-dashboard` | GITHUB | Zu alt: 1118d |
| `vmkspv/lenspect` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fr0gger/jupyter-collection` | GITHUB | Zu alt: 82d |
| `djkurlander/knock-knock` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `adulau/the-art-of-pivoting` | GITHUB | Zu alt: 91d |
| `MISP/MISP-maltego` | GITHUB | Zu alt: 769d |
| `alvin-tosh/Infosec-and-Hacking-Scripts` | GITHUB | Zu alt: 861d |
| `gharty03/Conti-Ransomware` | GITHUB | Zu alt: 1178d |
| `osintbuddy/osintbuddy` | GITHUB | Zu alt: 149d |
| `KC7-Foundation/kc7` | GITHUB | Zu alt: 750d |
| `0xsha/sweetie-data` | GITHUB | Zu alt: 2347d |
| `harvard-itsecurity/docker-misp` | GITHUB | Zu alt: 1957d |
| `docintelapp/DocIntel` | GITHUB | Zu alt: 995d |
| `rix4uni/medium-writeups` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tg12/PoC_CVEs` | GITHUB | Zu alt: 77d |
| `typedb-osi/typedb-cti` | GITHUB | Zu alt: 205d |
| `pe3zx/mthc` | GITHUB | Zu alt: 1404d |
| `Patrowl/PatrowlHears` | GITHUB | Zu alt: 140d |
| `mthcht/ThreatHunting-Keywords-yara-rules` | GITHUB | Zu alt: 447d |
| `gen0sec/synapse` | GITHUB | IP-Datei 64d alt |
| `SoulSec/resource-threat-hunting` | GITHUB | Zu alt: 2878d |
| `trickest/insiders` | GITHUB | Zu alt: 1041d |
| `rix4uni/WordList` | GITHUB | Zu alt: 36d |
| `hpthreatresearch/subcrawl` | GITHUB | Zu alt: 1044d |
| `visualbasic6/chatter` | GITHUB | Zu alt: 1210d |
| `OpenCTI-Platform/client-python` | GITHUB | Zu alt: 261d |
| `w0h1v/mcp-shodan` | GITHUB | Zu alt: 123d |
| `ControlCompass/ControlCompass.github.io` | GITHUB | Zu alt: 888d |
| `knight0x07/pyc2bytecode` | GITHUB | Zu alt: 1161d |
| `ma111e/melody` | GITHUB | Zu alt: 533d |
| `tg12/rapid7_OSINT` | GITHUB | Zu alt: 77d |
| `r-smith/deceptifeed` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fox-it/cobaltstrike-beacon-data` | GITHUB | Zu alt: 1587d |
| `rix4uni/cvemapping` | GITHUB | IP-Datei 447d alt |
| `7WaySecurity/cloud_osint` | GITHUB | Zu alt: 115d |
| `tegridydev/python-OSINT-notebook` | GITHUB | Zu alt: 459d |
| `fabriziosalmi/wildbox` | GITHUB | IP-Datei 400d alt |
| `njcx/BlackIPS` | GITHUB | Zu alt: 1387d |
| `ecstatic-nobel/Analyst-Arsenal` | GITHUB | Zu alt: 2525d |
| `osintph/threatintel-platform` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ine-labs/ThreatSeeker` | GITHUB | Zu alt: 1173d |
| `tylabs/dovehawk` | GITHUB | Zu alt: 1846d |
| `OraclesTech/guardian-sdk` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BishopFox/sliver` | GITHUB | IP-Datei 184d alt |
| `Ne0nd0g/merlin` | GITHUB | Zu alt: 471d |
| `cobbr/Covenant` | GITHUB | Zu alt: 744d |
| `t3l3machus/Villain` | GITHUB | Zu alt: 437d |
| `skerkour/black-hat-rust` | GITHUB | Zu alt: 304d |
| `bats3c/shad0w` | GITHUB | Zu alt: 1767d |
| `DeimosC2/DeimosC2` | GITHUB | Zu alt: 471d |
| `S1ckB0y1337/Cobalt-Strike-CheatSheet` | GITHUB | Zu alt: 1635d |
| `sensepost/godoh` | GITHUB | Zu alt: 956d |
| `SpenserCai/DRat` | GITHUB | Zu alt: 1236d |
| `mhaskar/Octopus` | GITHUB | Zu alt: 1852d |
| `cxnturi0n/convoC2` | GITHUB | Zu alt: 563d |
| `b23r0/Heroinn` | GITHUB | Zu alt: 1393d |
| `3ct0s/dystopia-c2` | GITHUB | Zu alt: 744d |
| `Ptkatz/OrcaC2` | GITHUB | Zu alt: 1310d |
| `Tomiwa-Ot/moukthar` | GITHUB | Zu alt: 264d |
| `looCiprian/GC2-sheet` | GITHUB | Zu alt: 38d |
| `gl4ssesbo1/Nebula` | GITHUB | Zu alt: 430d |
| `spellshift/realm` | GITHUB | IP-Datei 887d alt |
| `Cr4sh/MicroBackdoor` | GITHUB | Zu alt: 1607d |
| `wsummerhill/C2_RedTeam_CheatSheets` | GITHUB | Zu alt: 51d |
| `postrequest/link` | GITHUB | Zu alt: 1809d |
| `Getshell/C2` | GITHUB | Zu alt: 721d |
| `0xflux/Wyrm` | GITHUB | Zu alt: 139d |
| `JoelGMSec/PSRansom` | GITHUB | Zu alt: 211d |
| `enkomio/AlanFramework` | GITHUB | Zu alt: 920d |
| `chainreactors/malice-network` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Coalfire-Research/Slackor` | GITHUB | Zu alt: 1253d |
| `Leo4j/Amnesiac` | GITHUB | Zu alt: 304d |
| `itaymigdal/Nimbo-C2` | GITHUB | Zu alt: 184d |
| `portbuster1337/ArachneC2` | GITHUB | Zu alt: 46d |
| `zarkones/XENA` | GITHUB | Zu alt: 462d |
| `0xTriboulet/Revenant` | GITHUB | Zu alt: 732d |
| `MatheuZSecurity/RingReaper` | GITHUB | Zu alt: 337d |
| `pumpbin/pumpbin` | GITHUB | Zu alt: 746d |
| `not-sekiun/PyIris` | GITHUB | Zu alt: 637d |
| `PhoenixC2/PhoenixC2` | GITHUB | Zu alt: 71d |
| `tokyoneon/CredPhish` | GITHUB | Zu alt: 1831d |
| `kyxiaxiang/GateSentinel` | GITHUB | Zu alt: 380d |
| `D13Xian/CobaltStrike-KunKun` | GITHUB | Zu alt: 470d |
| `kleiton0x00/RedditC2` | GITHUB | Zu alt: 1291d |
| `chainreactors/malefic` | GITHUB | Zu alt: 40d |
| `reveng007/SharpGmailC2` | GITHUB | Zu alt: 309d |
| `Coff0xc/AutoRedTeam-Orchestrator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Ziconius/FudgeC2` | GITHUB | Zu alt: 1188d |
| `shadow-workers/shadow-workers` | GITHUB | Zu alt: 1033d |
| `Ixve/Red-Team-Tools` | GITHUB | Zu alt: 269d |
| `Red-Hex-Consulting/Ankou` | GITHUB | Zu alt: 99d |
| `dstours/OctoC2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ProcessusT/Venoma` | GITHUB | Zu alt: 429d |
| `dobin/antnium` | GITHUB | Zu alt: 1488d |
| `sharsil/favicorn` | GITHUB | Zu alt: 87d |
| `maxDcb/C2TeamServer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jasonmiacono/IOCs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kevthehermit/YaraRules` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `intezer/yara-rules` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MISP/misp-rfc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nshc-threatrecon/IoC-List` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OALabs/iocs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `reversinglabs/reversinglabs-yara-rules` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `InQuest/yara-rules` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0pc0deFR/YaraRules` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `inquest/python-iocextract` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `makflwana/IOCs-in-CSV-format` | GITHUB | IP-Datei 3651d alt |
| `pan-unit42/iocs` | GITHUB | IP-Datei 1755d alt |
| `mandiant/OpenIOC_1.1` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `swisscom/detections` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `x64dbg/yarasigs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `da667/667s_Shitlist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `citizenlab/malware-signatures` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kingtuna/Signatures` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `botherder/targetedthreats` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cube0x0/SharpMapExec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `1tayH/noisy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sbousseaden/Slides` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `a0rtega/metame` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kootenpv/whereami` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Hackplayers/4nonimizer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `carlospolop/hacktricks` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `themittenmac/TrueTree` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `0xSobky/Regaxor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sullo/nikto` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `evilsocket/pwnagotchi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Anon-Exploiter/SiteBroker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `niklasb/35c3ctf-challs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ElevenPaths/thethe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mindcrypt/uriDeep` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mdsecresearch/Publications` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `1N3/Sn1per` | GITHUB | IP-Datei 1769d alt |
| `itm4n/PPLdump` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DarkFlippers/unleashed-firmware` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `angr/heaphopper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dnsdb/dnsdbq` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dustyfresh/PHP-vulnerability-audit-cheatsheet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `al3xtjames/ghidra-firmware-utils` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RedDrip7/APT_Digital_Weapon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `google/vxsig` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `streaak/keyhacks` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LanHikari22/GBA-IDA-Pseudo-Terminal` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Battelle/sandsifter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PortSwigger/active-scan-plus-plus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `offensive-security/exploitdb` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tharina/BlackHoodie-2018-Workshop` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SecurityRiskAdvisors/VECTR` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SoloKeysSec/solo-hw` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Synacktiv/kernelcache-laundering` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TechRahul20/TelegramScraper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `a13xp0p0v/kconfig-hardened-check` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ustayready/fireprox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `carstein/rfuss2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `daira/pluto-eris` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `36hours/idaemu` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `projectdiscovery/interactsh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `uru-card/uru-card` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lief-project/LIEF` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rootm0s/WinPwnage` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `leecher1337/ntvdmx64` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `microsoft/New-KrbtgtKeys.ps1` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `byt3bl33d3r/SILENTTRINITY` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hackunagi/logsspot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `needmorecowbell/giggity` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Top-Hat-Sec/thsosrtl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `liyasthomas/postwoman` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `palantir/tslint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `byt3bl33d3r/CrackMapExec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Static-Flow/BurpSuite-Team-Extension` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SandboxEscaper/randomrepo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ogham/dog` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `guitmz/midrashim` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `juju4/ansible-MISP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `googleprojectzero/Jackalope` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `godaddy/yara-rules` | GITHUB | IP-Datei 3302d alt |
| `proxycannon/proxycannon-ng` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OxfordHCC/tracker-control-android` | GITHUB | IP-Datei 1278d alt |
| `CykuTW/My-CTF-Challenges` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `boku7/Ninja_UUID_Runner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `d35ha/CallObfuscator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `scythe-io/community-threats` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GhostPack/Rubeus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `giuspen/cherrytree` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `projectdiscovery/httpx` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `envoyproxy/envoy` | GITHUB | IP-Datei 843d alt |
| `CyCat-project/cycat-service` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MotherFuzzers/meetups` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `o-o-overflow/dc2019q-ooops` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mbechler/marshalsec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `helviojunior/shellcodetester` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `djhohnstein/macos_shell_memory` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DavidBuchanan314/dlinject` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cisco-config-analysis-tool/ccat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Microsoft/SpeculationControl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aoii103/DarkNet_ChineseTrading` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gitlab:shieldwed/ch.wwcom.wwphone` | GITLAB | Keine IP-Datei (Name/Inhalt) |
| `Shikkanime/core` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `whoahaow/rjsxrd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ramit-mitra/blocklist-ipsets` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `abdullahbutt/wordfeather` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `david942j/one_gadget` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `peasoft/NoMoreWalls` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ebrasha/free-v2ray-public-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `T145/black-truffles` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `borestad/static-binaries` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `santhreal/wafrift` | GITHUB | IP-Datei 69d alt |
| `fernvenue/chn-cidr-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Pawdroid/Free-servers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eraser-dev/eraser` | GITHUB | IP-Datei 1282d alt |
| `trilwu/apttrail` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bitwire-it/ipsum-clean` | GITHUB | Klon-Verdacht: 99.3% |
| `6r33z3/ros-abuseipdb` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `adysec/nuclei_poc` | GITHUB | Größe: 0 IPs |
| `GhostTroops/TOP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jasoncheng7115/jt-glogarch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lintsinghua/DeepAudit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `2dust/v2rayN` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Correia-jpv/fucking-open-source-mac-os-apps` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eventum-generator/eventum` | GITHUB | IP-Datei 57d alt |
| `Serp07/updater_list_for_mikrotik` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sgofferj/sipblocklist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Quan666/ELF_RSS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gensecaihq/Shai-Hulud-2.0-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Graylog2/graylog2-server` | GITHUB | IP-Datei 1230d alt |
| `Tagoletta/Fed0gaT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SHAdd0WTAka/Zen-Ai-Pentest` | GITHUB | IP-Datei 147d alt |
| `corazawaf/coraza` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JMousqueton/CTI-MSTeams-Bot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `endgamec2framework/endgame` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `toreamun/opnsense-plugins` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nomi-sec/PoC-in-GitHub` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sub-store-org/Sub-Store` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `corazawaf/coraza-spoa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fabriziosalmi/patterns` | GITHUB | IP-Datei 538d alt |
| `gebruder/wirken` | GITHUB | IP-Datei 78d alt |
| `future-architect/vuls` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fernvenue/github-cidr-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FrizzleM/SideInstaller` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fernvenue/telegram-cidr-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Winds-Studio/Leaf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ycdxsb/PocOrExp_in_Github` | GITHUB | IP-Datei 1230d alt |
| `travisghansen/hass-opnsense` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `axllent/mailpit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bitwire-it/Github-IP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SIA-IOTechnology/Kittysploit-framework` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `timescale/rsigma` | GITHUB | Größe: 0 IPs |
| `quodeq/quodeq` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheSecuredAnalyst/security-suite` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fastrevmd-lab/rustpanosmcp` | GITHUB | Größe: 0 IPs |
| `remixtedi/bagwatch` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hack-different/apple-knowledge` | GITHUB | IP-Datei 879d alt |
| `Chetoh16/watching-you` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fastrevmd-lab/fwskillsshare` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `praetorian-inc/nerva` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `votal-ai-hq/wb-red-team` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `privtools/ransomposts` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `32u-nd/Spamhaus-DROP` | GITHUB | IP-Datei 142d alt |
| `Jieyab89/OSINT-Cheat-sheet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `panther-labs/panther-analysis` | GITHUB | IP-Datei 851d alt |
| `actuator/Android-Security-Exploits-YouTube-Curriculum` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dolutech/agent-link` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aaronphifer/triagewall` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jkreileder/cf-ips-to-hcloud-fw` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hikka-io/hikka-next` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shuvonsec/claude-bug-bounty` | GITHUB | IP-Datei 41d alt |
| `artifact-keeper/artifact-keeper` | GITHUB | Größe: 0 IPs |
| `anchore/harbor-scanner-adapter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Pranith-Jain/daily-threat-brief` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SEKOIA-IO/documentation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `crowdsecurity/cs-haproxy-spoa-bouncer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nagameTW/mcp-server-malcolm` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Mahdi0024/ProxyCollector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fabriziosalmi/zion` | GITHUB | Größe: 0 IPs |
| `mahdibland/V2RayAggregator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dynatrace-oss/koney` | GITHUB | IP-Datei 215d alt |
| `xsscx/fuzz` | GITHUB | IP-Datei 3792d alt |
| `Corgea/Sighthound` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tyabus/banned_ips` | GITHUB | Größe: 0 IPs |
| `mwalbeck/docker-flox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trickest/wordlists` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EvilBit-Labs/opnDossier` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OWASP/cve-lite-cli` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `leebaird/discover` | GITHUB | Größe: 0 IPs |
| `VictoriaMetrics/VictoriaLogs` | GITHUB | IP-Datei 225d alt |
| `nyx-sec/nyx` | GITHUB | IP-Datei 98d alt |
| `tempesta-tech/tempesta` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `webamon-org/Daily-Threat-Brief` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trickest/cve` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `exemt/modsecEditor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alireza0/s-ui` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xalgorix/xalgorix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wp-labs/warp-parse` | GITHUB | IP-Datei 206d alt |
| `NiREvil/vless` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jamcalli/Pulsarr` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mateusdias96cs/aegis-threat-intelligence` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ruzickap/malware-cryptominer-container` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FunnyWolf/agentic-soc-platform` | GITHUB | Größe: 0 IPs |
| `CodeWithMa/watch-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `IamOumarIbrahim/radar-rf-research-stack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `link-society/krouter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `amitambekar510/Malicious-Hash-Threat-List` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xln777/home-soc-lab` | GITHUB | IP-Datei 58d alt |
| `Barabama/FreeNodes` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rblaine95/docker_monero_xmrig` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `openwrt-xiaomi/xmir-patcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trailofbits/it-depends` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `the-furry-hubofeverything/vps-ranges` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `browningluke/terraform-provider-opnsense` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `iDigitalFlame/ThunderStorm` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PumbaLP/CrowdSec-Smart-AbuseIPDB-Proxy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dwisiswant0/crlfuzz` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `grafana/pySigma-backend-loki` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pspete/psPAS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `secwexen/security-playbooks` | GITHUB | Größe: 0 IPs |
| `opena2a-org/opena2a` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `firefart/stunner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Excalibra/cybersecurity` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cargill/OpenSIEM-Logstash-Parsing` | GITHUB | IP-Datei 920d alt |
| `bitsadmin/wesng` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MaximeWewer/os-sso` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LJ9859/Malware-Database` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `6G-Networks/cu3GPP38.901` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wordfence/wordfence-cli` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lpsm-dev/docker-crypto-miner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `KKloudTarus/synapse-ce` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `webstockid/webstockid.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `physx322/ConsortWAF` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `qr243vbi/nekobox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `simonsruggi/StockDock` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vinceAmstoutz/symfony-security-auditor` | GITHUB | Größe: 0 IPs |
| `Hack23/lambda-in-private-vpc` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `cbuijs_hagezi` | GITHUB | 50,437 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 22,194 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,997 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 7,631 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,342 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 585 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 18,364 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 464 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 253 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,443 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,822 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,515 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 2,150 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,325 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,470 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,793 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,129 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 656 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 603 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 501 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 281 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 32,138 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 8,163 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 6,643 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 8,259 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 5,786 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,246 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 2,498 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 195,572 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,285 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,041 | 2.6% | 116 | 2026-07-05 |
| `breakingtechfr_proxy_free` | GITHUB | 29,347 | 0.6% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_all` | GITHUB | 32,012 | 0.5% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks4` | GITHUB | 7,200 | 1.9% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks5` | GITHUB | 5,942 | 2.2% | 55 | 2026-07-14 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,634 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 115,979 | 0.1% | 1560 | 2026-08-01 |
| `mohammedcha_proxripper` | GITHUB | 53,312 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,127 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,412 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,259 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 81,758 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,891 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 81,825 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 101,675 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,408 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 109,825 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 102,441 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 586 | 36.7% | 8 | 2026-07-03 |
| `ziyadnz_threat_intel_ip_feeds_ipv4_blacklist` | GITHUB | 100,530 | 47.2% | 8 | 2026-08-01 |
| `darzanebor_mikroblack` | GITHUB | 41,628 | 26.6% | 13 | 2026-07-05 |
| `ankaboot_source_email_open_data` | GITHUB | 491,755 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,715 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,581 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 172,862 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 139,853 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 106,133 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 95,795 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 109,265 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 83,805 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 160,985 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 43,153 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 69,567 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 29,818 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 19,811 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 33,016 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,175 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 15,368 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 13,292 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 27,367 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 13,053 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,821 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 3,369 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 12,721 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 7,727 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,427 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 6,934 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 5,478 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 3,135 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,269 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 5,074 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,620 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 1,742 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,121 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 31,198 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,669 | 78.1% | 10 | 2026-07-31 |
| `ian_lusule_proxies` | GITHUB | 3,157 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,329 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 865 | 17.2% | 9 | 2026-07-08 |
| `celestialbrain_worldpool` | GITHUB | 81,600 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 254,185 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,277 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,479 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 5,451 | 2.6% | 7 | 2026-07-04 |
| `realizelol_torblocklist` | GITHUB | 1,545 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 44 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 62,303 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 67,141 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,043 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 101 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 197,140 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,727 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,662 | 69.0% | 4 | 2026-06-28 |
| `fadouse_clash_threat_intel` | GITHUB | 8,089 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 8,453 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 170,279 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,056 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,970 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 16,442 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,287 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 49,362 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 51,375 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,361 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 109,830 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 386 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 192,269 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 112,471 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 129,107 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 29,556 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 22,922 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 13,813 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,784 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 4,805 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 2,907 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,684 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,261 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 1,500 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 1,443 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,123 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,534 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 1,275 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 1,942 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 1,758 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 3,128 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,841 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,365 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 460 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 440 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 446 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,002 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 373 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,092 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 437 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,437 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 704 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,279 | 6.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_maltrail_scanners` | GITHUB | 16,854 | 14.9% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_iblocklist_cruzit_web_attacks` | GITHUB | 13,871 | 0.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 5,631 | 5.0% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,127 | 24.2% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_tor_exits_1d` | GITHUB | 1,382 | 45.4% | 0 | 2026-07-26 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,428 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,462 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,208 | 8.1% | 0 | 2026-07-31 |
| `bitwire_it_ip_list_fetch` | GITHUB | 33,916 | 24.7% | 0 | 2026-08-01 |
| `serp07_dude_blacklist_ip` | GITHUB | 4,628 | 31.6% | 0 | 2026-08-01 |

---
*Generiert: 2026-08-01 03:41 UTC*