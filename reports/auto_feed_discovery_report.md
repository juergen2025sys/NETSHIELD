# Auto Feed Discovery – Report
**Aktualisiert:** 2026-08-01 07:16 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **7578** |
| davon GitHub (Topics+Code) | **7507** |
| davon GitLab | **71** |
| davon Awesome-Lists | **2290** |
| Tools/Libraries vor Eval gefiltert | **523** |
| davon Hard-Reject (awesome-Liste etc.) | **174** |
| EVAL-Kandidaten (nach Stratifizierung) | **400** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **400** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **398** |
| Neu angenommene Feed-Dateien | **5** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **163** |
| Abgelehnte Repositories (dieser Run) | **398** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **168** |
| IPs in seen_db bestätigt | **3157614** |
| Neue IPs eingetragen | **7902** |
| seen_db gesamt | **13,958,348** |
| HQ-Referenz-IPs (6 Quellen) | **107070** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Repo zu alt (>30d) | **192** |
| Keine IP-Datei im Repo | **169** |
| IP-Datei veraltet (>30d) | **26** |
| Falsche Größe (<100 / >2,000,000 IPs) | **11** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `sereinfy_adrules` | [Sereinfy/Adrules](https://github.com/Sereinfy/Adrules) | GITHUB | 1,414 | 12.2% | 0.0% | 7 | 🆕 NEU |
| `kalidada18_threatbase` | [kalidada18/threatbase](https://github.com/kalidada18/threatbase) | GITHUB | 181,761 | 16.5% | 0.0% | 2 | 🆕 NEU |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | [kalidada18/threatbase](https://github.com/kalidada18/threatbase) | GITHUB | 25,109 | 45.2% | 0.0% | 2 | 🆕 NEU |
| `kalidada18_threatbase_threatbase_ip_tor` | [kalidada18/threatbase](https://github.com/kalidada18/threatbase) | GITHUB | 7,435 | 9.1% | 0.0% | 2 | 🆕 NEU |
| `kalidada18_threatbase_threatbase_ip_botnet` | [kalidada18/threatbase](https://github.com/kalidada18/threatbase) | GITHUB | 3,577 | 34.1% | 2.0% | 2 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `FrancescoStabile/numasec` | GITHUB | Zu alt: 85d |
| `decal/werdlists` | GITHUB | Zu alt: 717d |
| `michredteam/RTbookNotes` | GITHUB | Zu alt: 762d |
| `curtislbyrd/CyberVault` | GITHUB | Zu alt: 141d |
| `saicharanamaraneni18-source/phishing-mail-incident-response` | GITHUB | Zu alt: 55d |
| `shubham7003/Security-Infrastructure-Observability-Platform` | GITHUB | Zu alt: 60d |
| `bhengubv/CircleAI` | GITHUB | Größe: 0 IPs |
| `bitjbullock/SysAdmin` | GITHUB | Zu alt: 74d |
| `servo/servo` | GITHUB | Größe: 0 IPs |
| `ankitkumarsh39-sys/email-analyzer-soc-tool` | GITHUB | Zu alt: 38d |
| `yuntianze/dmp` | GITHUB | Zu alt: 333d |
| `paulrouget/servo-embedding-example` | GITHUB | Zu alt: 3064d |
| `de-otio/agent-safety-pack` | GITHUB | Zu alt: 32d |
| `fabricedesre/servonk` | GITHUB | Zu alt: 2851d |
| `WebBluetoothCG/registries` | GITHUB | Zu alt: 1082d |
| `humaidq/dotfiles` | GITHUB | Größe: 0 IPs |
| `shizukutanaka/Muten` | GITHUB | Größe: 0 IPs |
| `allenai/dolma` | GITHUB | Zu alt: 269d |
| `jesuslopezreynosa/useful-scripts` | GITHUB | IP-Datei 629d alt |
| `seia-soto/dns` | GITHUB | Zu alt: 836d |
| `kakarot-dev/dnsink` | GITHUB | Zu alt: 88d |
| `1Jamie/project-lotus` | GITHUB | Zu alt: 34d |
| `mxmgorin/retsurf` | GITHUB | IP-Datei 322d alt |
| `yasirhamza/AndroDR` | GITHUB | IP-Datei 77d alt |
| `matiaselebi/Secure-DNS` | GITHUB | Größe: 0 IPs |
| `fx-dev-playground/gecko` | GITHUB | Zu alt: 1298d |
| `chaitanyaBytes/Slipstream` | GITHUB | Zu alt: 62d |
| `paulrouget/servofocus` | GITHUB | Zu alt: 3156d |
| `jschwe/ServoDemo` | GITHUB | IP-Datei 107d alt |
| `sagittaurius/malware-list-filter-compiler` | GITHUB | IP-Datei 62d alt |
| `paulrouget/hnbrowser` | GITHUB | Zu alt: 3322d |
| `jialunzhang-psu/SandCell-Artifact` | GITHUB | Zu alt: 198d |
| `ryanyxw/llm-decouple` | GITHUB | Zu alt: 310d |
| `arwunmarona/servo` | GITHUB | Größe: 0 IPs |
| `anthonyniqmm/servo` | GITHUB | Größe: 0 IPs |
| `webbeef/webviewer` | GITHUB | Zu alt: 715d |
| `justinmichaud/ion` | GITHUB | Zu alt: 2841d |
| `moto-browser/moto` | GITHUB | Zu alt: 463d |
| `securesystemslab/pkru-safe-servo` | GITHUB | Zu alt: 1369d |
| `fschutt/servo_gui_test` | GITHUB | Zu alt: 3231d |
| `Baconana-chan/ferro-browser` | GITHUB | Zu alt: 32d |
| `paulrouget/libsimpleservo` | GITHUB | Zu alt: 3224d |
| `karad/my-servo-embedding-example` | GITHUB | Zu alt: 2586d |
| `OwnedByWuigi/dactylic` | GITHUB | Zu alt: 59d |
| `galadran/tor-browser` | GITHUB | Zu alt: 2562d |
| `Anima-OS/Quokka` | GITHUB | Zu alt: 1313d |
| `kinetiknz/gecko` | GITHUB | Zu alt: 2376d |
| `BenEgeIzmirli/mozilla_central_in_c` | GITHUB | Zu alt: 1313d |
| `jsorg71/waterfox_classic_releases` | GITHUB | Zu alt: 1313d |
| `RekitRex21/Dino_Scan` | GITHUB | Zu alt: 160d |
| `Eswar19102005/Scam-Radar` | GITHUB | Zu alt: 111d |
| `GT-IoTEdu/Testbed-Virtual` | GITHUB | Zu alt: 113d |
| `MatheusCiocca/eng-ids` | GITHUB | Zu alt: 190d |
| `GT-IoTEdu/mvpv1-virtual` | GITHUB | IP-Datei 106d alt |
| `mashooquealiamur/blocked-ip-list` | GITHUB | Zu alt: 412d |
| `GT-IoTEdu/wticifes2026-iotedu` | GITHUB | IP-Datei 106d alt |
| `tachiikoma/nezumi` | GITHUB | Zu alt: 3400d |
| `danigargu/urlfuzz` | GITHUB | Zu alt: 2958d |
| `0x4meliorate/toxnet` | GITHUB | Zu alt: 174d |
| `safesploit/python-remote-session-lab-poc` | GITHUB | Zu alt: 1106d |
| `g0h4n/REC2` | GITHUB | Zu alt: 891d |
| `hrtywhy/BOF-CobaltStrike` | GITHUB | Zu alt: 1524d |
| `zarkones/OnionC2` | GITHUB | Zu alt: 275d |
| `jconwell/secret_handshake` | GITHUB | Zu alt: 869d |
| `emmaunel/DiscordGo` | GITHUB | Zu alt: 1182d |
| `jxroot/ZeroPulse` | GITHUB | Zu alt: 213d |
| `x86byte/LummaC2-Stealer` | GITHUB | Zu alt: 529d |
| `govindasamyarun/c2-cloud` | GITHUB | Zu alt: 895d |
| `cfs0x/Cobalt-Strike-Ultimate-Arsenal` | GITHUB | Zu alt: 56d |
| `st4inl3s5/kizagan` | GITHUB | Zu alt: 461d |
| `CirqueiraDev/KryptonC2` | GITHUB | Zu alt: 49d |
| `NixWasHere/NebulaC2` | GITHUB | Zu alt: 528d |
| `yuziiiiiiiiii/ThreatBook-C2` | GITHUB | Zu alt: 982d |
| `JLospinoso/cpp-implant` | GITHUB | Zu alt: 2064d |
| `BlackSnufkin/Maverick` | GITHUB | Zu alt: 55d |
| `Whomrx666/anonymous-c2` | GITHUB | Zu alt: 289d |
| `JoelGMSec/Kitsune` | GITHUB | Zu alt: 514d |
| `Project-Prismatica/Prismatica` | GITHUB | Zu alt: 1395d |
| `xRET2pwn/PickleC2` | GITHUB | Zu alt: 1832d |
| `SaturnsVoid/Project-Whis` | GITHUB | Zu alt: 1410d |
| `CroodSolutions/BeaconatorC2` | GITHUB | Zu alt: 68d |
| `CodeXTF2/HavocNotion` | GITHUB | Zu alt: 1391d |
| `XPSec-Security/Ravage` | GITHUB | Zu alt: 155d |
| `DarkCoderSc/SharpFtpC2` | GITHUB | Zu alt: 996d |
| `JrM2628/httpworker` | GITHUB | Zu alt: 319d |
| `audibleblink/gorsh` | GITHUB | Zu alt: 480d |
| `jxroot/ReHTTP` | GITHUB | Zu alt: 491d |
| `nopcorn/DuckDuckC2` | GITHUB | Zu alt: 993d |
| `Hex1629/BotnetC2` | GITHUB | Zu alt: 472d |
| `MythicAgents/venus` | GITHUB | Zu alt: 634d |
| `ZZ0R0/Proteus` | GITHUB | Zu alt: 80d |
| `tanc7/dark-lord-obama` | GITHUB | Zu alt: 1787d |
| `r4ulcl/Mythic-OSEP-CheatSheet` | GITHUB | Zu alt: 45d |
| `p4p1/havoc-bloodhound` | GITHUB | Zu alt: 910d |
| `ThreatMon/ThreatMon-Daily-C2-Feeds` | GITHUB | Zu alt: 948d |
| `t1b4n3/TibaneC2` | GITHUB | Zu alt: 227d |
| `malwarekid/OnlyShell` | GITHUB | Zu alt: 159d |
| `BlackSnufkin/Cheshire` | GITHUB | Zu alt: 89d |
| `ProfessionallyEvil/C4` | GITHUB | Zu alt: 2481d |
| `pygrum/monarch` | GITHUB | Zu alt: 571d |
| `voukatas/Commander` | GITHUB | Zu alt: 757d |
| `kensh1ro/Willie-C2` | GITHUB | Zu alt: 611d |
| `burpheart/dnsc2` | GITHUB | Zu alt: 1474d |
| `Otsmane-Ahmed/sliver-tor-bridge` | GITHUB | Zu alt: 193d |
| `reveng007/C2_Server` | GITHUB | Zu alt: 1616d |
| `JoasASantos/RTLC2` | GITHUB | Zu alt: 153d |
| `seqre/rast` | GITHUB | Zu alt: 179d |
| `0xEr3bus/ShadowForgeC2` | GITHUB | Zu alt: 1113d |
| `hdks-bug/hermit` | GITHUB | Zu alt: 583d |
| `p4p1/havoc-ligolo` | GITHUB | Zu alt: 921d |
| `Geeoon/asploit` | GITHUB | Zu alt: 844d |
| `ChaitanyaHaritash/IllusiveFog` | GITHUB | Zu alt: 672d |
| `RootUp/XRayC2` | GITHUB | Zu alt: 292d |
| `shogunlab/Sukoshi` | GITHUB | Zu alt: 1589d |
| `th3r4ven/Bifrost` | GITHUB | Zu alt: 1809d |
| `Team-intN18-SoybeanSeclab/prtstrike` | GITHUB | Zu alt: 104d |
| `Tomiwa-Ot/telegram-c2` | GITHUB | Zu alt: 626d |
| `maxDcb/C2Implant` | GITHUB | Zu alt: 82d |
| `ProcessusT/HavocHub` | GITHUB | Zu alt: 388d |
| `r3nt0n/zombiegang` | GITHUB | Zu alt: 1457d |
| `V-i-x-x/WIFIAIR-C2-Channel` | GITHUB | Zu alt: 126d |
| `cbrnrd/maliketh` | GITHUB | Zu alt: 176d |
| `degenerat3/meteor` | GITHUB | Zu alt: 1253d |
| `TryGOTry/C2_Demo` | GITHUB | Zu alt: 1622d |
| `slipperysquid/SquidNet` | GITHUB | Zu alt: 352d |
| `An00bRektn/gopher47` | GITHUB | Zu alt: 943d |
| `Syn2Much/VisionC2` | GITHUB | Zu alt: 102d |
| `zarkones/ControlSTUDIO` | GITHUB | Zu alt: 347d |
| `0xvpr/Malicious-Software-Research` | GITHUB | Zu alt: 141d |
| `wahyuhadi/beacon-c2-go` | GITHUB | Zu alt: 2391d |
| `Ayantaker/SpyderC2` | GITHUB | Zu alt: 1119d |
| `BlackSnufkin/GeckoDroid` | GITHUB | Zu alt: 140d |
| `lp-db/lp-db` | GITHUB | Zu alt: 1287d |
| `Dark-Avenger-Reborn/DRILL_V3` | GITHUB | Zu alt: 366d |
| `twezyzcerrin/discord-bot-ddos` | GITHUB | Zu alt: 596d |
| `CirqueiraDev/OverburstC2` | GITHUB | Zu alt: 195d |
| `sefinek/UFW-AbuseIPDB-Reporter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kristuff/abuseipdb-cli` | GITHUB | Zu alt: 1173d |
| `abriginets/umbress` | GITHUB | Zu alt: 811d |
| `sefinek/Cloudflare-WAF-To-AbuseIPDB` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PHPAuth/PHPAuth` | GITHUB | Zu alt: 195d |
| `kulkansecurity/gitxray` | GITHUB | Zu alt: 204d |
| `telekom-security/tpotce` | GITHUB | Zu alt: 39d |
| `hacklcx/HFish` | GITHUB | Zu alt: 141d |
| `beelzebub-labs/beelzebub` | GITHUB | IP-Datei 100d alt |
| `fabrimagic72/malware-samples` | GITHUB | Zu alt: 1781d |
| `GoSecure/pyrdp` | GITHUB | Zu alt: 80d |
| `seccome/Ehoney` | GITHUB | Zu alt: 1019d |
| `markets/invisible_captcha` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tenable/routeros` | GITHUB | Zu alt: 1341d |
| `qeeqbox/chameleon` | GITHUB | Zu alt: 1089d |
| `p1r06u3/opencanary_web` | GITHUB | Zu alt: 1990d |
| `aress31/wirespy` | GITHUB | Zu alt: 1386d |
| `DevSwanson/smart-contract-honeypot` | GITHUB | Zu alt: 208d |
| `DevSwanson/create-honeypot-token` | GITHUB | Zu alt: 208d |
| `0x4D31/honeyLambda` | GITHUB | Zu alt: 2842d |
| `tamimibrahim17/List-of-user-agents` | GITHUB | Zu alt: 969d |
| `C4o/Juggler` | GITHUB | Zu alt: 254d |
| `TrisenYu/b0gus` | GITHUB | Zu alt: 31d |
| `bhdresh/Dejavu` | GITHUB | Zu alt: 364d |
| `DevSwanson/how-to-create-honeypot-token` | GITHUB | Zu alt: 208d |
| `jamesturk/django-honeypot` | GITHUB | Zu alt: 410d |
| `formr/formr` | GITHUB | Zu alt: 382d |
| `fffaraz/fakessh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Shmakov/Honeypot` | GITHUB | Zu alt: 216d |
| `HoneypotCode/How-to-Create-Honeypot-Token` | GITHUB | Zu alt: 346d |
| `spacesiren/spacesiren` | GITHUB | Zu alt: 1686d |
| `0x4D31/finch` | GITHUB | Zu alt: 238d |
| `RiskyMH/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `burpheart/hachimi` | GITHUB | Zu alt: 554d |
| `TheKingOfDuck/Loki` | GITHUB | Zu alt: 1661d |
| `jayus0821/Armor` | GITHUB | Zu alt: 1860d |
| `Nirusu/how-to-setup-a-honeypot` | GITHUB | Zu alt: 1482d |
| `lockness-Ko/xz-vulnerable-honeypot` | GITHUB | Zu alt: 851d |
| `technicaldada/pentbox` | GITHUB | Zu alt: 304d |
| `bediger4000/php-malware-analysis` | GITHUB | Zu alt: 1870d |
| `DataDog/HASH` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ginger51011/pandoras_pot` | GITHUB | Zu alt: 33d |
| `leeberg/BlueHive` | GITHUB | Zu alt: 2593d |
| `valamidev/web3-defi-honeypot-and-slippage-checker` | GITHUB | Zu alt: 858d |
| `ANG13T/ESP8266-WiCon-Kit` | GITHUB | Zu alt: 1355d |
| `Fausto-404/AlterHive` | GITHUB | Größe: 0 IPs |
| `slowmist/blockchain-threat-intelligence` | GITHUB | Zu alt: 1693d |
| `tg12/dns-honeypot` | GITHUB | Zu alt: 77d |
| `aau-network-security/HosTaGe` | GITHUB | Zu alt: 408d |
| `victpork/sshsyrup` | GITHUB | Zu alt: 2714d |
| `Turing-Space/Smart-Contract-Modular-Template` | GITHUB | Zu alt: 2308d |
| `andreicscs/HoneyWire` | GITHUB | Größe: 0 IPs |
| `dweinstein/canary` | GITHUB | Zu alt: 127d |
| `Cymmetria/honeycomb` | GITHUB | Zu alt: 1478d |
| `ariafatah0711/HPone` | GITHUB | Zu alt: 123d |
| `adityashrm21/RaspberryPi-Packet-Sniffer` | GITHUB | Zu alt: 2791d |
| `referefref/sinon` | GITHUB | Zu alt: 605d |
| `telekom-security/tpotmobile` | GITHUB | Zu alt: 313d |
| `shantoroy/intro-2-cybersecurity-in-python` | GITHUB | Zu alt: 501d |
| `3CORESec/Trapdoor` | GITHUB | Zu alt: 1299d |
| `cowrie/docker-cowrie` | GITHUB | Zu alt: 1744d |
| `raspgot/Contact-Form-PHP` | GITHUB | Zu alt: 173d |
| `anouarbensaad/honeypot-iot` | GITHUB | Zu alt: 2641d |
| `malvaphe/Crypto_Honeypot_Detector` | GITHUB | Zu alt: 1160d |
| `random-robbie/docker-ssh-honey` | GITHUB | Zu alt: 367d |
| `Rushyo/VindicateTool` | GITHUB | Zu alt: 1581d |
| `kung-foo/freki` | GITHUB | Zu alt: 1276d |
| `Cymmetria/ciscoasa_honeypot` | GITHUB | Zu alt: 2808d |
| `LitoMore/honeypotoberfest` | GITHUB | Zu alt: 674d |
| `nunoOliveiraqwe/torii` | GITHUB | Zu alt: 36d |
| `BINANCECONTRACT/How-to-Create-Honeypot-Token` | GITHUB | Zu alt: 687d |
| `adanalvarez/HoneyTrail` | GITHUB | Zu alt: 623d |
| `ayebrian/fictusvnc` | GITHUB | Zu alt: 122d |
| `mixkorshun/django-antispam` | GITHUB | Zu alt: 739d |
| `OWASP/HoneySAP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rosehgal/HoneySMB` | GITHUB | Zu alt: 1952d |
| `bruneaug/DShield-SIEM` | GITHUB | IP-Datei 83d alt |
| `qeeqbox/seahorse` | GITHUB | Zu alt: 1923d |
| `isometriks/IsometriksSpamBundle` | GITHUB | Zu alt: 794d |
| `Red-company/RedNetwork_Tool` | GITHUB | Zu alt: 1589d |
| `honeynet/ochi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `abusix/xarf` | GITHUB | Zu alt: 46d |
| `juandresrodca/DorkCraft` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JMarchiori13/osint-recon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pownjs/pown` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shadowsocks/v2ray-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `outflanknl/Excel4-DCOM` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tensorflow/cleverhans` | GITHUB | IP-Datei 2012d alt |
| `thalium/icebox` | GITHUB | IP-Datei 2627d alt |
| `SecureAuthCorp/impacket` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ReddyyZ/urlbrute` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OmerYa/Invisi-Shell` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pwndoc/pwndoc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nccgroup/sadcloud` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mthbernardes/sshLooter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jessfraz/dotfiles` | GITHUB | IP-Datei 2391d alt |
| `caioluders/PII-Identifier` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trustedsec/social-engineer-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `stufus/reconerator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MISP/misp-modules` | GITHUB | IP-Datei 3442d alt |
| `andrew-d/static-binaries` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `iosiro/baserunner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `i3visio/osrframework` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `danielbohannon/Invoke-CradleCrafter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ch33r10/BlueSpace2021` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ShutdownRepo/The-Hacker-Recipes` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `epi052/feroxbuster` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `joesecurity/joesandboxcloudapi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `redcanaryco/AtomicTestHarnesses` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `i3visio/usufy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `snovvcrash/usbrip` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `p4pentest/SuperEnum` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Mr-Un1k0d3r/DKMC` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fabiomsr/okhttp-peer-certificate-extractor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ufrisk/pcileech` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `azsk/DevOpsKit-docs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `itm4n/PrivescCheck` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `honoki/bbrf-server` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SpiderLabs/social_mapper` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `A-poc/RedTeam-Tools` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `marcoramilli/PhishingKitTracker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kgretzky/pwndrop` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `david3107/graphql-security-labs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Microsoft/Detours` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ovh/debian-cis` | GITHUB | IP-Datei 333d alt |
| `github/secure_headers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Glorf/lear` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PortSwigger/http-request-smuggler` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CCob/SweetPotato` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HITB-CyberWeek/hitbsecconf-ctf-2021` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xct/ropstar` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yohanes/pgpemu` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ernw/Windows-Insight` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xlabssecurity/WAF-Hook` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `twelvesec/rootend` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gwen001/pentest-tools` | GITHUB | IP-Datei 1349d alt |
| `ualvesdias/crlfbruter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `plackyhacker/Shellcode-Injection-Techniques` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `chesire-cat/smbAutoRelay` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ail-project/ail-feeder-telegram` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `splunk/melting-cobalt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `allyomalley/dnsobserver` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bazad/x18-leak` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mentebinaria/retoolkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `libkeepass/libkeepass` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `korczis/foremost` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `trendmicro/telfhash` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `EdOverflow/can-i-take-over-xyz` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `merrychap/shellen` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dsopas/MindAPI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Viralmaniar/Remote-Desktop-Caching-` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aleff-github/my-flipper-shits` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `WhitewidowScanner/whitewidow` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pan-unit42/traffic-analysis-workshop` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thinkst/canaryfy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cutesunshine/ThreadBoat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `keepassium/KeePassium` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `juliocesarfort/public-pentesting-reports` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MalwareTech/TrickBot-Toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `serain/bbrecon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `secrary/makin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tyranid/DumpReparsePoints` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Dec0ne/KrbRelayUp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rabobank-cdc/DeTTECT` | GITHUB | IP-Datei 2207d alt |
| `target/strelka` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sleventyeleven/linuxprivchecker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fireeye/commando-vm` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `coreos/fero` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `StreisandEffect/streisand` | GITHUB | IP-Datei 2848d alt |
| `radare/v-r2pipe` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DarkSpiritz/DarkSpiritz` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `teemu-l/execution-trace-viewer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `timvisee/send` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kholia/airspy-utils` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nuxmorpheus/EHREM` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `utiso/dorkbot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `curi0usJack/ADImporter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `marcnewlin/presentation-clickers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PagerDuty/security-training` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GitGuardian/py-gitguardian` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `malcomvetter/ManagedInjection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SpiderLabs/Firework` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `O-X-L/ansible-opnsense` | GITHUB | IP-Datei 307d alt |
| `Correia-jpv/fucking-terminals-are-sexy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Correia-jpv/fucking-quick-look-plugins` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Correia-jpv/fucking-games` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Correia-jpv/fucking-magictools` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Correia-jpv/fucking-static-analysis` | GITHUB | IP-Datei 1173d alt |
| `Correia-jpv/fucking-Machine-Learning-Tutorials` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `commixproject/commix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ProfessorDong/afdm-multiblock-idar` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `p2pool-starter-stack/rigforge` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thesandipv/watchdone` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `regantemudo/dfir-playbooks` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mortennordbye/lawless-waf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sicuranext/karna` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cloudflare/wirefilter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gupax-io/gupax` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `browningluke/opnsense-go` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wddadk/Offensive-OSINT-Tools` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cniweb/xmrig-monero` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Pantheon-Security/medusa` | GITHUB | IP-Datei 125d alt |
| `HydraSoft/HydraSoft-DLL-Hijack-Scanner-ByPass-UAC` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BelalMou/panhygiene` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AnonCatalyst/Ominis-OSINT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AnonCatalyst/Coeus-OSINT-ToolBox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `glferreira-devsecops/Cascavel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `api-evangelist/letterboxd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zzmzm/tiyi` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `api-evangelist/f5-distributed-cloud-services` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `api-evangelist/datadome` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `api-evangelist/cybersecurity-and-infrastructure-security-agency` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `api-evangelist/cloudflare-turnstile` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `api-evangelist/citrix-netscaler` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `api-evangelist/aws-waf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `api-evangelist/amazon-waf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `api-evangelist/a10-networks` | GITHUB | IP-Datei 68d alt |
| `GuardianWAF/GuardianWAF` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nsasoft/nsauditor-ai` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bigcnash/cowrie-ssh-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `joseetenreiro/ISAC-Simulation-Framework-5G` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ByteRay-Labs/Query-Hub` | GITHUB | IP-Datei 171d alt |
| `dredozubov/hazmat` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jichangtuijian-cheap/cheap-airports` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GACWR/OpenUBA` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `opnsense/docs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ep3p/Sentinel_KQL` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `api-evangelist/human-security` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Hoshinonyaruko/Gensokyo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `e-m-b-a/emba` | GITHUB | Größe: 0 IPs |
| `caiteli/StockTicker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bluesaphire76/sovereign-ai-soc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sinewaveai/agent-security-scanner-mcp` | GITHUB | IP-Datei 159d alt |
| `netdefense-io/repo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `freelabz/secator` | GITHUB | IP-Datei 100d alt |
| `Dark-Avenger-Reborn/DEFpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nano-rs/nano` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `guilhermeescame/soc-homelab-wazuh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `clicksiem/clickdetect` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ugorur/os-zapret2` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `praetorian-inc/julius` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sv26000/nse-fno-watchlist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `anye1991/shield-waf-master` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Zarcolio/sitedorks` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `edoardottt/favirecon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `vigolium/vigolium` | GITHUB | IP-Datei 70d alt |
| `K3ysTr0K3R/INtrack` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `stanislav-web/OpenDoor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `projectdiscovery/urlfinder` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hett-patell/ShardLure` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mietzen/OPNware` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lopes/cordyceps` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Wootehfook/BoxdBuddies` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `chaser1780/CISR24` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `io12/pwninit` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `piklen/manmankan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `filipi86/drogonsec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Karib0u/rustinel` | GITHUB | Größe: 0 IPs |
| `MadokaProject/Madoka` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RasheedFarhat/DaC-Pipeline` | GITHUB | IP-Datei 31d alt |
| `presidio-v/presidio-hardened-vuln-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `turbot/tailpipe` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `cbuijs_hagezi` | GITHUB | 50,437 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 22,357 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 16,343 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 7,766 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,456 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 585 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 18,364 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 464 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 253 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,253 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,769 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,517 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 2,122 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,325 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,470 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,793 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,191 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 650 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 618 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 526 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 301 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 32,736 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 8,528 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 7,034 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 8,416 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 5,972 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,145 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 2,405 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 195,871 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,285 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 3,041 | 2.6% | 116 | 2026-07-05 |
| `breakingtechfr_proxy_free` | GITHUB | 29,347 | 0.6% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_all` | GITHUB | 32,012 | 0.5% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks4` | GITHUB | 7,200 | 1.9% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks5` | GITHUB | 5,942 | 2.2% | 55 | 2026-07-14 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,634 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 116,042 | 0.1% | 1560 | 2026-08-01 |
| `mohammedcha_proxripper` | GITHUB | 53,334 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,142 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,842 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,494 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 82,029 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,122 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 82,106 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 101,749 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,438 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 109,087 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 102,229 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 586 | 36.7% | 8 | 2026-07-03 |
| `darzanebor_mikroblack` | GITHUB | 41,628 | 26.6% | 13 | 2026-07-05 |
| `ankaboot_source_email_open_data` | GITHUB | 491,755 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,715 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,588 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 172,573 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 139,849 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 106,134 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 86,096 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 109,265 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 83,805 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 165,279 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 45,706 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 69,953 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 28,186 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 19,483 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 33,103 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 23,175 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 15,400 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 13,340 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 27,404 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 12,868 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 12,068 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 3,587 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 12,753 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 7,735 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,320 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 6,954 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 5,488 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 3,268 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,329 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,550 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,609 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 1,742 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,018 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 32,057 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,669 | 78.1% | 10 | 2026-07-31 |
| `ian_lusule_proxies` | GITHUB | 3,411 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,629 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 865 | 17.2% | 9 | 2026-07-08 |
| `sereinfy_adrules` | GITHUB | 1,414 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 81,886 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 254,185 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,277 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,479 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 5,451 | 2.6% | 7 | 2026-07-04 |
| `realizelol_torblocklist` | GITHUB | 1,545 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 44 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 62,303 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 66,816 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,043 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 101 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 196,764 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,719 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,661 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 181,761 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 25,109 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 7,435 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 3,577 | 34.1% | 2 | 2026-08-01 |
| `fadouse_clash_threat_intel` | GITHUB | 8,092 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 8,458 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 170,279 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,056 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,970 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 16,442 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,287 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 48,027 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 51,605 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,418 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 109,830 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 386 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 192,287 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 109,823 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 128,411 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,237 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 31,975 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 18,878 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 16,422 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,774 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 6,883 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 3,392 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,684 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,341 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 1,750 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 1,681 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,117 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,525 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,078 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,016 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 2,030 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,858 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,832 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,388 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 505 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 483 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 489 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,009 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 413 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,077 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 461 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,441 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 697 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,279 | 6.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_maltrail_scanners` | GITHUB | 16,854 | 14.9% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_iblocklist_cruzit_web_attacks` | GITHUB | 13,871 | 0.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 5,631 | 5.0% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,127 | 24.2% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,961 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,482 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 978 | 8.1% | 0 | 2026-07-31 |
| `bitwire_it_ip_list_fetch` | GITHUB | 33,197 | 24.7% | 0 | 2026-08-01 |
| `serp07_dude_blacklist_ip` | GITHUB | 4,628 | 31.6% | 0 | 2026-08-01 |

---
*Generiert: 2026-08-01 07:16 UTC*