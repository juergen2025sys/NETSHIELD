# Auto Feed Discovery – Report
**Aktualisiert:** 2026-05-28 18:24 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **6816** |
| davon GitHub (Topics+Code) | **6779** |
| davon GitLab | **37** |
| davon Awesome-Lists | **1018** |
| Tools/Libraries vor Eval gefiltert | **859** |
| davon Hard-Reject (awesome-Liste etc.) | **97** |
| EVAL-Kandidaten (nach Stratifizierung) | **212** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluiert | **219** |
| Neu angenommen | **5** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feeds aktualisiert | **25** |
| Abgelehnt (dieser Run) | **212** |
| davon GitLab abgelehnt | **2** |
| Feeds gesamt (aktiv) | **30** |
| IPs in seen_db bestätigt | **691129** |
| Neue IPs eingetragen | **7388** |
| seen_db gesamt | **4,766,027** |
| HQ-Referenz-IPs (6 Quellen) | **139481** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **153** |
| Repo zu alt (>30d) | **50** |
| IP-Datei veraltet (>30d) | **5** |
| Falsche Größe (<100 / >500k IPs) | **4** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `cbuijs_accomplist_plain_black_ipcidr` | [cbuijs/accomplist](https://github.com/cbuijs/accomplist) | GITHUB | 127,705 | 0.6% | 1.5% | 20 | 🆕 NEU |
| `cbuijs_accomplist_plain_black_ip4cidr` | [cbuijs/accomplist](https://github.com/cbuijs/accomplist) | GITHUB | 127,705 | 0.6% | 1.5% | 20 | 🆕 NEU |
| `turbolabit_zzfirewall_blacklist` | [TurboLabIt/zzfirewall](https://github.com/TurboLabIt/zzfirewall) | GITHUB | 85 | 66.4% | 0.0% | 0 | 🔄 Update |
| `wintergate_ic_wic_resources_permanent_blacklist_v3` | [WinterGate-IC/wic-resources](https://github.com/WinterGate-IC/wic-resources) | GITHUB | 508 | 67.0% | 0.0% | 0 | 🆕 NEU |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist_v2` | [mitchellkrogza/nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) | GITHUB | 10,628 | 75.0% | 0.0% | 4721 | 🆕 NEU |
| `kamalmjt_emerging_attackers_badips_txt` | [kamalmjt/emerging-attackers](https://github.com/kamalmjt/emerging-attackers) | GITHUB | 162,907 | 18.9% | 0.0% | 1 | 🆕 NEU |
| `ziyadnz_threat_intel_ip_feeds_ipv4_blacklist` | [ziyadnz/threat-intel-ip-feeds](https://github.com/ziyadnz/threat-intel-ip-feeds) | GITHUB | 106,405 | 36.7% | 0.0% | 8 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `utmstack/UTMStack` | GITHUB | Keine IP-Datei |
| `mandiant/capa` | GITHUB | Keine IP-Datei |
| `midwayjs/midway` | GITHUB | Keine IP-Datei |
| `rafaelfgx/DotNetCore` | GITHUB | Keine IP-Datei |
| `schorschii/RemotePointer-Server` | GITHUB | Keine IP-Datei |
| `frontendnetwork/veganify` | GITHUB | Keine IP-Datei |
| `greyhat-academy/lists.d` | GITHUB | Keine IP-Datei |
| `AdvDebug/Brovan` | GITHUB | Keine IP-Datei |
| `CERT-Polska/drakvuf-sandbox` | GITHUB | Keine IP-Datei |
| `x90skysn3k/brutespray` | GITHUB | Keine IP-Datei |
| `OWASP/Nettacker` | GITHUB | Keine IP-Datei |
| `ghluka/username-checker` | GITHUB | Keine IP-Datei |
| `sensepost/hash-cracker` | GITHUB | Größe: 0 IPs |
| `samuelcaldas/Bruteforce-Bootloader-Unlocker` | GITHUB | Keine IP-Datei |
| `chaitin/SafeLine` | GITHUB | Keine IP-Datei |
| `X-Stuff/CudaKeeloq` | GITHUB | Keine IP-Datei |
| `Antu7/python-bruteForce` | GITHUB | Keine IP-Datei |
| `animir/node-rate-limiter-flexible` | GITHUB | Keine IP-Datei |
| `threat9/routersploit` | GITHUB | Keine IP-Datei |
| `random-robbie/bruteforce-lists` | GITHUB | IP-Datei 2165d alt |
| `ariary/cfuzz` | GITHUB | Zu alt: 37d |
| `aryainjas/Microllect` | GITHUB | Zu alt: 42d |
| `telekom-security/tpotce` | GITHUB | Größe: 0 IPs |
| `beelzebub-labs/beelzebub` | GITHUB | Keine IP-Datei |
| `mushorg/glutton` | GITHUB | Keine IP-Datei |
| `mushorg/conpot` | GITHUB | Keine IP-Datei |
| `BlessedRebuS/Krawl` | GITHUB | Keine IP-Datei |
| `sjinks/mysql-honeypotd` | GITHUB | Keine IP-Datei |
| `SentryPeer/SentryPeer` | GITHUB | Keine IP-Datei |
| `jm33-m0/mec` | GITHUB | Zu alt: 1414d |
| `pwnesia/ssb` | GITHUB | Zu alt: 1623d |
| `InfosecMatter/SSH-PuTTY-login-bruteforcer` | GITHUB | Zu alt: 2014d |
| `mentat-is/gulp` | GITHUB | Keine IP-Datei |
| `benscha/KQLAdvancedHunting` | GITHUB | Keine IP-Datei |
| `Security-Onion-Solutions/securityonion` | GITHUB | Keine IP-Datei |
| `SlimKQL/Detections.AI` | GITHUB | Keine IP-Datei |
| `HugoLB0/Ransom0` | GITHUB | Keine IP-Datei |
| `FogSecurity/yes3-scanner` | GITHUB | Keine IP-Datei |
| `bhassani/WannacryDecompiled` | GITHUB | Keine IP-Datei |
| `JMousqueton/ransomware.live` | GITHUB | Zu alt: 31d |
| `PanagiotisDrakatos/JavaRansomware` | GITHUB | Zu alt: 40d |
| `avaje/avaje-inject` | GITHUB | Keine IP-Datei |
| `aptly-dev/aptly` | GITHUB | Keine IP-Datei |
| `wimpysworld/deb-get` | GITHUB | Keine IP-Datei |
| `valeriansaliou/bloom` | GITHUB | Keine IP-Datei |
| `tempesta-tech/tempesta` | GITHUB | Keine IP-Datei |
| `aaPanel/aaWAF` | GITHUB | Keine IP-Datei |
| `Altify-Developing/Altify-Developing-Main` | GITHUB | Keine IP-Datei |
| `RuiSiang/PoW-Shield` | GITHUB | Keine IP-Datei |
| `kyprizel/testcookie-nginx-module` | GITHUB | Keine IP-Datei |
| `0x00ctrl/CyberSec-Books` | GITHUB | Keine IP-Datei |
| `lance0/prefixd` | GITHUB | Keine IP-Datei |
| `noctiro/stormin` | GITHUB | Keine IP-Datei |
| `FunnyWolf/Viper` | GITHUB | Zu alt: 58d |
| `hakaioffsec/coffee` | GITHUB | Zu alt: 75d |
| `nickvourd/CS-Aggressor-Kit` | GITHUB | Zu alt: 77d |
| `D00Movenok/BounceBack` | GITHUB | Zu alt: 88d |
| `CDipper/Beacon` | GITHUB | Zu alt: 111d |
| `0xsh3llf1r3/ColdWer` | GITHUB | Zu alt: 119d |
| `CodeXTF2/bof_template` | GITHUB | Zu alt: 140d |
| `CodeXTF2/ScreenshotBOF` | GITHUB | Zu alt: 172d |
| `wwh1004/bof-template-ng` | GITHUB | Zu alt: 175d |
| `nickvourd/COM-Hunter` | GITHUB | Zu alt: 182d |
| `shaheeryasirofficial/Red-Team-Rust` | GITHUB | Zu alt: 185d |
| `andrecrafts/CobaltStrike-YARA-Bypass-f0b627fc` | GITHUB | Zu alt: 238d |
| `bluscreenofjeff/Red-Team-Infrastructure-Wiki` | GITHUB | Zu alt: 239d |
| `tdeerenberg/InlineWhispers3` | GITHUB | Zu alt: 323d |
| `lintstar/SharpHunter` | GITHUB | Zu alt: 408d |
| `CodeXTF2/WebcamBOF` | GITHUB | Zu alt: 428d |
| `CodeXTF2/WindowSpy` | GITHUB | Zu alt: 458d |
| `yqcs/ZheTian` | GITHUB | Zu alt: 475d |
| `chainski/AES-Encoder` | GITHUB | Zu alt: 561d |
| `fortra/No-Consolation` | GITHUB | Zu alt: 582d |
| `fortra/nanodump` | GITHUB | Zu alt: 618d |
| `001SPARTaN/aggressor_scripts` | GITHUB | Zu alt: 651d |
| `b1tg/cobaltstrike-beacon-rust` | GITHUB | Zu alt: 656d |
| `starnightcyber/Miscellaneous` | GITHUB | Zu alt: 678d |
| `naksyn/DojoLoader` | GITHUB | Zu alt: 695d |
| `Adminisme/ServerScan` | GITHUB | Zu alt: 711d |
| `D00Movenok/goMalleable` | GITHUB | Zu alt: 745d |
| `wangfly-me/LoaderFly` | GITHUB | Zu alt: 771d |
| `m3rcer/Chisel-Strike` | GITHUB | Zu alt: 794d |
| `ElJaviLuki/CobaltStrike_OpenBeacon` | GITHUB | Zu alt: 806d |
| `yutianqaq/CSx3Ldr` | GITHUB | Zu alt: 866d |
| `gloxec/CrossC2` | GITHUB | Zu alt: 920d |
| `Red-Hex-Consulting/Ankou` | GITHUB | Zu alt: 34d |
| `0xflux/Wyrm` | GITHUB | Zu alt: 74d |
| `JoasASantos/RTLC2` | GITHUB | Zu alt: 88d |
| `XPSec-Security/Ravage` | GITHUB | Zu alt: 90d |
| `malwarekid/OnlyShell` | GITHUB | Zu alt: 94d |
| `trsi-me/TS-OSINT` | GITHUB | Zu alt: 701d |
| `acidvegas/avoidr` | GITHUB | Zu alt: 932d |
| `stanford-esrg/gps` | GITHUB | Zu alt: 1206d |
| `elddy/NimScan` | GITHUB | Zu alt: 1568d |
| `prosopo/captcha` | GITHUB | Keine IP-Datei |
| `Dra-Ganzz/Premium-Call` | GITHUB | Keine IP-Datei |
| `nonPointer/uBlacklist-Subscription` | GITHUB | Größe: 1 IPs |
| `muneebwanee/InstaReporter` | GITHUB | Keine IP-Datei |
| `google/recaptcha` | GITHUB | Keine IP-Datei |
| `CleanTalk/php-antispam` | GITHUB | Keine IP-Datei |
| `fofapro/fapro` | GITHUB | Keine IP-Datei |
| `IllusiveNetworks-Labs/WebTrap` | GITHUB | Keine IP-Datei |
| `thomaspatzke/Log4Pot` | GITHUB | Keine IP-Datei |
| `bocajspear1/honeyhttpd` | GITHUB | Keine IP-Datei |
| `gfoss/phpmyadmin_honeypot` | GITHUB | Keine IP-Datei |
| `lanjelot/twisted-honeypots` | GITHUB | IP-Datei 2990d alt |
| `jeremyfritzen/Ethereum-honey-pot` | GITHUB | Keine IP-Datei |
| `sreinhardt/Docker-Honeynet` | GITHUB | Keine IP-Datei |
| `darkarnium/kako` | GITHUB | Keine IP-Datei |
| `MalwareTech/CitrixHoneypot` | GITHUB | Keine IP-Datei |
| `msurguy/Honeypot` | GITHUB | Keine IP-Datei |
| `aplura/Tango` | GITHUB | Keine IP-Datei |
| `free5ty1e/honeypotpi` | GITHUB | IP-Datei 4184d alt |
| `inguardians/toms_honeypot` | GITHUB | Keine IP-Datei |
| `ivre/masscanned` | GITHUB | Keine IP-Datei |
| `aelth/ddospot` | GITHUB | Keine IP-Datei |
| `droberson/ssh-honeypot` | GITHUB | IP-Datei 3433d alt |
| `kungfuguapo/HoneyPress` | GITHUB | Keine IP-Datei |
| `f0rw4rd/potsnitch` | GITHUB | Keine IP-Datei |
| `schmalle/Nodepot` | GITHUB | Keine IP-Datei |
| `ashmckenzie/go-sshoney` | GITHUB | Keine IP-Datei |
| `0x4D31/honeybits` | GITHUB | Keine IP-Datei |
| `ahoernecke/ensnare` | GITHUB | Keine IP-Datei |
| `referefref/honeyfs` | GITHUB | Keine IP-Datei |
| `nsmfoo/antivmdetection` | GITHUB | Keine IP-Datei |
| `buffer/pylibemu` | GITHUB | Keine IP-Datei |
| `freak3dot/smart-honeypot` | GITHUB | Keine IP-Datei |
| `miguelraulb/spamhat` | GITHUB | Keine IP-Datei |
| `bartnv/portlurker` | GITHUB | Keine IP-Datei |
| `WebDecoy/wordpress-plugin` | GITHUB | Keine IP-Datei |
| `referefref/SMTPLLMPot` | GITHUB | IP-Datei 909d alt |
| `Mojachieee/go-HoneyPot` | GITHUB | Keine IP-Datei |
| `threatstream/shockpot` | GITHUB | Keine IP-Datei |
| `sjhilt/GasPot` | GITHUB | Keine IP-Datei |
| `fw42/honeymap` | GITHUB | Keine IP-Datei |
| `buffer/libemu` | GITHUB | Keine IP-Datei |
| `securitygeneration/Honeyport` | GITHUB | Keine IP-Datei |
| `mzweilin/ipv6-attack-detector` | GITHUB | Keine IP-Datei |
| `hexgolems/pint` | GITHUB | Keine IP-Datei |
| `fygrave/honeyntp` | GITHUB | Keine IP-Datei |
| `Plazmaz/MongoDB-HoneyProxy` | GITHUB | Keine IP-Datei |
| `jordan-wright/elastichoney` | GITHUB | Keine IP-Datei |
| `mkishere/sshsyrup` | GITHUB | Keine IP-Datei |
| `yuchincheng/HpfeedsHoneyGraph` | GITHUB | Keine IP-Datei |
| `Marist-Innovation-Lab/DolosHoneypot` | GITHUB | Keine IP-Datei |
| `Masood-M/yalih` | GITHUB | Keine IP-Datei |
| `ls1911/GenAIPot` | GITHUB | Keine IP-Datei |
| `balte/TelnetHoney` | GITHUB | Keine IP-Datei |
| `joda32/owa-honeypot` | GITHUB | Keine IP-Datei |
| `jadb/honeypot` | GITHUB | Keine IP-Datei |
| `traetox/sshForShits` | GITHUB | Keine IP-Datei |
| `OWASP/Python-Honeypot` | GITHUB | Keine IP-Datei |
| `buffer/thug` | GITHUB | Keine IP-Datei |
| `Zeerg/helix-honeypot` | GITHUB | Keine IP-Datei |
| `blaverick62/SIREN` | GITHUB | Keine IP-Datei |
| `PaulMaddox/gohoney` | GITHUB | Keine IP-Datei |
| `gbrindisi/wordpot` | GITHUB | Keine IP-Datei |
| `hgascon/acapulco` | GITHUB | Keine IP-Datei |
| `JustinAzoff/ssh-auth-logger` | GITHUB | Keine IP-Datei |
| `amv42/sshd-honeypot` | GITHUB | Keine IP-Datei |
| `gitlab:pH-7/fake-admin-cp-honeypot-v1.2` | GITLAB | Zu alt: 2855d |
| `gitlab:swe_toast/privacy-filter` | GITLAB | Zu alt: 3165d |
| `ku5e/ku5e.github.io` | GITHUB | Keine IP-Datei |
| `adminlove520/github_cve_monitor` | GITHUB | Keine IP-Datei |
| `chalie56/proxy-multi-protocol-checker` | GITHUB | Keine IP-Datei |
| `Dstitronix/BIP39-RECOVERY-TOOL` | GITHUB | Keine IP-Datei |
| `Aro2105/Secra` | GITHUB | Keine IP-Datei |
| `ultrabanaan2009/MD_Audit` | GITHUB | Keine IP-Datei |
| `jbe2277/waf` | GITHUB | Keine IP-Datei |
| `adasd223/free-proxy-feed` | GITHUB | Keine IP-Datei |
| `ahahaabas/free-proxy-feed` | GITHUB | Keine IP-Datei |
| `Moraa1714/MSEP` | GITHUB | Keine IP-Datei |
| `votal-ai-hq/wb-red-team` | GITHUB | Keine IP-Datei |
| `mv12star/lista-telefonos-spam` | GITHUB | Keine IP-Datei |
| `nommichin7-a11y/CTC-PESU-IO-CourseResources` | GITHUB | Keine IP-Datei |
| `luoyinhu/MetaViewer` | GITHUB | Keine IP-Datei |
| `nigerbartus/Shai-Hulud-2.0-Detector` | GITHUB | Keine IP-Datei |
| `Jay01311/dns-honeypot` | GITHUB | Keine IP-Datei |
| `anilpoka-dev/anilpoka.site` | GITHUB | Keine IP-Datei |
| `K4Links/PWNNET-Toolkit` | GITHUB | Keine IP-Datei |
| `Ali786kumail/udwall` | GITHUB | Keine IP-Datei |
| `nikk8488/Unbreaking-News-2.0-Hackathon` | GITHUB | Keine IP-Datei |
| `Asafaraz/fpga_image` | GITHUB | Keine IP-Datei |
| `Gaplox00/Azure_GRC` | GITHUB | Keine IP-Datei |
| `jamcalli/Pulsarr` | GITHUB | Keine IP-Datei |
| `ommengman-prog/god-eye` | GITHUB | Keine IP-Datei |
| `Shreekant406/fuzzhound` | GITHUB | Keine IP-Datei |
| `georgi-i/bg-leaks-archive` | GITHUB | Keine IP-Datei |
| `ahmedriaz2004/NetSentry` | GITHUB | Keine IP-Datei |
| `tasiedev/telegram-account-osint` | GITHUB | Keine IP-Datei |
| `johnacelazatin/mail-osint-tools` | GITHUB | Keine IP-Datei |
| `Akarsolusi/inline-dlp-proxy` | GITHUB | Keine IP-Datei |
| `AleX-AA08/PhantomStego` | GITHUB | Keine IP-Datei |
| `Zantirim/Super-Champs-Game-Crypto-Bot-Auto-Farm-Clicker-Cheat-Api-Hack` | GITHUB | Keine IP-Datei |
| `user123-cry/Rynex` | GITHUB | Keine IP-Datei |
| `mmontalvo-sec/mmontalvo-sec.github.io` | GITHUB | Keine IP-Datei |
| `barestripehq/primer` | GITHUB | Keine IP-Datei |
| `binbi123/RedAudit-USB` | GITHUB | Keine IP-Datei |
| `guisant17/TerraSigma` | GITHUB | Keine IP-Datei |
| `mallahashok9239/Red-Team-Scaner-V2` | GITHUB | Keine IP-Datei |
| `beroboi/watchTowr-vs-Fortiweb-AuthBypass` | GITHUB | Keine IP-Datei |
| `0xCBradford/Vera5` | GITHUB | Größe: 1 IPs |
| `Alexinaja/public-api-list` | GITHUB | Keine IP-Datei |
| `pete731/sati` | GITHUB | Keine IP-Datei |
| `ahmadtgtv08/DNSint` | GITHUB | Keine IP-Datei |
| `mmontalvo-sec/mmontalvo-sec` | GITHUB | Keine IP-Datei |
| `Raanank10/Medical-C5-System-For-SAR` | GITHUB | Keine IP-Datei |
| `Quocton1/kali-linux-teaching-course-live` | GITHUB | Keine IP-Datei |
| `gtaiv005/PublicProxyList` | GITHUB | Keine IP-Datei |
| `LuffyAD/canary-stable` | GITHUB | Keine IP-Datei |
| `rightmost-substantivedye844/flutter_secret_exposed` | GITHUB | Keine IP-Datei |
| `IbdaaTec/AndroidDeviceRiskBookData` | GITHUB | Keine IP-Datei |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist_v2` | GITHUB | 10,628 | 75.0% | 4721 | 2026-05-28 |
| `cbuijs_accomplist` | GITHUB | 96,887 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 66,439 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_plain_black_ipcidr` | GITHUB | 127,705 | 0.6% | 20 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_ipv4_blacklist` | GITHUB | 106,405 | 36.7% | 8 | 2026-05-28 |
| `turntuptechnologies_iocs` | GITHUB | 61 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 38,121 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 94,911 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 21,155 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 100 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 220,922 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 7,923 | 69.0% | 4 | 2026-05-24 |
| `fadouse_clash_threat_intel` | GITHUB | 5,191 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 5,361 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips_txt` | GITHUB | 162,907 | 18.9% | 1 | 2026-05-28 |
| `idleadmin_threatfeed` | GITHUB | 49,732 | 41.9% | 0 | 2026-04-09 |
| `turbolabit_zzfirewall` | GITHUB | 99,243 | 66.4% | 0 | 2026-05-03 |
| `kraloveckey_ipsets_blocklist` | GITHUB | 16,854 | 13.1% | 0 | 2026-05-10 |
| `wintergate_ic_wic_resources_permanent_blacklist_v2` | GITHUB | 503 | 67.0% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 39,911 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_iblocklist_ciarmy_malicious` | GITHUB | 12,472 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_et_tor` | GITHUB | 7,500 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,414 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_blocklist_de_ssh` | GITHUB | 5,722 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_blocklist_de_bruteforce` | GITHUB | 731 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_snort_ip_blocklist` | GITHUB | 1,386 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_alienvault_reputation` | GITHUB | 609 | 13.1% | 0 | 2026-05-24 |
| `turbolabit_zzfirewall_blacklist` | GITHUB | 85 | 66.4% | 0 | 2026-05-28 |
| `wintergate_ic_wic_resources_permanent_blacklist_v3` | GITHUB | 508 | 67.0% | 0 | 2026-05-28 |

---
*Generiert: 2026-05-28 18:24 UTC*