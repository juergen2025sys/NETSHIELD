# Auto Feed Discovery – Report
**Aktualisiert:** 2026-09-04 22:08 CEST (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 5 |
| Kandidaten gesamt | **10916** |
| davon GitHub (Topics+Code) | **10833** |
| davon GitLab | **83** |
| davon Awesome-Lists | **2201** |
| Tools/Libraries vor Eval gefiltert | **844** |
| davon Hard-Reject (awesome-Liste etc.) | **188** |
| EVAL-Kandidaten (nach Stratifizierung) | **460** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **460** |
| davon angenommene Repositories | **1** |
| davon abgelehnte Repositories | **459** |
| Neu angenommene Feed-Dateien | **0** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **188** |
| Abgelehnte Repositories (dieser Run) | **459** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **188** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **160173** |
| SQLite-Refresh-Cache-Hits | **187/188** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **288** |
| Repo zu alt (>30d) | **144** |
| Falsche Größe (<30 / >2,000,000 IPs) | **20** |
| IP-Datei veraltet (>30d) | **7** |
| Sonstige | **1** |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `xxf098/LiteSpeedTest` | GITHUB | Zu alt: 1077d |
| `CriticalPathSecurity/Zeek-Intelligence-Feeds` | GITHUB | Identischer Inhalt wie kraloveckey_ipsets_blocklist_bds_atif |
| `stanfrbd/cyberbro` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GreedyBear-Project/GreedyBear` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ytisf/theZoo` | GITHUB | Zu alt: 42d |
| `a0rtega/pafish` | GITHUB | Zu alt: 805d |
| `D7EAD/mkPIVM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BiZken/PhishMailer` | GITHUB | Zu alt: 491d |
| `AbirHasan2005/ShellPhish` | GITHUB | Zu alt: 1716d |
| `m4n3dw0lf/pythem` | GITHUB | Zu alt: 2752d |
| `JoelGMSec/EvilnoVNC` | GITHUB | Zu alt: 486d |
| `Bhaviktutorials/shark` | GITHUB | Zu alt: 1419d |
| `hasanfirnas/symbiote` | GITHUB | Zu alt: 546d |
| `adamff-dev/ESP8266-Captive-Portal` | GITHUB | Zu alt: 1569d |
| `darkarp/chromepass` | GITHUB | Zu alt: 982d |
| `simplerhacking/Evilginx3-Phishlets` | GITHUB | Zu alt: 465d |
| `MyEtherWallet/ethereum-lists` | GITHUB | Zu alt: 51d |
| `0n1cOn3/FluxER` | GITHUB | Zu alt: 96d |
| `t4d/StalkPhish` | GITHUB | Zu alt: 907d |
| `Euronymou5/Doxxer-Toolkit` | GITHUB | Zu alt: 95d |
| `Err0r-ICA/Phishbait` | GITHUB | Zu alt: 465d |
| `AlteredSecurity/365-Stealer` | GITHUB | Zu alt: 182d |
| `EricksonAtHome/blackeye` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CanIPhish/Phishious` | GITHUB | Zu alt: 1238d |
| `RedSiege/EXCELntDonut` | GITHUB | Zu alt: 2172d |
| `spyboy-productions/Facad1ng` | GITHUB | Zu alt: 241d |
| `Akshay-Arjun/69phisher` | GITHUB | Zu alt: 566d |
| `Kl0ibi/esp32_hackingtool` | GITHUB | Zu alt: 799d |
| `Optane002/ZPhisher` | GITHUB | Zu alt: 1038d |
| `Cyber-Anonymous/Dark-Phish` | GITHUB | Zu alt: 711d |
| `cyberboyplas/WhPhisher` | GITHUB | Zu alt: 1435d |
| `taielab/Taie-AutoPhishing` | GITHUB | Zu alt: 1985d |
| `DRACULA-HACK/C-hacks` | GITHUB | Zu alt: 73d |
| `4w4k3/Umbrella` | GITHUB | Zu alt: 3399d |
| `sneakerhax/PyPhisher` | GITHUB | Zu alt: 874d |
| `ineesdv/Tangled` | GITHUB | Zu alt: 260d |
| `evildevill/EmptyPhish` | GITHUB | Zu alt: 1148d |
| `atexio/mercure` | GITHUB | Zu alt: 2007d |
| `alexbieber/SocioPhish` | GITHUB | Zu alt: 911d |
| `philomathic-guy/Malicious-Web-Content-Detection-Using-Machine-Learning` | GITHUB | Zu alt: 2163d |
| `phishingclub/phishingclub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cldrn/macphish` | GITHUB | Zu alt: 344d |
| `t4d/PhishingKitHunter` | GITHUB | Zu alt: 2783d |
| `t4d/PhishingKit-Yara-Rules` | GITHUB | Zu alt: 47d |
| `cybercdh/kitphishr` | GITHUB | Zu alt: 64d |
| `d-Rickyy-b/certstream-server-go` | GITHUB | Zu alt: 53d |
| `ninoseki/miteru` | GITHUB | Zu alt: 83d |
| `mschwager/gitem` | GITHUB | Zu alt: 1201d |
| `Toxic-Noob/Link-X` | GITHUB | Zu alt: 1288d |
| `FreeZeroDays/GoPhish-Templates` | GITHUB | Zu alt: 812d |
| `hxrofo/hotspotphisher` | GITHUB | Zu alt: 875d |
| `denniskniep/DeviceCodePhishing` | GITHUB | Zu alt: 350d |
| `polkadot-js/phishing` | GITHUB | Zu alt: 34d |
| `Discord-AntiScam/scam-links` | GITHUB | Zu alt: 244d |
| `Yezz123-Archive/Phisher` | GITHUB | Zu alt: 1862d |
| `R3LI4NT/articulos` | GITHUB | Zu alt: 40d |
| `DevVj-1/Hacking-Social_Media-Accounts` | GITHUB | Zu alt: 39d |
| `phish-report/IOK` | GITHUB | Zu alt: 498d |
| `salihpy/TgaHacking` | GITHUB | Zu alt: 1874d |
| `Flangvik/Bobber` | GITHUB | Zu alt: 817d |
| `tevora-threat/Dragnet` | GITHUB | Zu alt: 1334d |
| `OspreyProject/Osprey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IAmBlackHacker/Facebook-phishing` | GITHUB | Zu alt: 1647d |
| `LiveGray/OPENORCHID` | GITHUB | Zu alt: 1207d |
| `MrLuit/EtherScamDB` | GITHUB | Zu alt: 1367d |
| `martinsohn/Office-phish-templates` | GITHUB | Zu alt: 541d |
| `mamba-9mm/phishing` | GITHUB | Zu alt: 988d |
| `wariv/DarkLnk` | GITHUB | Zu alt: 415d |
| `mgeeky/VisualBasicObfuscator` | GITHUB | Zu alt: 1726d |
| `Altify-Developing/Altify-Developing-Main` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HiDe-Techno-Tips/Blackeye-for-Windows` | GITHUB | Zu alt: 1287d |
| `Arcanum-Sec/wraith` | GITHUB | Zu alt: 34d |
| `TYehan/SocialPhish` | GITHUB | Zu alt: 371d |
| `jackmichalak/phishim` | GITHUB | Zu alt: 1306d |
| `surajr/URL-Classification` | GITHUB | Zu alt: 1909d |
| `M4xSec/K-OTP-X` | GITHUB | Zu alt: 193d |
| `dsnezhkov/deepsea` | GITHUB | Zu alt: 2237d |
| `rubikproxy/rubikphish` | GITHUB | Zu alt: 680d |
| `dmdhrumilmistry/GooglePhish` | GITHUB | Zu alt: 107d |
| `bhikandeshmukh/Blackeye-v2.0` | GITHUB | Zu alt: 1524d |
| `Tanmay-Tiwaricyber/tphisher` | GITHUB | Zu alt: 1412d |
| `SiddhantOffl/cam-virus` | GITHUB | Zu alt: 1815d |
| `GSRHaX/NGL-Phish` | GITHUB | Zu alt: 73d |
| `manashma/BlackManPhishing` | GITHUB | Zu alt: 529d |
| `Schillings/SwordPhish` | GITHUB | Zu alt: 3143d |
| `idfp/masquerade` | GITHUB | Zu alt: 1212d |
| `Bitwise-01/ApeX` | GITHUB | Zu alt: 3157d |
| `HackWeiser360/MaxPhisher` | GITHUB | Zu alt: 850d |
| `Abhijeetbyte/Insta-login` | GITHUB | Zu alt: 806d |
| `EwyBoy/Counter-Phishing-Tool` | GITHUB | Zu alt: 818d |
| `t4d/StalkPhish-OSS` | GITHUB | Zu alt: 433d |
| `ariashirazi/InstaBrowser` | GITHUB | Zu alt: 1989d |
| `Mixore/Phishing-Discord-Servers-List` | GITHUB | Zu alt: 664d |
| `yogeshwaran01/maskurl` | GITHUB | Zu alt: 2041d |
| `cipheras/cipherginx` | GITHUB | Zu alt: 1408d |
| `sexettin78/sexettintool` | GITHUB | Zu alt: 477d |
| `CodingRanjith/autophisher` | GITHUB | Zu alt: 1481d |
| `Garrettiscool101/zphisher` | GITHUB | Zu alt: 51d |
| `LinkSec/phishing-templates` | GITHUB | Zu alt: 787d |
| `LetsDefend/Phishing-Email-Analysis` | GITHUB | Zu alt: 581d |
| `sky9262/phishEye` | GITHUB | Zu alt: 1701d |
| `Shlucus/FlipperZero-GooglePortal` | GITHUB | Zu alt: 370d |
| `SamueleAmato/exaPhisher` | GITHUB | Zu alt: 258d |
| `XiphosResearch/smsisher` | GITHUB | Zu alt: 3334d |
| `hoangminh5210119/deauther` | GITHUB | Zu alt: 1531d |
| `PHPAuth/PHPAuth` | GITHUB | Zu alt: 229d |
| `kulkansecurity/gitxray` | GITHUB | Zu alt: 238d |
| `cowrie/cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hacklcx/HFish` | GITHUB | Zu alt: 175d |
| `Webeoidentify/Honeypot-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `beelzebub-labs/beelzebub` | GITHUB | Größe: 0 IPs |
| `seccome/Ehoney` | GITHUB | Zu alt: 1053d |
| `markets/invisible_captcha` | GITHUB | Zu alt: 51d |
| `yunginnanet/HellPot` | GITHUB | Zu alt: 259d |
| `R00tS3c/DDOS-RootSec` | GITHUB | Zu alt: 701d |
| `DinoTools/dionaea` | GITHUB | Zu alt: 764d |
| `p1r06u3/opencanary_web` | GITHUB | Zu alt: 2024d |
| `aress31/wirespy` | GITHUB | Zu alt: 1420d |
| `DevSwanson/smart-contract-honeypot` | GITHUB | Zu alt: 242d |
| `DevSwanson/create-honeypot-token` | GITHUB | Zu alt: 242d |
| `tamimibrahim17/List-of-user-agents` | GITHUB | Zu alt: 1003d |
| `C4o/Juggler` | GITHUB | Zu alt: 288d |
| `utkusen/baitroute` | GITHUB | Zu alt: 598d |
| `TrisenYu/b0gus` | GITHUB | Zu alt: 65d |
| `bhdresh/Dejavu` | GITHUB | Zu alt: 398d |
| `DevSwanson/how-to-create-honeypot-token` | GITHUB | Zu alt: 242d |
| `jamesturk/django-honeypot` | GITHUB | Zu alt: 444d |
| `formr/formr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fffaraz/fakessh` | GITHUB | Zu alt: 55d |
| `Shmakov/Honeypot` | GITHUB | Zu alt: 250d |
| `HoneypotCode/How-to-Create-Honeypot-Token` | GITHUB | Zu alt: 380d |
| `spacesiren/spacesiren` | GITHUB | Zu alt: 1720d |
| `Phype/telnet-iot-honeypot` | GITHUB | Zu alt: 945d |
| `BINANCECONTRACT/How-to-Create-Honeypot-Token` | GITHUB | Zu alt: 721d |
| `RiskyMH/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SentryPeer/SentryPeer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `burpheart/hachimi` | GITHUB | Zu alt: 588d |
| `TheKingOfDuck/Loki` | GITHUB | Zu alt: 1695d |
| `jayus0821/Armor` | GITHUB | Zu alt: 1894d |
| `0xsha/sweetie-data` | GITHUB | Zu alt: 2381d |
| `Nirusu/how-to-setup-a-honeypot` | GITHUB | Zu alt: 1516d |
| `bediger4000/php-malware-analysis` | GITHUB | Zu alt: 1904d |
| `technicaldada/pentbox` | GITHUB | Zu alt: 338d |
| `lockness-Ko/xz-vulnerable-honeypot` | GITHUB | Zu alt: 885d |
| `Fausto-404/AlterHive` | GITHUB | Zu alt: 51d |
| `ginger51011/pandoras_pot` | GITHUB | Zu alt: 32d |
| `ivre/masscanned` | GITHUB | Zu alt: 79d |
| `leeberg/BlueHive` | GITHUB | Zu alt: 2627d |
| `valamidev/web3-defi-honeypot-and-slippage-checker` | GITHUB | Zu alt: 892d |
| `ANG13T/ESP8266-WiCon-Kit` | GITHUB | Zu alt: 1389d |
| `slowmist/blockchain-threat-intelligence` | GITHUB | Zu alt: 1727d |
| `andreicscs/HoneyWire` | GITHUB | IP-Datei 55d alt |
| `aau-network-security/HosTaGe` | GITHUB | Zu alt: 442d |
| `victpork/sshsyrup` | GITHUB | Zu alt: 2748d |
| `Turing-Space/Smart-Contract-Modular-Template` | GITHUB | Zu alt: 2342d |
| `dynatrace-oss/koney` | GITHUB | IP-Datei 249d alt |
| `dweinstein/canary` | GITHUB | Zu alt: 161d |
| `Plazmaz/MongoDB-HoneyProxy` | GITHUB | Zu alt: 1292d |
| `adityashrm21/RaspberryPi-Packet-Sniffer` | GITHUB | Zu alt: 2825d |
| `shantoroy/intro-2-cybersecurity-in-python` | GITHUB | Zu alt: 535d |
| `fhightower/ioc-finder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MISP/misp-workbench` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mushorg/glastopf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `deroux/longitudinal-analysis-cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0x4D31/honeylambda` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aelth/ddospot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mzweilin/ipv6-attack-detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `madirish/kojoney2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bjeborn/basic-auth-pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Masood-M/yalih` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yuchincheng/HpfeedsHoneyGraph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `miguelraulb/spamhat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pjlantz/Hale` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thinkst/opencanary` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cymmetria/ciscoasa_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DataSoft/Nova` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magisterquis/vnclowpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mkishere/sshsyrup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexbredo/honeypot-ftp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thomaspatzke/Log4Pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lcashdol/WAPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SecurityTW/delilah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kingtuna/go-emulators` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jadb/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Joss-Steward/honeypotDisplay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JustinAzoff/ssh-auth-logger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jeremyfritzen/Ethereum-honey-pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `czardoz/hornet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gfoss/phpmyadmin_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hexgolems/schem` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `packetflare/amthoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ncouture/MockSSH` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `inguardians/toms_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sahilm/hived` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `buffer/libemu` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mdp/honeypot.go` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `amv42/sshd-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ayrus/afterglow-cloud` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PaulMaddox/gohoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jordan-wright/elastichoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hbhzwj/imalse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xme/dshield-docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `urule99/jsunpack-n` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Novetta/delilah` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `threatstream/mhn` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Zeerg/helix-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `phin3has/mailoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gregcmartin/Kippo_JunOS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MattCarothers/mhn-core-docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bartnv/portlurker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LogoiLab/honeyup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `graneed/bwpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fzerorubigd/go0r` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrew-morris/kippo_detect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/manuka` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mfontani/kippo-stats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `schmalle/servletpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/bluepot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `f0rw4rd/potsnitch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/ghost-usb-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hexgolems/pint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `referefref/honeyfs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omererdem/honeything` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `securitygeneration/Honeyport` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sec51/honeymail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jpyorre/IntelligentHoneyNet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xiaoxiaoleo/HoneyMysql` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marist-Innovation-Lab/PasitheaHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CanadianJeff/honeywrt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ciscocsirt/dhp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eymengunay/EoHoneypotBundle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betheroot/pghoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christophe77/node-ftp-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ahoernecke/ensnare` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `m4rco-/dorothy2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rep/hpfeeds` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sreinhardt/Docker-Honeynet` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jedie/django-kippo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cymmetria/MTPot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johestephan/VerySimpleHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CERT-Polska/hsn2-bundle` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magisterquis/sshlowpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marist-Innovation-Lab/DolosHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hatching/vmcloak` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `run41/honey_ports` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `freak3dot/smart-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `upa/ofpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `batchmcnulty/Malbait` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ppacher/honeyssh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kungfuguapo/HoneyPress` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aplura/Tango` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mrschyte/dockerpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `csirtgadgets/csirtg-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shjalayeri/pwnypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ajackal/arctic-swallow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MartinIngesen/HonnyPotter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `honeynet/phoneyc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `magisterquis/sshhipot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `provos/honeyd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shiva-spampot/shiva` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `balte/TelnetHoney` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `antonsatt/ssh-radar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lnslbrty/potd` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ziemeck/bifrozt-ansible` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sefcom/honeyplc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cryptix720/HUDINX` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrewmichaelsmith/honeypot-setup-script` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jesparza/peepdf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alexbredo/honeypot-camera` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `secureworks/dcept` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SneakersInc/HoneyMalt` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gbrindisi/wordpot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `msurguy/Honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johnnykv/mnemosyne` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `codypierce/hackers-grep` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/flare-fakenet-ng` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sooshie/packerid` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lmco/laikaboss` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `9b/pdfxray_lite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hellman/xortool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `arkade-os/intent-solver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CircuitWall/jarela` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `destinorandagio/cryptoaid-trade-ai` | GITHUB | Größe: 0 IPs |
| `caiovicentino/opencode-remote` | GITHUB | Größe: 0 IPs |
| `Marianomrz/ContextoWeb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `obscurer-prune597/Akabaka-Crush-Landing-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `minibikeunbars7/Crush-Landing-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrei649/jarvis-hub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jupiter8nohate/computational-metacognitive-bilingualism` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jlbisconti2026/jorsat` | GITHUB | IP-Datei 439d alt |
| `zachbuilds26/somnus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yokel-coolie988141/Adobe-Fresco-Enhanced-Toolkit-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ghimiresaroj09/Futsal-BE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betwixthawked99459/Minecraft-Dungeons-II-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Benedikt14799/facebook-bot-command-center` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `openmen-gif/life-info-static` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kamisaberi/blackbox-sentinel` | GITHUB | Größe: 0 IPs |
| `jtmasters3/nfl-news-hub` | GITHUB | Größe: 0 IPs |
| `webziggy/deluxe-sonos-raycast-extension` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Fawwozer/My-RSS-merger` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RinkyDinkyNooble/piano-song-to-visual` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DereC4/internships-and-newgrad` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AswinNS-dev/DRISHYAM` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vukyn/hexarena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `musicman0917/WaterparkSimTwitchExpansion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CedricRandriamanjaka/dimitri-allodoudou-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qwertyuiopas17/netsentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `connorth3-lgtm/Injection-moulding-app-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mohabdelkarim/NexusFeed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iDev-Games/The-Open-Web-Directory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mavins8678-sycamore/SuckerForLove-CrushLanding-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `api-evangelist/uchecker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `UnknownDev2018/Kov-Sec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nichenke/nextup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omacom/omarchy-plugin-marketplace` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sebastien-ribiere/hands-on` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nodes-467105-dawdles/CONTROL-Resonant-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TyTheCyberGuy/VulnWire` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skylerblue333/skycoin4444` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `James-Lloyd/lean-agent-harness` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HNJAMeindersma/blacklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tragical728/void-ai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `offflinerpsy/base2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PersonalClaw/PersonalClaw` | GITHUB | Größe: 0 IPs |
| `espied423bribe/Emberville-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `satyasai2025/AstroOs` | GITHUB | Größe: 0 IPs |
| `justinwaddy/schwaddy-fpl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `anshul-agarwal3034/AEIS-NEW` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lucasmaiccol/Clinica-Odontologica` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Scubber/insider-intel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `moo-swarm/halo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `claudinhostgo-byte/WITEDUCA` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nisreendh05/Home-SOC-Lab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Xeno828/delivery-value-dashboard` | GITHUB | Größe: 0 IPs |
| `urosavurdic/dpo-safety-representations` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `stoatworks-labs/cathode-ray-tomes` | GITHUB | Größe: 0 IPs |
| `sandeepramaswamykashyap-coder/job-search-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `matthummel-pa/matthummel-theme` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `WellCod/multi-k` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `carped-2156-nickle/Ratchet-Clank-Rift-Apart-Enhanced-Tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ccp141995-oss/Trader-agent` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Allswap/funbo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fmsouza/lanekeep` | GITHUB | IP-Datei 35d alt |
| `shunts879380-bulking/Breathedge-2-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `k55kw7vw42-gif/before-you-buy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jwal7000/menu-display-horizontal` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `theodoreyong9/Jobber` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mukteshwar845/SEEMADRISHTI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tekguyz/tekguyz-site` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0306251282-ux/ardamax-keylogger-pro-tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `api-evangelist/trint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jgamblin/KalmanCVE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cueingovertime-20/The-Cabin-Game-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `adityajoshi18vk-art/Gigly-` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ultraviolet01/AgentBZ` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lukislp/studylife-focus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JoseRFJuniorLLMs/HeraclitusDB` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skinsdreamers6/EVE-Vanguard-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `StickyHashTr33/tx-surveillance-watch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `digifirst-org/egress-rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ziuus/Zervox` | GITHUB | Größe: 0 IPs |
| `yameenbux/Taiyabah-Mosque-Website-Rebrand` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LandDuck/merlin-box` | GITHUB | Größe: 0 IPs |
| `adassociate-client/Website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rikterskale/AdversaryFlow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `S4PAY/payhole` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `altamashh1/Dialect` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spydey74/lg-webos-bsc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wreckedbutchery30199/Cabin-Game-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Ganesh-0509/FreshFrame` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ratnesh-ml/SIH26100` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BillionVerify/disposable` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kittenhaswares-ui/SeitonSense` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RarDog/Lunaris` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nodes-467105-dawdles/Wanderburg-Game-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gouge43756settled/Forspoken-Ultimate-Enhancement-Kit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `k7raq/K7RAQQ` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SDCofA/mena-threat-index` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `migthyhbb/it_techno-project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `api-evangelist/tmt-id` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `alex-kzr/feature-pipeline-skill` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Vishwa-Pragnan2004/Insider-Threat-Behavioral-Intelligence-System` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rosined55-allying/Resonance-Plague-Tale-Legacy-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nattuuuzamiurai/kurume-bar-navi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ponds938-duskier/Portal-Alive-Kicking-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Gensiphone/team9960-website` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `yxpil/ADONWORD` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thakurishan9990-jpg/chakravyuh` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `digitalsigntech/claude-code-skills` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `copytolive/robinhood-mint-radar` | GITHUB | Größe: 0 IPs |
| `AndamAziz/Andamiptv` | GITHUB | IP-Datei 31d alt |
| `Electroingenieria-SAS/CRM-SUMINISTROS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bestwade22/polymarket-trader` | GITHUB | Größe: 0 IPs |
| `chroxify/floaty` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `api-evangelist/threattrack-security` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tuklusan/carrom-arena` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wazuh/wazuh-documentation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kabbalahmonster/robinhood-grid-bot-py` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `W-venemum/recover-or-restrict-system` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hashtagRR/AnonTestLab` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KPKrol85/DS-construction-pr02-Axiom` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `luisduran890815/luiseduardo-duran` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JKasteele/ai-act-companion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abbeys-606drone/Fell-Sell-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ziadnasif77-debug/VAI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Gmblos/Dribik` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vedantchouhan/vedantchouhan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `chandu12kumar/TsmEnterprises_Ecommerce` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `duolahypercho/codex-router` | GITHUB | Größe: 0 IPs |
| `Monkfish1337/Serioussportsync` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OneUptime/oneuptime` | GITHUB | IP-Datei 155d alt |
| `serenshreya/ring-sentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `skinsdreamers6/Wanderburg-Leaked-Build-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mehebub648/drop-network` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Anionex/dsh-tool-search` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `linny006/mcp-servers-live` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elleVas/briskcms` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jgamblin/NVDAnalysisStatus` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sbirkmann/site_makler1` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ahma-labs/ahma` | GITHUB | Größe: 0 IPs |
| `softtask-tech/dlx-dubai-shell` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `karanpargal/second-brain` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ErenOzusen/eren-muzik-atolyesi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andrew-barnett/slack-review-bot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bnymnDev/agentgate` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evozifans/judolguard-blocklists` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `adit-syntax/ResolvAI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jokeprimmest-1/Crimson-Moon-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bdubs2004/DropBite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `shreyanahar-cpu/AI-powered-Email-Threat-Detection-Forensics-Analysis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wfh86421/APFS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `milocaetano/quantick` | GITHUB | Größe: 0 IPs |
| `alexis-life/threats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bretesq/sdr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yashh027/FraudLensAI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `petfold/loopmarket` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `muurxdev/MeliodasBot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nodes-467105-dawdles/Shadow-of-the-Road-Leaked-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Numi2/numichart-news` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `erikvullings/procyon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CoPdasten/copsec` | GITHUB | Größe: 4 IPs |
| `CharlieMcVicker/parC-macros` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lunarmoon26/dsh-adaptive-loop` | GITHUB | Größe: 0 IPs |
| `NightVaporEquip/the-finals-aim-assistant` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TracecatHQ/tracecat` | GITHUB | IP-Datei 630d alt |
| `bilalhaider-ux/fraudlens` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `san3ncrypt3d/vulnometry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fleuris11/rssi-as-a-service` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `playboy150-status/Category-6-Trainer-2026` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rixxxxx/claudecode-docker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Sabermrddz/maitriser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tien-bap/url-safety-checker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Adityasiig/Voip-Honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `neutr0nslayer/Temporal-Botnet-Detection-using-Graph-Neural-Networks` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `api-evangelist/syntage` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bromenie2026-commits/Cointracker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NguyenQuan121321/FinnApiGo` | GITHUB | Größe: 0 IPs |
| `Jawa463728/DCFC-transfers` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abdellatifabouhou/lunea-skin` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Gh0s777tt/E-OS` | GITHUB | Größe: 0 IPs |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 29,049 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,480 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 9,461 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 11,228 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,867 | 0.2% | 120 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 6,640 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,740 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,947 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,952 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,231 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 2,978 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 1,878 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 897 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 567 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 571 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 459 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 269 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 53,741 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,452 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 17,217 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,332 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,770 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,798 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 3,043 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 213,714 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 5,175 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 2,882 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,641 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 123,904 | 0.1% | 1560 | 2026-08-01 |
| `hookzof_socks5_list` | GITHUB | 236 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 31,698 | 3.8% | 133 | 2026-09-04 |
| `mohammedcha_proxripper` | GITHUB | 53,119 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 113,477 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,845 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 115,617 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 93,598 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,240 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 92,454 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 104,419 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,688 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 124,292 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,394 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 113,888 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 564 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 484,889 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 219,174 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 171,697 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 182,370 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 147,454 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 129,972 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 108,303 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 129,040 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 104,362 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 214,874 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 69,870 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 150,601 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 35,152 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 25,417 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 25,448 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 22,346 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 19,152 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 36,568 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 16,368 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,193 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 10,144 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 18,143 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 9,686 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,451 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 9,223 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 6,454 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 1,901 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 10,889 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 4,579 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,759 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 862 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,279 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 3,044 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 9,066 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 3,513 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 81,359 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_apache` | GITHUB | 1,782 | 51.3% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 1,062 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 59,933 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 4,531 | 64.6% | 10 | 2026-08-09 |
| `ian_lusule_proxies` | GITHUB | 3,791 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 2,156 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,395 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 85,003 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 281,825 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,704 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,562 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 6,688 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,563 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 24 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 84,758 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 93,531 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,393 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 112 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 223,048 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 5,194 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,704 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 186,510 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 31,213 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 6,806 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 2,615 | 34.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_compromised` | GITHUB | 15,544 | 65.9% | 2 | 2026-08-01 |
| `securitylist1568_fortigate` | GITHUB | 143 | 28.1% | 2 | 2026-08-02 |
| `theouterspaced_ip_blocklist` | GITHUB | 44 | 34.1% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao` | GITHUB | 14,764 | 76.5% | 3 | 2026-08-09 |
| `runtechx_dns_runtech_ao_n2` | GITHUB | 14,755 | 76.5% | 3 | 2026-08-09 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,063 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,952 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 15,443 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,334 | 31.1% | 1 | 2026-07-14 |
| `fwahyui_masifa_ipblacklist` | GITHUB | 126,973 | 91.7% | 1 | 2026-08-16 |
| `idleadmin_threatfeed` | GITHUB | 55,033 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 58,276 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,760 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 133,254 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 467 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,169 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 194,079 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 133,248 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 164,968 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 33,900 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 21,363 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 15,543 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,747 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 6,484 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 9,627 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,655 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,580 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 5,000 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 4,728 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,118 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,537 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 2,667 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,872 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 1,038 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,093 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,368 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,396 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,394 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 1,330 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,289 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 962 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 1,147 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,039 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,026 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,489 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 716 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 2,468 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,889 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 1,235 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 14,722 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 91,823 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 93,488 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 94,036 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 92,358 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 91,340 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 90,919 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 88,590 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 24,247 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 44,771 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 316 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_firehol_level3` | GITHUB | 12,452 | 64.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,960 | 2.7% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_myip` | GITHUB | 1,013 | 46.3% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,250 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 14,720 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 43,612 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 20,975 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 13,561 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 5,872 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 51 | 63.9% | 0 | 2026-08-12 |
| `kraloveckey_ipsets_blocklist_ipwhois_bl` | GITHUB | 873 | 45.7% | 0 | 2026-08-15 |
| `zgzyh_malicious_website_detection` | GITHUB | 25,336 | 3.1% | 0 | 2026-08-15 |
| `claudiusdecimius_ioc_ipsets_firehol_level4` | GITHUB | 130,362 | 9.1% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_firehol_level2` | GITHUB | 22,851 | 54.9% | 0 | 2026-08-23 |
| `claudiusdecimius_ioc_ipsets_botscout_30d` | GITHUB | 3,741 | 5.1% | 0 | 2026-08-23 |

---
*Generiert: 2026-09-04 22:08 CEST (Europe/Berlin)*