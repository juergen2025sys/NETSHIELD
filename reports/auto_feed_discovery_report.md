# Auto Feed Discovery – Report
**Aktualisiert:** 2026-11-15 13:13 CET (Europe/Berlin)

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Discovery-Graph Seed-Repos | 30 |
| Discovery-Graph neue Kandidaten | 3 |
| Kandidaten gesamt | **11958** |
| davon GitHub (Topics+Code) | **11877** |
| davon GitLab | **81** |
| davon Awesome-Lists | **2214** |
| Tools/Libraries vor Eval gefiltert | **1023** |
| davon Hard-Reject (awesome-Liste etc.) | **221** |
| EVAL-Kandidaten (nach Stratifizierung) | **403** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **403** |
| davon angenommene Repositories | **0** |
| davon abgelehnte Repositories | **403** |
| Neu angenommene Feed-Dateien | **0** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **187** |
| Abgelehnte Repositories (dieser Run) | **403** |
| davon GitLab abgelehnt | **5** |
| Feeds gesamt (aktiv) | **187** |
| IPs direkt in seen_db geschrieben | **0 (Registry-only)** |
| Neue seen_db-IP-Eintraege durch AFD | **0** |
| seen_db | **nicht geoeffnet (bewusste Rollentrennung)** |
| Ablauf-Kandidaten Watchlist (30d) | **nicht geprueft – Combined ist allein zustaendig** |
| Ablauf-Kandidaten Active (180d) | **nicht geprueft – Combined ist allein zustaendig** |
| HQ-Referenz-IPs (6 Quellen) | **157359** |
| SQLite-Refresh-Cache-Hits | **0/191** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Keine IP-Datei im Repo | **235** |
| Repo zu alt (>30d) | **141** |
| Falsche Größe (<30 / >2,000,000 IPs) | **17** |
| IP-Datei veraltet (>30d) | **10** |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `Azure/Azure-Sentinel` | GITHUB | IP-Datei 1342d alt |
| `Entware/entware-packages` | GITHUB | IP-Datei 858d alt |
| `profullstack/threatcrush` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ThreatConnect-Inc/threatconnect-jobs` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hardex001-tech/Canary-Poison-Deception-Trap` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AmnestyTech/investigations` | GITHUB | Zu alt: 699d |
| `prodaft/malware-ioc` | GITHUB | Zu alt: 376d |
| `rastrea2r/rastrea2r` | GITHUB | Zu alt: 34d |
| `spyre-project/spyre` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gensecaihq/Shai-Hulud-2.0-Detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MotherSphere/NIKKE-Launcher-Check` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bad-antics/nullsec-logreaper` | GITHUB | Zu alt: 213d |
| `mirrormode/mirror-softcnkiller` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `realchendahuang/feedsieve` | GITHUB | Größe: 0 IPs |
| `Frostwarriormoon/synaphos-resp` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dr4gon123/flasi` | GITHUB | IP-Datei 196d alt |
| `maestron/botnets` | GITHUB | Zu alt: 1533d |
| `outflanknl/EvilClippy` | GITHUB | Zu alt: 1054d |
| `kai5263499/osx-security-awesome` | GITHUB | Zu alt: 33d |
| `CapacitorSet/box-js` | GITHUB | Zu alt: 136d |
| `SaumyajeetDas/GodGenesis` | GITHUB | Zu alt: 1014d |
| `vysecurity/morphHTA` | GITHUB | Zu alt: 1311d |
| `badchars/darknet-mcp-server` | GITHUB | Zu alt: 54d |
| `D3Ext/Hooka` | GITHUB | Zu alt: 684d |
| `NPMscan/npmscan-action` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `danielpoliakov/lisa` | GITHUB | Zu alt: 1294d |
| `hackirby/skuld` | GITHUB | Zu alt: 704d |
| `rf-peixoto/phishing_pot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `droidefense/engine` | GITHUB | Zu alt: 1432d |
| `chenerlich/FCL` | GITHUB | Zu alt: 2047d |
| `owasp-dep-scan/blint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Hagrid29/PELoader` | GITHUB | Zu alt: 1490d |
| `V1D1AN/S1EM` | GITHUB | Zu alt: 725d |
| `Squiblydoo/debloat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `diStyApps/Safe-and-Stable-Ckpt2Safetensors-Conversion-Tool-GUI` | GITHUB | Zu alt: 1342d |
| `cristianzsh/freki` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `abdulkadir-gungor/JPGtoMalware` | GITHUB | Zu alt: 1612d |
| `ThreatLabz/ransomware_notes` | GITHUB | Zu alt: 94d |
| `0x25bit/Updated-Carbanak-Source-with-Plugins` | GITHUB | Zu alt: 2755d |
| `d4rksystem/VBoxCloak` | GITHUB | Zu alt: 499d |
| `crocodyli/ThreatActors-TTPs` | GITHUB | Zu alt: 290d |
| `zeropointdynamics/zelos` | GITHUB | Zu alt: 1384d |
| `secrary/SSMA` | GITHUB | Zu alt: 2399d |
| `D3Ext/maldev` | GITHUB | Zu alt: 725d |
| `htr-tech/zphisher` | GITHUB | Zu alt: 816d |
| `skerkour/black-hat-rust` | GITHUB | Zu alt: 410d |
| `htr-tech/nexphisher` | GITHUB | Zu alt: 1495d |
| `Ignitetch/AdvPhishing` | GITHUB | Zu alt: 314d |
| `jaykali/maskphish` | GITHUB | Zu alt: 425d |
| `CrimsonForge-io/king-phisher` | GITHUB | Zu alt: 103d |
| `AdrMXR/KitHack` | GITHUB | Zu alt: 634d |
| `x0rz/phishing_catcher` | GITHUB | Zu alt: 824d |
| `chenjj/espoofer` | GITHUB | Zu alt: 1647d |
| `xiecat/goblin` | GITHUB | Zu alt: 1265d |
| `TheresAFewConors/Sooty` | GITHUB | Zu alt: 781d |
| `BiZken/PhishMailer` | GITHUB | Zu alt: 563d |
| `Raikia/FiercePhish` | GITHUB | Zu alt: 1041d |
| `AbirHasan2005/ShellPhish` | GITHUB | Zu alt: 1788d |
| `m4n3dw0lf/pythem` | GITHUB | Zu alt: 2824d |
| `JoelGMSec/EvilnoVNC` | GITHUB | Zu alt: 558d |
| `Bhaviktutorials/shark` | GITHUB | Zu alt: 1491d |
| `hasanfirnas/symbiote` | GITHUB | Zu alt: 618d |
| `pentestgeek/phishing-frenzy` | GITHUB | Zu alt: 1104d |
| `adamff-dev/ESP8266-Captive-Portal` | GITHUB | Zu alt: 1641d |
| `darkarp/chromepass` | GITHUB | Zu alt: 1054d |
| `simplerhacking/Evilginx3-Phishlets` | GITHUB | Zu alt: 537d |
| `MyEtherWallet/ethereum-lists` | GITHUB | Zu alt: 123d |
| `0n1cOn3/FluxER` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `t4d/StalkPhish` | GITHUB | Zu alt: 979d |
| `Err0r-ICA/Phishbait` | GITHUB | Zu alt: 537d |
| `EricksonAtHome/blackeye` | GITHUB | Zu alt: 101d |
| `AlteredSecurity/365-Stealer` | GITHUB | Zu alt: 254d |
| `spyboy-productions/Facad1ng` | GITHUB | Zu alt: 313d |
| `CanIPhish/Phishious` | GITHUB | Zu alt: 1310d |
| `Akshay-Arjun/69phisher` | GITHUB | Zu alt: 55d |
| `Kl0ibi/esp32_hackingtool` | GITHUB | Zu alt: 871d |
| `Optane002/ZPhisher` | GITHUB | Zu alt: 1110d |
| `phishdestroy/ScamIntelLogs` | GITHUB | IP-Datei 259d alt |
| `Cyber-Anonymous/Dark-Phish` | GITHUB | Zu alt: 783d |
| `curtbraz/PhishAPI` | GITHUB | Zu alt: 612d |
| `cyberboyplas/WhPhisher` | GITHUB | Zu alt: 1507d |
| `DRACULA-HACK/C-hacks` | GITHUB | Zu alt: 145d |
| `taielab/Taie-AutoPhishing` | GITHUB | Zu alt: 2057d |
| `duo-labs/isthislegit` | GITHUB | Zu alt: 1202d |
| `alexbieber/SocioPhish` | GITHUB | Zu alt: 983d |
| `phishingclub/phishingclub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `evildevill/EmptyPhish` | GITHUB | Zu alt: 1220d |
| `4w4k3/Umbrella` | GITHUB | Zu alt: 3471d |
| `ineesdv/Tangled` | GITHUB | Zu alt: 332d |
| `atexio/mercure` | GITHUB | Zu alt: 2079d |
| `philomathic-guy/Malicious-Web-Content-Detection-Using-Machine-Learning` | GITHUB | Zu alt: 2235d |
| `omergunal/PoT` | GITHUB | Zu alt: 3069d |
| `JoasASantos/ShadowPhish` | GITHUB | Zu alt: 576d |
| `cldrn/macphish` | GITHUB | Zu alt: 416d |
| `t4d/PhishingKitHunter` | GITHUB | Zu alt: 2855d |
| `t4d/PhishingKit-Yara-Rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `d-Rickyy-b/certstream-server-go` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cybercdh/kitphishr` | GITHUB | Zu alt: 47d |
| `ninoseki/miteru` | GITHUB | Zu alt: 155d |
| `DevVj-1/Hacking-Social_Media-Accounts` | GITHUB | Zu alt: 111d |
| `mschwager/gitem` | GITHUB | Zu alt: 1273d |
| `Toxic-Noob/Link-X` | GITHUB | Zu alt: 1360d |
| `R3LI4NT/articulos` | GITHUB | Zu alt: 112d |
| `hxrofo/hotspotphisher` | GITHUB | Zu alt: 947d |
| `denniskniep/DeviceCodePhishing` | GITHUB | Zu alt: 422d |
| `FreeZeroDays/GoPhish-Templates` | GITHUB | Zu alt: 884d |
| `polkadot-js/phishing` | GITHUB | Zu alt: 53d |
| `Arcanum-Sec/wraith` | GITHUB | Zu alt: 106d |
| `Yezz123-Archive/Phisher` | GITHUB | Zu alt: 1934d |
| `Discord-AntiScam/scam-links` | GITHUB | Zu alt: 316d |
| `salihpy/TgaHacking` | GITHUB | Zu alt: 1946d |
| `phish-report/IOK` | GITHUB | Zu alt: 570d |
| `tevora-threat/Dragnet` | GITHUB | Zu alt: 1406d |
| `OspreyProject/Osprey` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IAmBlackHacker/Facebook-phishing` | GITHUB | Zu alt: 1719d |
| `rsmusllp/king-phisher-templates` | GITHUB | Zu alt: 2615d |
| `LiveGray/OPENORCHID` | GITHUB | Zu alt: 1279d |
| `martinsohn/Office-phish-templates` | GITHUB | Zu alt: 613d |
| `MrLuit/EtherScamDB` | GITHUB | Zu alt: 1439d |
| `mamba-9mm/phishing` | GITHUB | Zu alt: 1060d |
| `rivetternregard/acid-test-osint-scam-checker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wariv/DarkLnk` | GITHUB | Zu alt: 487d |
| `Altify-Developing/Altify-Developing-Main` | GITHUB | Zu alt: 101d |
| `HiDe-Techno-Tips/Blackeye-for-Windows` | GITHUB | Zu alt: 1359d |
| `TYehan/SocialPhish` | GITHUB | Zu alt: 443d |
| `mgeeky/VisualBasicObfuscator` | GITHUB | Zu alt: 1798d |
| `duo-labs/phish-collect` | GITHUB | Zu alt: 1209d |
| `jackmichalak/phishim` | GITHUB | Zu alt: 1378d |
| `surajr/URL-Classification` | GITHUB | Zu alt: 1981d |
| `dsnezhkov/deepsea` | GITHUB | Zu alt: 2309d |
| `rubikproxy/rubikphish` | GITHUB | Zu alt: 752d |
| `SiddhantOffl/cam-virus` | GITHUB | Zu alt: 1887d |
| `dmdhrumilmistry/GooglePhish` | GITHUB | Zu alt: 179d |
| `bhikandeshmukh/Blackeye-v2.0` | GITHUB | Zu alt: 1596d |
| `Tanmay-Tiwaricyber/tphisher` | GITHUB | Zu alt: 1484d |
| `GSRHaX/NGL-Phish` | GITHUB | Zu alt: 145d |
| `manashma/BlackManPhishing` | GITHUB | Zu alt: 601d |
| `idfp/masquerade` | GITHUB | Zu alt: 1284d |
| `Schillings/SwordPhish` | GITHUB | Zu alt: 3215d |
| `Bitwise-01/ApeX` | GITHUB | Zu alt: 3229d |
| `HackWeiser360/MaxPhisher` | GITHUB | Zu alt: 922d |
| `Abhijeetbyte/Insta-login` | GITHUB | Zu alt: 878d |
| `t4d/StalkPhish-OSS` | GITHUB | Zu alt: 505d |
| `EwyBoy/Counter-Phishing-Tool` | GITHUB | Zu alt: 890d |
| `jaykali/shellphish` | GITHUB | Zu alt: 2324d |
| `yogeshwaran01/maskurl` | GITHUB | Zu alt: 2113d |
| `ariashirazi/InstaBrowser` | GITHUB | Zu alt: 2061d |
| `Garrettiscool101/zphisher` | GITHUB | Zu alt: 123d |
| `LinkSec/phishing-templates` | GITHUB | Zu alt: 859d |
| `CodingRanjith/autophisher` | GITHUB | Zu alt: 1553d |
| `Mixore/Phishing-Discord-Servers-List` | GITHUB | Zu alt: 736d |
| `cipheras/cipherginx` | GITHUB | Zu alt: 1480d |
| `hoangminh5210119/deauther` | GITHUB | Zu alt: 1603d |
| `LetsDefend/Phishing-Email-Analysis` | GITHUB | Zu alt: 653d |
| `sexettin78/sexettintool` | GITHUB | Zu alt: 549d |
| `sky9262/phishEye` | GITHUB | Zu alt: 1773d |
| `rsmusllp/king-phisher-plugins` | GITHUB | Zu alt: 2093d |
| `SamueleAmato/exaPhisher` | GITHUB | Zu alt: 330d |
| `Shlucus/FlipperZero-GooglePortal` | GITHUB | Zu alt: 442d |
| `P0cL4bs/flexphish` | GITHUB | Zu alt: 184d |
| `XiphosResearch/smsisher` | GITHUB | Zu alt: 3406d |
| `PHPAuth/PHPAuth` | GITHUB | Zu alt: 301d |
| `kulkansecurity/gitxray` | GITHUB | Zu alt: 310d |
| `hacklcx/HFish` | GITHUB | Zu alt: 247d |
| `beelzebub-labs/beelzebub` | GITHUB | IP-Datei 72d alt |
| `EmersonElectricCo/fsf` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cmu-sei/pharos` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fireeye/capa` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `keydet89/RegRipper2.8` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hurricanelabs/machinae` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomchop/unxor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jbremer/httpreplay` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sleuthkit/scalpel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lmco/laikaboss` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xd4d/de4dot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xd4d/dnSpy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `johnnykv/mnemosyne` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mateuszk87/PcapViz` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Storyyeller/Krakatau` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `plasma-disassembler/plasma` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `uppusaikiran/generic-parser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `micheloosterhof/cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `detuxsandbox/detux` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rocky/python-uncompyle6` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `crypto2011/IDR` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `malwaremusings/unpacker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `devttys0/binwalk` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `horsicq/Detect-It-Easy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pidydx/PyIOCe` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pidydx/SMRT` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hiddenillusion/AnalyzePE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `katjahahn/PortEx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Karneades/malware-persistence` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `elceef/dnstwist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aim4r/VolDiff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `williballenthin/EVTXtract` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Cisco-Talos/ROPMEMU` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Tencent/HaboMalHunter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `brad-accuvant/cuckoo-modified` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `nbeede/BoomBox` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `google/binnavi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `longld/peda` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Dynetics/Malfunction` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NtQuery/Scylla` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `p1ngul1n0/blackbird` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/xbox_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomnomnom/waybackurls` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hamodywe/telegram-scraper-TeleGraphite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Alaa-abdulridha/SerpScan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AccentuSoft/LinkScope_Client` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cybersader/WebsiteTechMiner-py` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `DataSploit/datasploit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `fauvidoTechnologies/PyBrowserAutomation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atenreiro/opensquat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `proxifly/free-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NPCmillionaire/dread-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wireservice/csvkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mantisfury/ArkhamMirror` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `projectdiscovery/dnsx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `its0x08/duckduckgo` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Belluxx/Aleph` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TeehanLax/Hyperlapse.js` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/lastfm_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zbetcheckin/Security_list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `six2dez/reconftw` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/steam_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tomsec8/IntelHub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sqren/fb-sleep-stats` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `khashashin/ogi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/Telegram-Archive` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `subzeroid/insto` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `seekr-osint/seekr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Turner-Levey/section-16-deadline-calculator` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jsvine/waybackpack` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `0xzerolight/topic_watch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ANG13T/SatIntel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NPCmillionaire/recap-cli` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `eth0izzle/the-endorser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `IvanGlinkin/CCTV` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Berchez/OSINT-steam` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ArthurHeitmann/arctic_shift` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vericle/intellyweave` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OSINTI4L/cupidcr4wl` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `owasp-amass/amass` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `AbdaullahAG/Threat_Intel_Project` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aydinnyunus/exiflooter` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `heldersepu/gmapcatcher` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `devdavidejesus/btc-toolkit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `snooppr/shotstars` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `atiilla/gitrecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `xPloits3c/DorkEye` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GreyNoise-Intelligence/pygreynoise` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sundowndev/PhoneInfoga` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s-rah/onionscan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hstsethi/in-mob-prefix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FlowingMedia/TimeFlow` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `drego85/tosint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `loseys/Oblivion` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `laramies/theHarvester` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `axmaier/tme-s` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/psn_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `matiash26/steam-osint` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `3nock/sub3suite` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `s0md3v/Zen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `akamhy/waybackpy` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `spmedia/Crypto-Scam-and-Crypto-Phishing-Threat-Intel-Feed` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `misiektoja/github_monitor` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `thalha-a9/helix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/Wayback-Archive` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `hmaverickadams/DeHashed-API-Tool` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Lissy93/personal-security-checklist` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dgtlmoon/changedetection.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `proseltd/Telepathy-Community` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `narkopolo/fb_friend_list_scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sockysec/Telerecon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `GeiserX/Wayback-Diff` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bibanon/tubeup` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Moresyl/metaclean` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `milo2012/osintstalker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gorhill/uBlock` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rmusser01/Infosec_Reference` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `vognik/maltego-telegram` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Bevigil/BeVigil-OSINT-CLI` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `momenbasel/keyFinder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cga-harvard/Data_Science_Big_Data_Projects` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:phishdestroy/ScamIntelLogs` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:phishdestroy/phishdestroy` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:phishdestroy/medium-archive-phishdestroy` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:phishdestroy/DestroyScammers` | GITLAB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gitlab:cyberintel-spain-ops/cyberintel-spain` | GITLAB | Zu alt: 39d |
| `RME-Solutions-Technology/cmail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `JesseBrown1980/Finite-universe-Yang-mills-existence-and-mass-gap-using-HEB-C` | GITHUB | Größe: 0 IPs |
| `kyvo-app/kyvo-app.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Miixms99/email-security-filter-rules` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `iam11thsiddharth/free-for-dev-contribution-deomail` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `omni-line/omni-audit` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LloydCoder/hezqen` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `NateshKannaR/Careverse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `jancykoud/hold` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `swol3y/phish-detector` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `surendra2304/FRIDAY-Universe` | GITHUB | Größe: 0 IPs |
| `botnoir4-AGI/nshe-combat-artifacts` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gina0513/Medicaid-Causal-Analysis` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ompweb-dev/ompweb` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ecoPrimal/wateringHole` | GITHUB | IP-Datei 37d alt |
| `RohitBishla/Travel-Inventory` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `maorun/rlcd-panel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `pandolien/project_amr` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `wpiotrw/MS_SOC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Arcotix/lunar-mission-viewer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `LeiterConsulting/splunk-version-value-explorer` | GITHUB | Größe: 0 IPs |
| `jefmextra/nino-lang` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `dob963/D10S_K-_2026-11-14` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenVibers/OpenVibe.Deals` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aalmaz1/AtsermyyRE` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `CrusaderBoy/CVEwatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `KleiKodesh/SeforimLibrarySearchEngine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `corekraft/kore` | GITHUB | Größe: 0 IPs |
| `tacplus-dev/looper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `VikramadityaOhlyan/Phishing-Website-Link-Checker` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenVibers/OpenVibe.Coupons` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tmittelstaedt/Windows-SNMP` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `StefanKnol/No-Return` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `concyafoyorwoth840-ui/Vendora-mobile-tooltik` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kudakaseke/ats-cv` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `oceanviolet/Utils` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mchen6/countinghouse` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `RumaizaNorova/wanderer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `starfancy/myPhotoGallery` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ovnice-dev/onechess` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `manish91082-coder/nexus-autonomous-cloud-work-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kvegh/aap_autodeploy_configascode` | GITHUB | Größe: 0 IPs |
| `newkit/OCW` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `tlsc-eng/daedalus` | GITHUB | IP-Datei 38d alt |
| `rootagi/scx_research` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zkf0587-lgtm/mint-radar` | GITHUB | Größe: 0 IPs |
| `ysm446/book-viewer` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `mkusaka/ghok` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `BeeJay805/RoomScape` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `PerryLink/dsh-score` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Trypiq-Concepts/networkwalks-intenship-week2` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gknoco/BOT-APZIN` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `trivenico/Yuki` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Qudit-Labs/Astro_Sapien` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sabin-glitch/turbodoctor-reels` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `d1vv1/firecrawl-scraper` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `EmotionalLeaves/Feed` | GITHUB | Größe: 0 IPs |
| `aminmozaffari23-cmyk/opencode-unlimited` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `adnanwahab/dear_congress` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `HilmiRidho/pemu` | GITHUB | Größe: 0 IPs |
| `DisColow/oeil-de-lynx` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rajesh1008/securing-ai-agents` | GITHUB | Größe: 0 IPs |
| `schorsch3000/Linkrot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `takumi-mr/AegisCMS` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `christianlinzatti/dashboard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sbstndalton/opencloud-bar` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `lowprocess/kicad2ems-ipc` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `cherdakmd/CHRDK_F_REGISTER` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `MeetTailor-Data/astro-ai-engine` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `robertfilay53-spec/TrueSpec` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Piyushjain1857/PJ-Study` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `TheHalfMoon/Ascout` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Marica7731/daily-song-list` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zanex-dev/kiss-shot` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `zapplyjobs/New-Grad-IT-Jobs-2027` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `bengasparian/bengasparian.github.io` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rayden-nicksari/Advanced-Lan-Scanner` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `moliyu1101/Phoenix` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `qluxtech/Asgard` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `aman-nitb-cse/Aurex-Browser` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `betterix/league-voice-recorder` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `ridaabbas000000-cloud/Network-Detection-and-Response-SOC-Investigation` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `andreafis/andreaserver` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `secbyarafai/Snort-Sentinel` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SadmaFaahiim/perks-man` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `OpenVibers/OpenVibe.Chat` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Umangpatel5122006/NLP-for-Cyber-Threat-Intelligence-Extraction` | GITHUB | Größe: 5 IPs |
| `beyond-repair/informational-flux-identity` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Aertun/Aertun` | GITHUB | IP-Datei 42d alt |
| `Matalin25/matalin-portfolio` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `SamSjosten/OSRSPS` | GITHUB | Größe: 0 IPs |
| `YahnLP/CyberLab` | GITHUB | Größe: 0 IPs |
| `patrickdugan/MathCan` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `FSOldierrr/FSODefender` | GITHUB | Größe: 0 IPs |
| `ogowoo/gantry` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Xilleet/caribbean_trade` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `realzephaniahjohnson/mothlight-honeypot-data` | GITHUB | Größe: 0 IPs |
| `Olexxee/Logistic-Hub` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Wael-Adel-Shfq/Tabibi` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sarthakdev143-lite/toolwarden` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `gotedyz/mirai` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `kumarb123243-pixel/echoalert` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Yashvir-13/sira` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Popoboxxo/ReqogniLoom` | GITHUB | IP-Datei 75d alt |
| `OpenVibers/OpenVibe.Blog` | GITHUB | Größe: 0 IPs |
| `Mehedisohel/Unibudget_backend` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `margotrneveux-pixel/Attune-Landing-Page` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `einavh550/STM32-SmartNIC` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `Andre3456-del/Studies` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `sumitgoxlofficial-jpg/Medoro` | GITHUB | Größe: 0 IPs |
| `scriptzteam/TorBridgeWatch` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |
| `rawtonic-app/rawtonic` | GITHUB | IP-Datei 35d alt |
| `fountainnnnn/NASA-Hackathon` | GITHUB | Keine IP-Datei (Name/Inhalt/Extern) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 21,091 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 18,078 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 8,450 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,695 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 499,803 | 0.2% | 120 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 2,135 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 2,402 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 358 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,195 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 555 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 497 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 404 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 247 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 54,974 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 18,974 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 20,600 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 13,231 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,368 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,956 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 6,860 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 216,596 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,488 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 6,874 | 2.6% | 116 | 2026-07-05 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,633 | 93.4% | 4764 | 2026-07-22 |
| `hookzof_socks5_list` | GITHUB | 4,760 | 22.1% | 1030 | 2026-08-04 |
| `criticalpathsecurity_public_intelligence_feeds` | GITHUB | 32,722 | 3.8% | 133 | 2026-09-04 |
| `bert_janp_open_source_threat_intel_feeds` | GITHUB | 4,662 | 64.3% | 938 | 2026-09-04 |
| `cbuijs_hagezi` | GITHUB | 29,578 | 37.9% | 129 | 2026-11-08 |
| `mohammedcha_proxripper` | GITHUB | 53,374 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,840 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 116,927 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 118,605 | 0.2% | 36 | 2026-07-05 |
| `telekom_security_listbot` | GITHUB | 521 | 10.4% | 22 | 2026-10-18 |
| `dinoz0rg_proxy_list` | GITHUB | 91,985 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 1,831 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 94,991 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 110,042 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 65,227 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 129,639 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 16,295 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 95,210 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 584 | 36.7% | 8 | 2026-07-03 |
| `ankaboot_source_email_open_data` | GITHUB | 498,786 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 220,071 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 174,815 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 91,408 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 173,910 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 176,195 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 89,865 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 85,811 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 289,696 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 63,889 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 228,051 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 25,159 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 13,180 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 11,683 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 276,147 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 14,720 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 12,075 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 10,346 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 27,973 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 16,322 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 13,630 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 26,662 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,043 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,079 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,463 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 2,809 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 721 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,199 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 3,242 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,045 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,226 | 29.9% | 10 | 2026-08-02 |
| `configserverapps_service_blocklists_ssh_365d` | GITHUB | 138,668 | 54.2% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_attacks_bruteforce` | GITHUB | 697 | 47.1% | 10 | 2026-08-08 |
| `configserverapps_service_blocklists_blocklist` | GITHUB | 29,116 | 40.5% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_all_1d` | GITHUB | 3,331 | 64.6% | 10 | 2026-08-09 |
| `configserverapps_service_blocklists_ssh_bruteforce_attackers` | GITHUB | 3,683 | 79.4% | 10 | 2026-09-24 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 4,299 | 64.3% | 10 | 2026-10-11 |
| `ian_lusule_proxies` | GITHUB | 2,979 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,511 | 3.4% | 9 | 2026-07-05 |
| `sereinfy_adrules` | GITHUB | 1,365 | 12.2% | 7 | 2026-08-01 |
| `gazpitchy92_ip_blocklist` | GITHUB | 409,157 | 22.0% | 6 | 2026-07-08 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,360 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 28 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 106,397 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 105,783 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 23,373 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 140 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 104,347 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 4,988 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,753 | 69.0% | 4 | 2026-06-28 |
| `securitylist1568_fortigate` | GITHUB | 73 | 28.1% | 2 | 2026-08-02 |
| `runtechx_dns_runtech_ao` | GITHUB | 20,439 | 76.5% | 3 | 2026-08-09 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 30,544 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,418 | 31.1% | 1 | 2026-07-14 |
| `klonet_it_ip_threat_lists` | GITHUB | 136,991 | 51.5% | 1 | 2026-10-11 |
| `klonet_it_ip_threat_lists_blocklist_apache` | GITHUB | 9,037 | 9.7% | 1 | 2026-10-11 |
| `idleadmin_threatfeed` | GITHUB | 49,394 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 75,273 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 6,989 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 136,075 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,164 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 198,010 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 136,069 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 225,419 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,105 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 39,353 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 494 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 14,690 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 18,171 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,690 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 9,085 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 7,742 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,614 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 6,559 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 4,000 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 3,793 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,118 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,530 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 3,613 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,484 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 751 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 7,010 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,021 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,260 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 1,083 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 990 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 1,061 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 1,161 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 812 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,099 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 1,026 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,300 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 583 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,968 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,438 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 976 | 8.1% | 0 | 2026-07-31 |
| `cercatrova21_blocklist` | GITHUB | 26,474 | 44.4% | 0 | 2026-08-08 |
| `feezony_feezony_ip_inbound_blocklist_split` | GITHUB | 93,547 | 1.3% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | GITHUB | 89,200 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | GITHUB | 92,724 | 2.5% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | GITHUB | 92,885 | 1.4% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | GITHUB | 90,320 | 2.1% | 0 | 2026-08-09 |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | GITHUB | 91,849 | 1.4% | 0 | 2026-08-09 |
| `taylored_itmail_blacklists` | GITHUB | 110,194 | 5.9% | 0 | 2026-08-09 |
| `obarve_rr37_malicious_ip_blocklist` | GITHUB | 23,712 | 73.5% | 0 | 2026-08-09 |
| `kennybayram_soc_feeds` | GITHUB | 37,426 | 49.2% | 0 | 2026-08-09 |
| `hezhidong_scanguard` | GITHUB | 323 | 91.3% | 0 | 2026-08-10 |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | GITHUB | 3,659 | 2.7% | 0 | 2026-08-10 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_7d` | GITHUB | 1,000 | 5.7% | 0 | 2026-08-11 |
| `theseuss_usom_siber_edl` | GITHUB | 15,660 | 5.8% | 0 | 2026-08-11 |
| `oktayalver_siberkapan_list` | GITHUB | 38,162 | 23.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_all_feed` | GITHUB | 18,580 | 53.4% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_honeypot_feed` | GITHUB | 11,224 | 46.6% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_nginx_feed` | GITHUB | 3,603 | 71.1% | 0 | 2026-08-12 |
| `oktayalver_siberkapan_list_fortigate_feed` | GITHUB | 23 | 63.9% | 0 | 2026-08-12 |
| `zgzyh_malicious_website_detection` | GITHUB | 33,747 | 3.1% | 0 | 2026-08-15 |
| `infosec_tr_usom_ioc_sync` | GITHUB | 6,890 | 7.6% | 0 | 2026-09-04 |
| `claudiusdecimius_ics_ip` | GITHUB | 18,164 | 9.3% | 0 | 2026-09-13 |
| `brandontroidl_blocklist` | GITHUB | 6,365 | 67.4% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_30d` | GITHUB | 3,579 | 69.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_7d` | GITHUB | 1,318 | 61.7% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_all_24h` | GITHUB | 489 | 65.2% | 0 | 2026-09-24 |
| `brandontroidl_blocklist_standard` | GITHUB | 227 | 52.5% | 0 | 2026-09-24 |
| `blessedrebus_krawl` | GITHUB | 11,597 | 20.6% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split` | GITHUB | 95,012 | 0.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_36` | GITHUB | 98,254 | 1.5% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_23` | GITHUB | 94,591 | 1.9% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_31` | GITHUB | 92,607 | 2.2% | 0 | 2026-09-24 |
| `feezony_feezony_ip_blocklist_split_ipblocklist_part_22` | GITHUB | 97,236 | 2.1% | 0 | 2026-09-24 |
| `claudiusdecimius_threatfox` | GITHUB | 34,792 | 1.5% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc` | GITHUB | 5,245 | 84.6% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_indicators` | GITHUB | 5,185 | 84.4% | 0 | 2026-09-25 |
| `zikmadol_trapline_ioc_ai_infra` | GITHUB | 1,751 | 76.9% | 0 | 2026-09-25 |
| `brandontroidl_blocklist_all_90d` | GITHUB | 6,583 | 61.9% | 0 | 2026-10-11 |
| `brandontroidl_blocklist_aggressive` | GITHUB | 68 | 80.9% | 0 | 2026-10-11 |
| `helio4k_bad_ip` | GITHUB | 2,355 | 43.3% | 0 | 2026-10-25 |
| `verkombr_block_list_firewalls` | GITHUB | 913 | 46.9% | 0 | 2026-10-25 |
| `blawoblowa_blackened` | GITHUB | 1,328 | 56.0% | 0 | 2026-11-01 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 7,039 | 13.1% | 0 | 2026-11-08 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,221 | 69.7% | 0 | 2026-11-08 |

---
*Generiert: 2026-11-15 13:13 CET (Europe/Berlin)*