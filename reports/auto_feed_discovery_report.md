# Auto Feed Discovery – Report
**Aktualisiert:** 2026-08-03 15:47 UTC

---
## Zusammenfassung

| Metrik | Wert |
|---|---|
| Kandidaten gesamt | **9723** |
| davon GitHub (Topics+Code) | **9646** |
| davon GitLab | **77** |
| davon Awesome-Lists | **2209** |
| Tools/Libraries vor Eval gefiltert | **703** |
| davon Hard-Reject (awesome-Liste etc.) | **187** |
| EVAL-Kandidaten (nach Stratifizierung) | **500** |
| davon bereits rejected (übersprungen) | **0** |
| davon bereits approved (übersprungen) | **0** |
| tatsächlich evaluierte Repositories | **500** |
| davon angenommene Repositories | **2** |
| davon abgelehnte Repositories | **498** |
| Neu angenommene Feed-Dateien | **2** |
| davon aus GitLab | **0** |
| davon aus Awesome-Lists | **0** |
| Bestehende Feed-Dateien aktualisiert | **171** |
| Abgelehnte Repositories (dieser Run) | **498** |
| davon GitLab abgelehnt | **0** |
| Feeds gesamt (aktiv) | **173** |
| IPs in seen_db bestätigt | **3184189** |
| Neue IPs eingetragen | **25002** |
| seen_db gesamt | **14,579,106** |
| HQ-Referenz-IPs (6 Quellen) | **110296** |

---
## 📊 Reject-Gründe (dieser Run)

| Grund | Anzahl |
|---|---|
| Repo zu alt (>30d) | **240** |
| Keine IP-Datei im Repo | **224** |
| IP-Datei veraltet (>30d) | **23** |
| Falsche Größe (<100 / >2,000,000 IPs) | **7** |
| Overlap mit HQ-Feeds zu gering (<20%) | **3** |
| False-Positive-Rate zu hoch (>5%) | **1** |

---
## ✅ Angenommene Feeds

| Feed | Repo | Plattform | IPs | Overlap | FP-Rate | Stars | Status |
|---|---|---|---|---|---|---|---|
| `bilsectr_sgb_api_bridge` | [bilsectr/sgb-api-bridge](https://github.com/bilsectr/sgb-api-bridge) | GITHUB | 15,077 | 5.7% | 0.0% | 9 | 🆕 NEU |
| `romainmarcoux_misc_ip_lists` | [romainmarcoux/misc-ip-lists](https://github.com/romainmarcoux/misc-ip-lists) | GITHUB | 3,584 | 19.8% | 0.0% | 5 | 🆕 NEU |

---
## ❌ Abgelehnte Repos

| Repo | Plattform | Grund |
|---|---|---|
| `fastrevmd-lab/firewallintentconverter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `netcanon/netcanon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `brojangles24/BlocklistAggregate` | GITHUB | Größe: 0 IPs |
| `GhostKellz/ckelley.dev` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Vaibhav-gadhave/StudyMaterial` | GITHUB | Zu alt: 85d |
| `cleverg0d/threat-feeds` | GITHUB | IP-Datei 389d alt |
| `MFIRoadMap/Fortinet-Product-Notes` | GITHUB | Zu alt: 407d |
| `expressemotion/kvstore-syncthing` | GITHUB | Zu alt: 171d |
| `yuliussetyawan/network-lab` | GITHUB | Zu alt: 47d |
| `kidrek/VigilIntel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MM0x02/RSS-Push` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DASD-Panthers/Fortigate-Threat-Feeds` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AriCourcy/Veille_Techno_H25` | GITHUB | Zu alt: 417d |
| `d3ckx1/today-news` | GITHUB | Zu alt: 634d |
| `abrhim1/malicious-ip` | GITHUB | Zu alt: 408d |
| `fabriziosalmi/asn-api` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `pcardotatgit/XDR_Workflows_and_Stuffs` | GITHUB | Zu alt: 327d |
| `mahmoudahmed3132/soar-lite` | GITHUB | Zu alt: 127d |
| `Arpitapaaul/SIEM-Lite` | GITHUB | Zu alt: 32d |
| `SumoLogic/cloud-siem-content-catalog` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheLurkas/SOC` | GITHUB | Zu alt: 133d |
| `101zh/FortiGate40FWLANControllerLab` | GITHUB | Zu alt: 78d |
| `GhostKellz/fortigate` | GITHUB | Zu alt: 124d |
| `shellsec/SECDaily` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fortinet/aws-lambda-guardduty-v2` | GITHUB | Zu alt: 264d |
| `domis-corp/huntershield` | GITHUB | Zu alt: 335d |
| `peterreyess123/fortigate7.6-chapter-key-takeaways` | GITHUB | Zu alt: 419d |
| `opnsense/lang` | GITHUB | Zu alt: 109d |
| `yuvalg72/Cyber_Security-Blocklist-Compilation` | GITHUB | Zu alt: 342d |
| `pulumiverse/pulumi-fortios` | GITHUB | Zu alt: 755d |
| `Mano-Abdeen/Firewall-Policy-Anomaly-Analyzer` | GITHUB | Zu alt: 31d |
| `tbrmidwest27/fwforge` | GITHUB | IP-Datei 54d alt |
| `jwhitt3r/intel.overresearched.net` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `neostar-ja/wazuh_ova` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LL7Baucarre/ELASLIP` | GITHUB | Zu alt: 181d |
| `simonpainter/www.simonpainter.com` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `juergen2025sys/NETSHIELD` | GITHUB | Größe: 0 IPs |
| `poroping/terraform-provider-fortimanagerdvdb` | GITHUB | Zu alt: 798d |
| `fortinetdev/terraform-provider-fmgdevice` | GITHUB | Zu alt: 95d |
| `CTI-Buddy/cti-buddy.github.io` | GITHUB | Zu alt: 277d |
| `groovy-sky/gmuv` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jkerai1/SoftwareCertificates` | GITHUB | IP-Datei 668d alt |
| `BeardedInfoSec/t1agentics` | GITHUB | IP-Datei 63d alt |
| `huynhtrungcsc/sonaro-gate` | GITHUB | Zu alt: 98d |
| `Joana-Cabral/CVSS_Prediction` | GITHUB | Zu alt: 772d |
| `SpyL1nk/fortigate_default_config` | GITHUB | Zu alt: 876d |
| `first20hours/google-10000-english` | GITHUB | Zu alt: 1174d |
| `daviddao/awful-ai` | GITHUB | Zu alt: 529d |
| `nv-tlabs/SCube` | GITHUB | Zu alt: 293d |
| `PKU-Alignment/safe-rlhf` | GITHUB | Zu alt: 252d |
| `punishell/bbtips` | GITHUB | Zu alt: 368d |
| `TheAlanNix/cisco-security-tools` | GITHUB | Zu alt: 1334d |
| `sbhooley/ainativelang` | GITHUB | Zu alt: 39d |
| `hyunjun/bookmarks` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yitu-opensource/ConvBert` | GITHUB | Zu alt: 1399d |
| `temm1e-labs/temm1e` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LycheeMem/LycheeMem` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tmgthb/Autonomous-Agents` | GITHUB | Zu alt: 40d |
| `MontrealAI/AGI-Alpha-Agent-v0` | GITHUB | Zu alt: 95d |
| `FlagOpen/FlagData` | GITHUB | Zu alt: 781d |
| `mikeroyal/Parrot-Security-Guide` | GITHUB | Zu alt: 1819d |
| `Abhinavbwj/Claude-skills-for-Computational-Designers` | GITHUB | Zu alt: 130d |
| `guy032/InfraQuery` | GITHUB | Zu alt: 272d |
| `mikeroyal/Fedora-Guide` | GITHUB | Zu alt: 942d |
| `CiscoDevNet/foundry-security-spec` | GITHUB | Zu alt: 83d |
| `claude-did-this/claude-hub` | GITHUB | Zu alt: 280d |
| `tradle/why-hypercore` | GITHUB | Zu alt: 713d |
| `arstgit/high-frequency-vocabulary` | GITHUB | Zu alt: 2400d |
| `sookinoby/sentiment-analysis2` | GITHUB | Zu alt: 3233d |
| `CES-Ltd/TitanX` | GITHUB | Zu alt: 104d |
| `arthurpanhku/DocSentinel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `costinEEST/almanacs` | GITHUB | Zu alt: 70d |
| `rcortx/kiwiq` | GITHUB | Zu alt: 112d |
| `ashhart/TensorFold` | GITHUB | Zu alt: 41d |
| `sheawinkler/hermes-agent-ultra` | GITHUB | IP-Datei 51d alt |
| `stepfun-ai/Step-3.7-Flash` | GITHUB | Zu alt: 63d |
| `dkyazzentwatwa/osint-ai` | GITHUB | Zu alt: 149d |
| `abdullaalhussein/soc-training-simulator` | GITHUB | Zu alt: 116d |
| `VilledeMontreal/urban-detection` | GITHUB | Zu alt: 1797d |
| `GreedyBear-Project/GreedyBear` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ioc-fang/ioc-fanger` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HadiKhoirudin/Qualcomm-Tool-GUI` | GITHUB | Zu alt: 1335d |
| `Red5d/edlkit` | GITHUB | Zu alt: 890d |
| `Mrivai/Xiaomi-Service-Tool` | GITHUB | Zu alt: 1415d |
| `CosmicDan-Android/MiA1LowLevelBackupRestoreTool` | GITHUB | Zu alt: 1613d |
| `yuriskinfo/cheat-sheets` | GITHUB | Zu alt: 36d |
| `prometheus-community/fortigate_exporter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheTaylorLee/AdminToolbox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yuriskinfo/Fortinet-tools` | GITHUB | Zu alt: 207d |
| `FortiPower/PowerFGT` | GITHUB | Zu alt: 215d |
| `fortinet/fortigate-terraform-deploy` | GITHUB | Zu alt: 39d |
| `fortinet-solutions-cse/fortiosapi` | GITHUB | Zu alt: 1263d |
| `mbdraks/fortinet-zabbix` | GITHUB | Zu alt: 1503d |
| `fortinet/4D-Demo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fortinet-solutions-cse/40ansible` | GITHUB | Zu alt: 2361d |
| `40net-cloud/fortinet-azure-solutions` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mbdraks/gatepy` | GITHUB | Zu alt: 2751d |
| `alextibor/wazuh-fortigate-rules-decoders` | GITHUB | Zu alt: 860d |
| `bl4ko/netbox-ssot` | GITHUB | IP-Datei 54d alt |
| `angela-d/brain-dump` | GITHUB | Zu alt: 100d |
| `glennake/DirectFire_Converter` | GITHUB | Zu alt: 1611d |
| `AsBuiltReport/AsBuiltReport.Fortinet.FortiGate` | GITHUB | Zu alt: 246d |
| `Tufin/pytos` | GITHUB | Zu alt: 627d |
| `ondrejholecek/sniftran` | GITHUB | Zu alt: 159d |
| `N4SOC/fortilogcsv` | GITHUB | Zu alt: 252d |
| `noways-io/fortigate-crypto` | GITHUB | Zu alt: 882d |
| `signorrayan/Splunk-Threat-Hunting` | GITHUB | Zu alt: 1467d |
| `fortinet/fortios-ips-snort` | GITHUB | Zu alt: 571d |
| `gdoornenbal/dehydrated-certificate-installers` | GITHUB | Zu alt: 2240d |
| `akshaymane920/pyFortimanagerAPI` | GITHUB | Zu alt: 128d |
| `fortinet-solutions-cse/fortistacks` | GITHUB | Zu alt: 674d |
| `kljunowsky/CVE-2023-36845` | GITHUB | Zu alt: 948d |
| `vxunderground/MalwareSourceCode` | GITHUB | Zu alt: 65d |
| `wifiphisher/wifiphisher` | GITHUB | Zu alt: 73d |
| `screetsec/TheFatRat` | GITHUB | Zu alt: 869d |
| `ayoubfaouzi/al-khaser` | GITHUB | Zu alt: 33d |
| `qilingframework/qiling` | GITHUB | IP-Datei 1958d alt |
| `CalebFenton/simplify` | GITHUB | Zu alt: 1556d |
| `mandiant/flare-floss` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `maestron/botnets` | GITHUB | Zu alt: 1429d |
| `Lifka/hacking-resources` | GITHUB | Zu alt: 769d |
| `m0nad/Diamorphine` | GITHUB | Zu alt: 98d |
| `Ch0pin/medusa` | GITHUB | Zu alt: 32d |
| `outflanknl/EvilClippy` | GITHUB | Zu alt: 950d |
| `mattnotmax/cyberchef-recipes` | GITHUB | Zu alt: 780d |
| `vxunderground/VX-API` | GITHUB | Zu alt: 887d |
| `JustasMasiulis/lazy_importer` | GITHUB | Zu alt: 1096d |
| `chvancooten/maldev-for-dummies` | GITHUB | Zu alt: 1158d |
| `Da2dalus/The-MALWARE-Repo` | GITHUB | Zu alt: 953d |
| `zeustrojancode/Zeus` | GITHUB | Zu alt: 2064d |
| `jvoisin/php-malware-finder` | GITHUB | Zu alt: 1018d |
| `D4Vinci/Dr0p1t-Framework` | GITHUB | Zu alt: 2830d |
| `openclarity/openclarity` | GITHUB | Zu alt: 70d |
| `mandiant/flare-learning-hub` | GITHUB | Zu alt: 125d |
| `vxunderground/VXUG-Papers` | GITHUB | Zu alt: 1700d |
| `cecio/USBvalve` | GITHUB | Zu alt: 107d |
| `CERT-Polska/drakvuf-sandbox` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mandiant/ThreatPursuit-VM` | GITHUB | Zu alt: 1159d |
| `research-virus/stuxnet` | GITHUB | Zu alt: 1437d |
| `mategol/PySilon` | GITHUB | Zu alt: 64d |
| `MinhasKamal/TrojanCockroach` | GITHUB | Zu alt: 287d |
| `NoDataFound/hackGPT` | GITHUB | Zu alt: 378d |
| `alvin-tosh/Malware-Exhibit` | GITHUB | Zu alt: 934d |
| `NYAN-x-CAT/Lime-RAT` | GITHUB | Zu alt: 2597d |
| `AHXR/ghost` | GITHUB | Zu alt: 1887d |
| `SaadAhla/FilelessPELoader` | GITHUB | Zu alt: 1070d |
| `redcode-labs/neurax` | GITHUB | Zu alt: 984d |
| `redcode-labs/Coldfire` | GITHUB | Zu alt: 598d |
| `0x6rss/matkap` | GITHUB | Zu alt: 357d |
| `mauri870/ransomware` | GITHUB | Zu alt: 2816d |
| `data-prep-kit/data-prep-kit` | GITHUB | IP-Datei 455d alt |
| `aaaddress1/RunPE-In-Memory` | GITHUB | Zu alt: 1954d |
| `certsocietegenerale/fame` | GITHUB | Zu alt: 51d |
| `curated-intel/Ukraine-Cyber-Operations` | GITHUB | Zu alt: 1134d |
| `InQuest/malware-samples` | GITHUB | Zu alt: 860d |
| `aw-junaid/Hacking-Tools` | GITHUB | Zu alt: 109d |
| `mrexodia/dumpulator` | GITHUB | Zu alt: 913d |
| `x86byte/RE-MA-Roadmap` | GITHUB | Zu alt: 305d |
| `KiExitDispatcher/GoDefender` | GITHUB | Zu alt: 236d |
| `strazzere/anti-emulator` | GITHUB | Zu alt: 2019d |
| `BushidoUK/Open-source-tools-for-CTI` | GITHUB | Zu alt: 176d |
| `hdks-bug/exploitnotes` | GITHUB | Zu alt: 144d |
| `dragokas/hijackthis` | GITHUB | Zu alt: 32d |
| `hasherezade/demos` | GITHUB | Zu alt: 1630d |
| `tarcisio-marinho/GonnaCry` | GITHUB | Zu alt: 556d |
| `SaturnsVoid/GoBot2` | GITHUB | Zu alt: 1774d |
| `Print3M/DllShimmer` | GITHUB | Zu alt: 342d |
| `cr-0w/maldev` | GITHUB | Zu alt: 80d |
| `gen0cide/gscript` | GITHUB | Zu alt: 891d |
| `ossillate-inc/packj` | GITHUB | Zu alt: 113d |
| `gwillem/magento-malware-scanner` | GITHUB | Zu alt: 971d |
| `r1cksec/cheatsheets` | GITHUB | Zu alt: 44d |
| `rek7/fireELF` | GITHUB | Zu alt: 2665d |
| `MinhasKamal/CuteVirusCollection` | GITHUB | Zu alt: 848d |
| `KiExitDispatcher/GoRedOps` | GITHUB | Zu alt: 463d |
| `guitmz/virii` | GITHUB | Zu alt: 127d |
| `hasherezade/process_doppelganging` | GITHUB | Zu alt: 1434d |
| `tijme/dittobytes` | GITHUB | Zu alt: 182d |
| `0xIslamTaha/Python-Rootkit` | GITHUB | Zu alt: 643d |
| `Cr4sh/SmmBackdoor` | GITHUB | Zu alt: 1029d |
| `ncorbuk/Python-Ransomware` | GITHUB | Zu alt: 516d |
| `Virus-Samples/Malware-Sample-Sources` | GITHUB | Zu alt: 2004d |
| `ThomasThelen/Anti-Debugging` | GITHUB | Zu alt: 1679d |
| `Cr4sh/MicroBackdoor` | GITHUB | Zu alt: 1609d |
| `scr34m/php-malware-scanner` | GITHUB | Zu alt: 40d |
| `mstfknn/malware-sample-library` | GITHUB | Zu alt: 986d |
| `EgeBalci/HERCULES` | GITHUB | Zu alt: 1842d |
| `AleksaMCode/WiFi-password-stealer` | GITHUB | Zu alt: 373d |
| `CheckPointSW/InviZzzible` | GITHUB | Zu alt: 125d |
| `rek7/mXtract` | GITHUB | Zu alt: 1728d |
| `ujjwal-kr/system-programming-roadmap` | GITHUB | Zu alt: 570d |
| `hackerxphantom/HXP-Ducky` | GITHUB | Zu alt: 269d |
| `NYAN-x-CAT/Lime-Crypter` | GITHUB | Zu alt: 833d |
| `richkmeli/Richkware` | GITHUB | Zu alt: 211d |
| `dobin/avred` | GITHUB | Zu alt: 37d |
| `SaumyajeetDas/GodGenesis` | GITHUB | Zu alt: 910d |
| `carbonblack/binee` | GITHUB | Zu alt: 1255d |
| `vysecurity/morphHTA` | GITHUB | Zu alt: 1207d |
| `D3Ext/Hooka` | GITHUB | Zu alt: 580d |
| `Cr4sh/WindowsRegistryRootkit` | GITHUB | Zu alt: 3221d |
| `CalebFenton/dex-oracle` | GITHUB | Zu alt: 2694d |
| `google/safebrowsing` | GITHUB | Zu alt: 32d |
| `danielpoliakov/lisa` | GITHUB | Zu alt: 1190d |
| `machine1337/gmailc2` | GITHUB | Zu alt: 320d |
| `chenerlich/FCL` | GITHUB | Zu alt: 1943d |
| `hackirby/skuld` | GITHUB | Zu alt: 600d |
| `hasherezade/malware_analysis` | GITHUB | Zu alt: 304d |
| `mandiant/FIDL` | GITHUB | Zu alt: 1211d |
| `V1D1AN/S1EM` | GITHUB | Zu alt: 621d |
| `JPCERTCC/aa-tools` | GITHUB | Zu alt: 354d |
| `diStyApps/Safe-and-Stable-Ckpt2Safetensors-Conversion-Tool-GUI` | GITHUB | Zu alt: 1238d |
| `Hagrid29/PELoader` | GITHUB | Zu alt: 1386d |
| `Squiblydoo/debloat` | GITHUB | Zu alt: 55d |
| `owasp-dep-scan/blint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CheckPointSW/Evasions` | GITHUB | Zu alt: 125d |
| `cristianzsh/freki` | GITHUB | Zu alt: 917d |
| `JustasMasiulis/nt_wrapper` | GITHUB | Zu alt: 2008d |
| `CERT-Polska/mquery` | GITHUB | Zu alt: 181d |
| `rf-peixoto/phishing_pot` | GITHUB | Zu alt: 44d |
| `SitinCloud/Owlyshield` | GITHUB | Zu alt: 749d |
| `0x25bit/Updated-Carbanak-Source-with-Plugins` | GITHUB | Zu alt: 2651d |
| `abdulkadir-gungor/JPGtoMalware` | GITHUB | Zu alt: 1508d |
| `ThreatLabz/ransomware_notes` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aaaddress1/Windows-APT-Warfare` | GITHUB | Zu alt: 1107d |
| `zeropointdynamics/zelos` | GITHUB | Zu alt: 1280d |
| `d4rksystem/VBoxCloak` | GITHUB | Zu alt: 395d |
| `secrary/SSMA` | GITHUB | Zu alt: 2295d |
| `crocodyli/ThreatActors-TTPs` | GITHUB | Zu alt: 186d |
| `D3Ext/maldev` | GITHUB | Zu alt: 621d |
| `saferwall/pe` | GITHUB | Zu alt: 72d |
| `NYAN-x-CAT/Mass-RAT` | GITHUB | Zu alt: 2297d |
| `htr-tech/zphisher` | GITHUB | Zu alt: 712d |
| `skerkour/black-hat-rust` | GITHUB | Zu alt: 306d |
| `htr-tech/nexphisher` | GITHUB | Zu alt: 1391d |
| `Ignitetch/AdvPhishing` | GITHUB | Zu alt: 210d |
| `jaykali/maskphish` | GITHUB | Zu alt: 321d |
| `CrimsonForge-io/king-phisher` | GITHUB | Zu alt: 48d |
| `AdrMXR/KitHack` | GITHUB | Zu alt: 530d |
| `shivaya-dav/DogeRat` | GITHUB | Zu alt: 441d |
| `chenjj/espoofer` | GITHUB | Zu alt: 1543d |
| `xiecat/goblin` | GITHUB | Zu alt: 1161d |
| `TheresAFewConors/Sooty` | GITHUB | Zu alt: 677d |
| `Raikia/FiercePhish` | GITHUB | Zu alt: 937d |
| `BiZken/PhishMailer` | GITHUB | Zu alt: 459d |
| `m4n3dw0lf/pythem` | GITHUB | Zu alt: 2720d |
| `AbirHasan2005/ShellPhish` | GITHUB | Zu alt: 1684d |
| `JoelGMSec/EvilnoVNC` | GITHUB | Zu alt: 454d |
| `Bhaviktutorials/shark` | GITHUB | Zu alt: 1387d |
| `hasanfirnas/symbiote` | GITHUB | Zu alt: 514d |
| `hackerxphantom/HACK-CAMERA` | GITHUB | Zu alt: 1069d |
| `pentestgeek/phishing-frenzy` | GITHUB | Zu alt: 1000d |
| `adamff-dev/ESP8266-Captive-Portal` | GITHUB | Zu alt: 1537d |
| `darkarp/chromepass` | GITHUB | Zu alt: 950d |
| `simplerhacking/Evilginx3-Phishlets` | GITHUB | Zu alt: 433d |
| `MyEtherWallet/ethereum-lists` | GITHUB | IP-Datei 1795d alt |
| `0n1cOn3/FluxER` | GITHUB | Zu alt: 64d |
| `t4d/StalkPhish` | GITHUB | Zu alt: 875d |
| `Err0r-ICA/Phishbait` | GITHUB | Zu alt: 433d |
| `Euronymou5/Doxxer-Toolkit` | GITHUB | Zu alt: 63d |
| `AlteredSecurity/365-Stealer` | GITHUB | Zu alt: 150d |
| `EricksonAtHome/blackeye` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `RedSiege/EXCELntDonut` | GITHUB | Zu alt: 2140d |
| `CanIPhish/Phishious` | GITHUB | Zu alt: 1206d |
| `spyboy-productions/Facad1ng` | GITHUB | Zu alt: 209d |
| `Akshay-Arjun/69phisher` | GITHUB | Zu alt: 534d |
| `Kl0ibi/esp32_hackingtool` | GITHUB | Zu alt: 767d |
| `Optane002/ZPhisher` | GITHUB | Zu alt: 1006d |
| `wifiphisher/extra-phishing-pages` | GITHUB | Zu alt: 1924d |
| `curtbraz/PhishAPI` | GITHUB | Zu alt: 508d |
| `Cyber-Anonymous/Dark-Phish` | GITHUB | Zu alt: 679d |
| `cyberboyplas/WhPhisher` | GITHUB | Zu alt: 1403d |
| `qeeqbox/analyzer` | GITHUB | Zu alt: 840d |
| `taielab/Taie-AutoPhishing` | GITHUB | Zu alt: 1953d |
| `duo-labs/isthislegit` | GITHUB | Zu alt: 1098d |
| `DRACULA-HACK/C-hacks` | GITHUB | Zu alt: 41d |
| `4w4k3/Umbrella` | GITHUB | Zu alt: 3367d |
| `sneakerhax/PyPhisher` | GITHUB | Zu alt: 842d |
| `ineesdv/Tangled` | GITHUB | Zu alt: 228d |
| `evildevill/EmptyPhish` | GITHUB | Zu alt: 1116d |
| `balte/TelnetHoney` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MattCarothers/mhn-core-docker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aelth/ddospot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mushorg/glastopf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `omererdem/honeything` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `desaster/kippo` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `WebDecoy/wordpress-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `androguard/androguard` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fw42/honeymap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `packetflare/amthoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `torque59/nosqlpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `upa/ofpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ahoernecke/ensnare` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jordan-wright/elastichoney` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sreinhardt/Docker-Honeynet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sefcom/honeyplc` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ayrus/afterglow-cloud` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `amv42/sshd-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `run41/honey_ports` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tillmannw/honeytrap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `buffer/libemu` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alexbredo/honeypot-camera` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SneakersInc/HoneyMalt` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sjhilt/GasPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CERT-Polska/HSN-Capture-HPC-NG` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cymmetria/ciscoasa_honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `yuchincheng/HpfeedsHoneyGraph` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eymengunay/EoHoneypotBundle` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hbhzwj/imalse` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `MalwareTech/CitrixHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CERT-Polska/hsn2-bundle` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `fnzv/YAFH` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gregcmartin/Kippo_JunOS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cymmetria/StrutsHoneypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `honeynet/apkinspector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `magisterquis/vnclowpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `glaslos/honeyprint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hgascon/acapulco` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Cymmetria/MTPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ls1911/GenAIPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `DataSoft/Nova` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `LogoiLab/honeyup` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mycert/ESPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `kungfuguapo/HoneyPress` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GetPageSpeed/nginx-honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mzweilin/ipv6-attack-detector` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `shiva-spampot/shiva` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hexgolems/schem` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dutchcoders/troje` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `schmalle/MysqlPot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `traetox/sshForShits` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alexbredo/honeypot-ftp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ajackal/arctic-swallow` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `threatstream/shockpot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `andrew-morris/kippo_detect` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jadb/honeypot` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sahilm/hived` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `threatstream/mhn` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `chvancooten/BugBountyScanner` | GITHUB | IP-Datei 962d alt |
| `bfuzzy/auditd-attack` | GITHUB | IP-Datei 2806d alt |
| `quarkslab/QBDI` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `armanshan12/rkms` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mainframed/Enumeration` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Super-Guesser/ctf` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `6IX7ine/certstreamcatcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JohnHammond/poor-mans-pentest` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gerhart01/Hyper-V-Internals` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ernw/hardening` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `xoreaxeaxeax/movfuscator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nccgroup/azucar` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `optiv/Go365` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `bagder/http2-explained` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `naingyeminn/CentOS7_Lockdown` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `highmeh/lure` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `gmatuz/cve-scanner-exploiting-pocs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SEC642/SEC642_papers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dumb-password-rules/dumb-password-rules` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rurban/smhasher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `romanzaikin/BurpExtension-WhatsApp-Decryption-CheckPoint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ManhNho/AWAE-OSWE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eugenekolo/sec-tools` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Srinivas11789/PcapXray` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `StrangerealIntel/DailyIOC` | GITHUB | IP-Datei 2346d alt |
| `te-k/apkcli` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `volatilityfoundation/profiles` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Wenzel/oswatcher` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `outflanknl/Invoke-ADLabDeployer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `dandrews/nefarious-linkedin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `malwareinfosec/EKFiddle` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Antelox/FOPO-PHP-Deobfuscator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `noraj/rawsec-cybersecurity-inventory` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mschwager/dhcpwn` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `FuzzySecurity/PowerShell-Suite` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ShiftLeftSecurity/sast-scan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `google/trillian` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `boazbk/crypto` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `KingOfBugbounty/KingOfBugBountyTips` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Azure/Azure-Sentinel` | GITHUB | IP-Datei 1238d alt |
| `allfro/dotNetBeautifier` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `3xpl01tc0d3r/ProcessInjection` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `BloodHoundAD/SharpHound3` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nickboucher/trojan-source` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `swisskyrepo/GraphQLmap` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `manifoldco/torus-cli` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `can1357/NoVmp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zardus/preeny` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `minimaxir/big-list-of-naughty-strings` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `azonenberg/starshipraider` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sharkdp/hexyl` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rj-chap/BaselineTraining` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alainesp/CBG` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hlldz/SpookFlare` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Arno0x/DivertTCPconn` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `m1nl/pompa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `openwall/lkrg` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `GossiTheDog/ThreatHunting` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cutaway-security/chaps` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `microsoft/restler-fuzzer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `2factorauth/twofactorauth` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `psecio/canary` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ninedter/pcap-hunter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ReaJason/MemShellParty` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thib3113/node-crowdsec` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sjinks/wazuh-ar-ipset` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `panther-labs/panther-analysis` | GITHUB | IP-Datei 853d alt |
| `dividebysandwich/sdroxide` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OneUptime/oneuptime` | GITHUB | IP-Datei 123d alt |
| `OWLZOPS/owlzops-mapper` | GITHUB | Größe: 0 IPs |
| `rekryt/iplist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `nwiecz/C2IntelFeedsFGT` | GITHUB | Overlap zu gering: 0.0% |
| `elliottophellia/proxylist` | GITHUB | Overlap zu gering: 14.3% |
| `swjturay/cfnb-ip` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `CERT-Polska/Artemis` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `l3montree-dev/devguard` | GITHUB | Größe: 0 IPs |
| `ContextualWisdomLab/wardnet` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `HolmesGPT/holmesgpt` | GITHUB | IP-Datei 249d alt |
| `Wikid82/Charon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `SecNN/AiScan-N` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `presidio-v/presidio-hardened-vuln-scanner` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `grave0x/gitprops` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `lord-alfred/ipranges` | GITHUB | FP-Rate: 95.5% |
| `kubeshark/kubeshark` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Mapiiik/Watcher-NMS` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NSM-Barii/Yoda` | GITHUB | IP-Datei 80d alt |
| `wazuh/wazuh-documentation` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jgamblin/cvelint-action` | GITHUB | Größe: 0 IPs |
| `EXP-Tools/threat-broadcast` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jgamblin/OpenClawCVEs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jgamblin/isthisipbad` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jgamblin/CVElk` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jgamblin/KalmanCVE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jgamblin/NVDAnalysisStatus` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jgamblin/NCAA-Prediction` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `koala73/worldmonitor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `barvhaim/HoneyMCP` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wyre-technology/avanan-mcp` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `mjcaley/aiospamc` | GITHUB | IP-Datei 1373d alt |
| `Ozark-Connect/NetworkOptimizer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wazuh/wazuh-dashboard-plugins` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `modem7/crowdsec-troubleshooter` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `grafana/pySigma-backend-loki` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `PowerDNS/weakforced` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `zwerkenm/Muck-MASS-SMS-Sender-Whatsapp-Boomber` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `100Rkn/Discord-Token-Password-Stealer` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cplieger/docker-caddy` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `NIKX-Tech/karshipta` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sari3l/Poc-Monitor` | GITHUB | IP-Datei 1253d alt |
| `gfpcom/free-proxy-list` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `owasp-dep-scan/dep-scan` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `JSONbored/simplelogin-aio` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `aboutcode-org/vulnerablecode` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `macadmins/sofa` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jgamblin/tufty-recon` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `archetech/archon` | GITHUB | IP-Datei 121d alt |
| `frgfm/holocron` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `joeavanzato/recent_c2_infrastructure` | GITHUB | Overlap zu gering: 0.2% |
| `alexar76/aimarket-plugins` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wazuh/wazuh-ansible` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wazuh/wazuh-docker` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alonsoir/argus` | GITHUB | IP-Datei 68d alt |
| `maxlerebourg/crowdsec-bouncer-traefik-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Davie3/mikrotik-cloudflare-iplist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `TheDuffman85/crowdsec-web-ui` | GITHUB | Größe: 0 IPs |
| `parkr/antispam` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `ongridio/ongrid` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `tenzir/tenzir` | GITHUB | IP-Datei 227d alt |
| `giantswarm/coredns-warnlist-plugin` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `opencve/opencve` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `jblukach/feedwalla` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `eye-wave/spotify-ai-blocklist` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `larlarua/AutoCVE` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Elwinmage/ha-reefbeat-component` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `AlderlineSystems/vmga` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rehiy/isrvd` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Zilleali/mikrotik-laravel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Probesys/agentj` | GITHUB | IP-Datei 328d alt |
| `WarMatrixAI/WarMatrix` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sfr-development/WonderSuite-Ai-Bug-Bounty` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `righel/ms-exchange-version-nse` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `Phishcan/phishcan-data` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `flowintel/flowintel` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `crowdsecurity/crowdsec-docs` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `presidio-v/presidio-hardened-ids` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `konkos1/OpenSecDash` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `sourcentis/mercator` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `IRISX-AI/IRIS-Mini` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `hugefiver/fakessh` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `wp-labs/wp-editor` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `rubennati/secure-docker-blueprint` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `thrive-spectrexq/nxc-rs` | GITHUB | Größe: 0 IPs |
| `SHAdd0WTAka/AKIR-EDR` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `OpenOSINT/OpenOSINT` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `403errors/repomind` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cowrie/cowrie` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `castle/disposable-phone-numbers` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `alivirgo/SentryLoom` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `cwit-ae/Verlux` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `roxy-wi/IncidentRelay` | GITHUB | Keine IP-Datei (Name/Inhalt) |
| `stratosphereips/zeek_anomaly_detector` | GITHUB | Keine IP-Datei (Name/Inhalt) |

---
## 📋 Alle aktiven Auto-Feeds

| Feed | Plattform | IPs | Overlap | Stars | Hinzugefügt |
|---|---|---|---|---|---|
| `cbuijs_hagezi` | GITHUB | 44,947 | 40.4% | 105 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist` | GITHUB | 48,653 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist` | GITHUB | 21,284 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ipsum` | GITHUB | 15,898 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | GITHUB | 7,615 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | GITHUB | 4,381 | 1.8% | 49 | 2026-07-04 |
| `alsyundawy_mikrotik_blacklist_emerging_threats` | GITHUB | 585 | 1.8% | 49 | 2026-07-04 |
| `antoinevastel_avastel_bot_ips_lists` | GITHUB | 500,000 | 0.2% | 120 | 2026-07-04 |
| `skillter_proxygather` | GITHUB | 18,364 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_all` | GITHUB | 464 | 1.1% | 122 | 2026-07-04 |
| `skillter_proxygather_working_proxies_http` | GITHUB | 253 | 1.1% | 122 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub` | GITHUB | 4,847 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | GITHUB | 3,660 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | GITHUB | 2,552 | 1.3% | 44 | 2026-07-04 |
| `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | GITHUB | 1,991 | 1.3% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list` | GITHUB | 3,325 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_https` | GITHUB | 3,470 | 1.9% | 44 | 2026-07-04 |
| `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | GITHUB | 2,793 | 1.9% | 44 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list` | GITHUB | 1,085 | 6.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl` | GITHUB | 598 | 8.6% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_elite` | GITHUB | 632 | 8.5% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | GITHUB | 494 | 9.2% | 60 | 2026-07-04 |
| `vpslabcloud_vpslab_free_proxy_list_socks5_all` | GITHUB | 288 | 12.8% | 60 | 2026-07-04 |
| `ercindedeoglu_proxies` | GITHUB | 37,266 | 0.6% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks4` | GITHUB | 12,277 | 1.9% | 375 | 2026-07-05 |
| `ercindedeoglu_proxies_socks5` | GITHUB | 10,989 | 2.6% | 375 | 2026-07-05 |
| `tuanminpay_live_proxy` | GITHUB | 9,132 | 1.4% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_http` | GITHUB | 6,535 | 1.9% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks4` | GITHUB | 4,697 | 2.0% | 51 | 2026-07-05 |
| `tuanminpay_live_proxy_socks5` | GITHUB | 2,844 | 2.9% | 51 | 2026-07-05 |
| `gitrecon1455_fresh_proxy_list` | GITHUB | 197,672 | 0.2% | 106 | 2026-07-05 |
| `noctiro_getproxy` | GITHUB | 4,511 | 1.3% | 116 | 2026-07-05 |
| `noctiro_getproxy_socks5` | GITHUB | 2,392 | 2.6% | 116 | 2026-07-05 |
| `breakingtechfr_proxy_free` | GITHUB | 29,347 | 0.6% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_all` | GITHUB | 32,012 | 0.5% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks4` | GITHUB | 7,200 | 1.9% | 55 | 2026-07-14 |
| `breakingtechfr_proxy_free_socks5` | GITHUB | 5,942 | 2.2% | 55 | 2026-07-14 |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | GITHUB | 10,635 | 93.4% | 4764 | 2026-07-22 |
| `leon406_subcrawler` | GITHUB | 116,792 | 0.1% | 1560 | 2026-08-01 |
| `mohammedcha_proxripper` | GITHUB | 53,328 | 0.3% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks4` | GITHUB | 112,849 | 0.1% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_http` | GITHUB | 117,116 | 0.2% | 36 | 2026-07-05 |
| `mohammedcha_proxripper_socks5` | GITHUB | 114,728 | 0.2% | 36 | 2026-07-05 |
| `dinoz0rg_proxy_list` | GITHUB | 85,241 | 0.2% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_http` | GITHUB | 2,236 | 2.6% | 22 | 2026-07-05 |
| `dinoz0rg_proxy_list_socks5` | GITHUB | 85,432 | 0.2% | 22 | 2026-07-05 |
| `cbuijs_accomplist` | GITHUB | 101,918 | 0.6% | 20 | 2026-03-27 |
| `cbuijs_accomplist_adblock_ip_v2` | GITHUB | 64,632 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip_v3` | GITHUB | 113 | 0.6% | 20 | 2026-05-24 |
| `cbuijs_accomplist_adblock_ip` | GITHUB | 103,031 | 0.6% | 20 | 2026-05-28 |
| `bilsectr_sgb_api_bridge` | GITHUB | 15,077 | 5.7% | 9 | 2026-08-03 |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | GITHUB | 106,193 | 36.7% | 8 | 2026-05-28 |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | GITHUB | 586 | 36.7% | 8 | 2026-07-03 |
| `darzanebor_mikroblack` | GITHUB | 41,628 | 26.6% | 13 | 2026-07-05 |
| `ankaboot_source_email_open_data` | GITHUB | 490,942 | 2.0% | 13 | 2026-07-06 |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | GITHUB | 218,728 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_full` | GITHUB | 170,572 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_outbound` | GITHUB | 171,900 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_abusers_30d` | GITHUB | 139,664 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level4` | GITHUB | 105,511 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_extralarge` | GITHUB | 84,797 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_all` | GITHUB | 109,595 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level1` | GITHUB | 80,819 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_http_365d` | GITHUB | 185,563 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_master` | GITHUB | 47,907 | 2.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_telnet_365d` | GITHUB | 73,540 | 29.7% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_large` | GITHUB | 28,932 | 62.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blocklist_core` | GITHUB | 19,297 | 67.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all_365d` | GITHUB | 33,773 | 77.0% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2` | GITHUB | 22,472 | 94.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level2_v2` | GITHUB | 14,096 | 62.6% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_all` | GITHUB | 12,952 | 60.8% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_ftp_365d` | GITHUB | 27,597 | 35.9% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_forums` | GITHUB | 12,629 | 5.5% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_level3` | GITHUB | 13,689 | 65.2% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_blacklist_today` | GITHUB | 7,123 | 78.1% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_rdp_365d` | GITHUB | 13,097 | 55.4% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_highrisk` | GITHUB | 5,631 | 2.3% | 10 | 2026-07-04 |
| `configserverapps_service_blocklists_vnc_365d` | GITHUB | 7,884 | 62.1% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_mail` | GITHUB | 5,307 | 49.8% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_smtp_365d` | GITHUB | 7,106 | 62.2% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_sip_365d` | GITHUB | 5,575 | 57.4% | 10 | 2026-07-05 |
| `configserverapps_service_blocklists_attacks_bots` | GITHUB | 2,250 | 29.5% | 10 | 2026-07-06 |
| `configserverapps_service_blocklists_attacks_ssh` | GITHUB | 4,193 | 86.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_abusers_1d` | GITHUB | 3,509 | 4.1% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_botscout_30d` | GITHUB | 3,609 | 4.6% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_blocklist_v2` | GITHUB | 749 | 77.2% | 10 | 2026-07-08 |
| `configserverapps_service_blocklists_attacks_imap` | GITHUB | 3,874 | 40.8% | 10 | 2026-07-09 |
| `configserverapps_service_blocklists_http_1d` | GITHUB | 1,943 | 5.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_greylist` | GITHUB | 8,237 | 78.1% | 10 | 2026-07-31 |
| `configserverapps_service_blocklists_telnet_1d` | GITHUB | 2,522 | 29.9% | 10 | 2026-08-02 |
| `ian_lusule_proxies` | GITHUB | 3,783 | 2.4% | 9 | 2026-07-05 |
| `ian_lusule_proxies_socks5` | GITHUB | 1,704 | 3.4% | 9 | 2026-07-05 |
| `tscci_threatips` | GITHUB | 865 | 17.2% | 9 | 2026-07-08 |
| `sereinfy_adrules` | GITHUB | 1,342 | 12.2% | 7 | 2026-08-01 |
| `celestialbrain_worldpool` | GITHUB | 82,698 | 0.1% | 8 | 2026-07-05 |
| `gazpitchy92_ip_blocklist` | GITHUB | 314,786 | 22.0% | 6 | 2026-07-08 |
| `officialputuid_proxyforeveryone` | GITHUB | 6,277 | 2.3% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_https` | GITHUB | 5,479 | 1.7% | 7 | 2026-07-04 |
| `officialputuid_proxyforeveryone_proxies` | GITHUB | 5,451 | 2.6% | 7 | 2026-07-04 |
| `romainmarcoux_misc_ip_lists` | GITHUB | 3,584 | 19.8% | 5 | 2026-08-03 |
| `realizelol_torblocklist` | GITHUB | 1,560 | 40.4% | 3 | 2026-07-08 |
| `turntuptechnologies_iocs` | GITHUB | 38 | 97.4% | 4 | 2026-03-29 |
| `cbuijs_badip` | GITHUB | 63,430 | 60.7% | 4 | 2026-03-29 |
| `maximewewer_heimdallblocklists` | GITHUB | 67,008 | 69.0% | 4 | 2026-03-29 |
| `agent6_6_6_wordpress_login_blocklist` | GITHUB | 22,057 | 1.4% | 4 | 2026-03-29 |
| `turntuptechnologies_iocs_scanner` | GITHUB | 87 | 97.4% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | GITHUB | 197,241 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | GITHUB | 6,690 | 69.0% | 4 | 2026-05-24 |
| `maximewewer_heimdallblocklists_spamhaus_drop` | GITHUB | 1,661 | 69.0% | 4 | 2026-06-28 |
| `kalidada18_threatbase` | GITHUB | 180,820 | 16.5% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_bruteforce` | GITHUB | 23,295 | 45.2% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_tor` | GITHUB | 7,531 | 9.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_botnet` | GITHUB | 2,228 | 34.1% | 2 | 2026-08-01 |
| `kalidada18_threatbase_threatbase_ip_compromised` | GITHUB | 15,565 | 65.9% | 2 | 2026-08-01 |
| `securitylist1568_fortigate` | GITHUB | 117 | 28.1% | 2 | 2026-08-02 |
| `fadouse_clash_threat_intel` | GITHUB | 8,190 | 12.7% | 2 | 2026-03-17 |
| `fadouse_clash_threat_intel_c2` | GITHUB | 8,557 | 12.7% | 2 | 2026-05-24 |
| `kamalmjt_emerging_attackers_badips` | GITHUB | 169,396 | 18.9% | 1 | 2026-05-28 |
| `ipanalytics_ai_crawler_blocklist` | GITHUB | 2,056 | 21.9% | 1 | 2026-07-04 |
| `makarson_daily_phishing_feed` | GITHUB | 15,972 | 4.2% | 1 | 2026-07-14 |
| `toxyl_ossh_swarm_wordlists` | GITHUB | 16,435 | 68.4% | 1 | 2026-07-14 |
| `infosecuniversity_block_list` | GITHUB | 1,290 | 31.1% | 1 | 2026-07-14 |
| `idleadmin_threatfeed` | GITHUB | 48,044 | 41.9% | 0 | 2026-04-09 |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | GITHUB | 51,890 | 13.1% | 0 | 2026-05-24 |
| `kraloveckey_ipsets_blocklist_dm_tor` | GITHUB | 7,492 | 13.1% | 0 | 2026-05-24 |
| `openprx_prx_sd_signatures` | GITHUB | 106,284 | 64.5% | 0 | 2026-05-30 |
| `openprx_prx_sd_signatures_url_blocklist` | GITHUB | 404 | 64.5% | 0 | 2026-05-30 |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | GITHUB | 24,167 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_myip_full` | GITHUB | 192,268 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | GITHUB | 144,527 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum` | GITHUB | 106,277 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | GITHUB | 127,592 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | GITHUB | 3,104 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | GITHUB | 1,238 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_2` | GITHUB | 31,158 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | GITHUB | 495 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | GITHUB | 18,517 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_3` | GITHUB | 15,967 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | GITHUB | 8,774 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_4` | GITHUB | 6,210 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | GITHUB | 3,874 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | GITHUB | 6,674 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | GITHUB | 4,215 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | GITHUB | 2,000 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | GITHUB | 1,918 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | GITHUB | 2,122 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | GITHUB | 2,528 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_ipsum_5` | GITHUB | 1,622 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | GITHUB | 2,150 | 13.1% | 0 | 2026-06-28 |
| `kraloveckey_ipsets_blocklist_bds_atif` | GITHUB | 825 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | GITHUB | 2,880 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_gpf_comics` | GITHUB | 1,835 | 13.1% | 0 | 2026-07-02 |
| `kraloveckey_ipsets_blocklist_tor_exits` | GITHUB | 1,396 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_bad_30d` | GITHUB | 598 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_spammers_30d` | GITHUB | 569 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_php_commenters_30d` | GITHUB | 575 | 13.1% | 0 | 2026-07-03 |
| `kraloveckey_ipsets_blocklist_sblam` | GITHUB | 992 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_php_dictionary_30d` | GITHUB | 487 | 13.1% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_myip` | GITHUB | 1,000 | 65.5% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_sslproxies_30d` | GITHUB | 519 | 6.0% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | GITHUB | 1,460 | 40.9% | 0 | 2026-07-04 |
| `kraloveckey_ipsets_blocklist_iblocklist_onion_router` | GITHUB | 713 | 41.2% | 0 | 2026-07-05 |
| `kraloveckey_ipsets_blocklist_cps_log4j` | GITHUB | 25,279 | 6.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_maltrail_scanners` | GITHUB | 16,854 | 14.9% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_iblocklist_cruzit_web_attacks` | GITHUB | 13,871 | 0.5% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_nodes` | GITHUB | 5,631 | 5.0% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_secops_tor_exits` | GITHUB | 1,127 | 24.2% | 0 | 2026-07-22 |
| `kraloveckey_ipsets_blocklist_cleantalk_7d` | GITHUB | 1,964 | 4.9% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_tor_exits_30d` | GITHUB | 1,506 | 46.7% | 0 | 2026-07-31 |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_7d` | GITHUB | 979 | 8.1% | 0 | 2026-07-31 |
| `bitwire_it_ip_list_fetch` | GITHUB | 33,155 | 24.7% | 0 | 2026-08-01 |
| `serp07_dude_blacklist_ip` | GITHUB | 4,652 | 31.6% | 0 | 2026-08-01 |

---
*Generiert: 2026-08-03 15:47 UTC*