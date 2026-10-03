# Feed Health Monitor – Report
**Aktualisiert:** 2026-10-03 07:56 CEST (Europe/Berlin)

**Feeds gesamt:** 103 | ✅ 99 OK | ⚠️ 1 leer | ❌ 3 Fehler

---
## ✅ DataPlane-Feeds (Phase 1)

Alle 17 DataPlane-Feeds erreichbar und liefern IPs.

| Feed | Status | HTTP | IPs (Sample) | Reaktionszeit |
|---|---|---|---|---|
| `dataplane_dnsrd` | ✅ | 200 | ~9546 | 690ms |
| `dataplane_dnsrdany` | ✅ | 200 | ~320 | 300ms |
| `dataplane_dnstcp` | ✅ | 200 | ~1124 | 540ms |
| `dataplane_dnsversion` | ✅ | 200 | ~7580 | 660ms |
| `dataplane_ntpmode3` | ✅ | 200 | ~3509 | 810ms |
| `dataplane_ntpmode6` | ✅ | 200 | ~654 | 530ms |
| `dataplane_ntpmode7` | ✅ | 200 | ~717 | 300ms |
| `dataplane_proto41` | ✅ | 200 | ~52564 | 21640ms |
| `dataplane_sipinvitation` | ✅ | 200 | ~139 | 170ms |
| `dataplane_sipquery` | ✅ | 200 | ~5284 | 910ms |
| `dataplane_sipregistration` | ✅ | 200 | ~393 | 350ms |
| `dataplane_smtpdata` | ✅ | 200 | ~361 | 400ms |
| `dataplane_smtpgreet` | ✅ | 200 | ~9376 | 1280ms |
| `dataplane_sshclient` | ✅ | 200 | ~19071 | 2810ms |
| `dataplane_sshpwauth` | ✅ | 200 | ~8747 | 970ms |
| `dataplane_telnetlogin` | ✅ | 200 | ~42835 | 4950ms |
| `dataplane_vncrfb` | ✅ | 200 | ~1715 | 350ms |

## ❌ Fehlerhafte Feeds

| Feed | HTTP | Fehler | Reaktionszeit |
|---|---|---|---|
| `abuseipdb_tmiland` | 0 | <urlopen error timed out> | 60999ms |
| `edanwong` | 404 | HTTP 404 | 496ms |
| `fortigate_azure` | 404 | HTTP 404 | 315ms |

## ⚠️ Feeds ohne IPs (möglicherweise leer oder falsches Format)

| Feed | HTTP | Reaktionszeit |
|---|---|---|
| `blocklist_de_ssh` | 200 | 300ms |

## ✅ Alle Feeds – Übersicht

| Feed | Status | HTTP | IPs (Sample) | Reaktionszeit |
|---|---|---|---|---|
| `4ip_high_security` | ✅ | 200 | ~56385 | 920ms |
| `abuseipdb_axllent` | ✅ | 200 | ~103444 | 2029ms |
| `abuseipdb_s100_30d` | ✅ | 200 | ~135006 | 14090ms |
| `abuseipdb_s100_7d` | ✅ | 200 | ~73340 | 4400ms |
| `abuseipdb_score100` | ✅ | 200 | ~8884 | 470ms |
| `amitambekar_threats_aa` | ✅ | 200 | ~40164 | 1940ms |
| `ashleykleynhans_abuseipdb` | ✅ | 200 | ~31614 | 2390ms |
| `binary_defense` | ✅ | 200 | ~1073 | 310ms |
| `bitwire_ipblocklist` | ✅ | 200 | ~1815858 | 27930ms |
| `black_mirror` | ✅ | 200 | ~1577401 | 18620ms |
| `blocklist_de_all` | ✅ | 200 | ~7967 | 1090ms |
| `blocklist_de_export` | ✅ | 200 | ~7967 | 1170ms |
| `blocklist_de_ssh` | ⚠️ | 200 | ~0 | 300ms |
| `blocklist_de_strongips` | ✅ | 200 | ~385 | 630ms |
| `blocklist_net_ua` | ✅ | 200 | ~208483 | 2970ms |
| `bsdly_bruteforcers` | ✅ | 200 | ~122923 | 4610ms |
| `bsdly_pop3` | ✅ | 200 | ~3639 | 1360ms |
| `bsdly_traplist` | ✅ | 200 | ~646 | 960ms |
| `c2_iplist` | ✅ | 200 | ~135 | 410ms |
| `cinsarmy` | ✅ | 200 | ~15000 | 380ms |
| `cinsscore` | ✅ | 200 | ~15000 | 260ms |
| `crowdsec_ssh` | ✅ | 200 | ~14027 | 320ms |
| `cypher139_ipblacklist` | ✅ | 200 | ~28589 | 2820ms |
| `danger_bruteforce` | ✅ | 200 | ~627 | 1740ms |
| `data_shield` | ✅ | 200 | ~100243 | 720ms |
| `data_shield_full` | ✅ | 200 | ~90975 | 930ms |
| `dataplane_dnsrd` | ✅ | 200 | ~9546 | 690ms |
| `dataplane_dnsrdany` | ✅ | 200 | ~320 | 300ms |
| `dataplane_dnstcp` | ✅ | 200 | ~1124 | 540ms |
| `dataplane_dnsversion` | ✅ | 200 | ~7580 | 660ms |
| `dataplane_ntpmode3` | ✅ | 200 | ~3509 | 810ms |
| `dataplane_ntpmode6` | ✅ | 200 | ~654 | 530ms |
| `dataplane_ntpmode7` | ✅ | 200 | ~717 | 300ms |
| `dataplane_proto41` | ✅ | 200 | ~52564 | 21640ms |
| `dataplane_sipinvitation` | ✅ | 200 | ~139 | 170ms |
| `dataplane_sipquery` | ✅ | 200 | ~5284 | 910ms |
| `dataplane_sipregistration` | ✅ | 200 | ~393 | 350ms |
| `dataplane_smtpdata` | ✅ | 200 | ~361 | 400ms |
| `dataplane_smtpgreet` | ✅ | 200 | ~9376 | 1280ms |
| `dataplane_sshclient` | ✅ | 200 | ~19071 | 2810ms |
| `dataplane_sshpwauth` | ✅ | 200 | ~8747 | 970ms |
| `dataplane_telnetlogin` | ✅ | 200 | ~42835 | 4950ms |
| `dataplane_vncrfb` | ✅ | 200 | ~1715 | 350ms |
| `ddrimus_http_threats` | ✅ | 200 | ~402 | 350ms |
| `dshield` | ✅ | 200 | ~40 | 430ms |
| `et_compromised` | ✅ | 200 | ~621 | 480ms |
| `f3csystems` | ✅ | 200 | ~2577 | 610ms |
| `fadouse_botnet` | ✅ | 200 | ~11204 | 1030ms |
| `fadouse_c2` | ✅ | 200 | ~12142 | 650ms |
| `fadouse_loader` | ✅ | 200 | ~903 | 1520ms |
| `fadouse_malware` | ✅ | 200 | ~65558 | 2900ms |
| `fadouse_ransomware` | ✅ | 200 | ~319 | 490ms |
| `fadouse_rat` | ✅ | 200 | ~3889 | 540ms |
| `fadouse_stealer` | ✅ | 200 | ~1570 | 630ms |
| `fadouse_worm` | ✅ | 200 | ~150 | 570ms |
| `ffraud_confirmed` | ✅ | 200 | ~959294 | 19140ms |
| `firehol_abusers_1d` | ✅ | 200 | ~3678 | 1380ms |
| `firehol_anonymous` | ✅ | 200 | ~1747669 | 20620ms |
| `firehol_level2` | ✅ | 200 | ~5210 | 1450ms |
| `firehol_level3` | ✅ | 200 | ~12667 | 1820ms |
| `firehol_level4` | ✅ | 200 | ~159611 | 3480ms |
| `firehol_webserver` | ✅ | 200 | ~1254 | 790ms |
| `freakuency_threatfeed` | ✅ | 200 | ~19172 | 1040ms |
| `greedybear_recent` | ✅ | 200 | ~5000 | 890ms |
| `greensnow` | ✅ | 200 | ~5604 | 5980ms |
| `hagezi_tif_cdn` | ✅ | 200 | ~34446 | 80ms |
| `interserver` | ✅ | 200 | ~3140 | 520ms |
| `ipsum_level5` | ✅ | 200 | ~3528 | 410ms |
| `ipsum_level7` | ✅ | 200 | ~186 | 250ms |
| `ipsum_master` | ✅ | 200 | ~108749 | 1340ms |
| `magicteamc_bad_ips` | ✅ | 200 | ~1272245 | 19450ms |
| `myip_ms` | ✅ | 200 | ~1625 | 1780ms |
| `netmountains_blocklist` | ✅ | 200 | ~54169 | 1280ms |
| `pgl_yoyo_adservers` | ✅ | 200 | ~8721 | 1350ms |
| `romain_marcoux` | ✅ | 200 | ~40000 | 910ms |
| `romainmarcoux_aa` | ✅ | 200 | ~300000 | 4210ms |
| `romainmarcoux_ab` | ✅ | 200 | ~300000 | 4080ms |
| `romainmarcoux_outgoing_aa` | ✅ | 200 | ~131072 | 1250ms |
| `romainmarcoux_outgoing_ab` | ✅ | 200 | ~41647 | 1550ms |
| `rtbh_com_tr` | ✅ | 200 | ~79370 | 3430ms |
| `rutgers_drop` | ✅ | 200 | ~581 | 410ms |
| `sefinek_malicious` | ✅ | 200 | ~221288 | 2380ms |
| `serp07_dude_blacklist` | ✅ | 200 | ~6008 | 1760ms |
| `shadowwhisperer_probes` | ✅ | 200 | ~30245 | 500ms |
| `shadowwhisperer_scanners` | ✅ | 200 | ~62148 | 840ms |
| `shadowwhisperer_threats` | ✅ | 200 | ~17179 | 410ms |
| `shadowwhisperer_threats_uncl` | ✅ | 200 | ~38875 | 540ms |
| `sky_poppy_recent` | ✅ | 200 | ~117802 | 680ms |
| `spydi_high_confidence` | ✅ | 200 | ~9605 | 1480ms |
| `threat_live` | ✅ | 200 | ~42413 | 6660ms |
| `threathive_blocklist` | ✅ | 200 | ~182303 | 1830ms |
| `threatslist_paloalto_edl` | ✅ | 200 | ~33051 | 490ms |
| `threatview_high_conf` | ✅ | 200 | ~10373 | 1340ms |
| `ufukart_blacklist` | ✅ | 200 | ~238613 | 2200ms |
| `ultimate_hosts_ips0` | ✅ | 200 | ~144537 | 4140ms |
| `urlhaus_agh` | ✅ | 200 | ~14554 | 1030ms |
| `urlhaus_ips` | ✅ | 200 | ~1334 | 4880ms |
| `viriback_c2` | ✅ | 200 | ~8077 | 1640ms |
| `yuexuan_hfish` | ✅ | 200 | ~302 | 260ms |
| `zerof_ipextractor` | ✅ | 200 | ~13001 | 1960ms |
| `abuseipdb_tmiland` | ❌ | 0 | ~0 | 60999ms |
| `edanwong` | ❌ | 404 | ~0 | 496ms |
| `fortigate_azure` | ❌ | 404 | ~0 | 315ms |

---
*Generiert: 2026-10-03 07:56 CEST (Europe/Berlin) | 103 Feeds geprüft*