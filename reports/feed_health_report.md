# Feed Health Monitor – Report
**Aktualisiert:** 2026-10-05 08:27 CEST (Europe/Berlin)

**Feeds gesamt:** 103 | ✅ 99 OK | ⚠️ 1 leer | ❌ 3 Fehler

---
## ✅ DataPlane-Feeds (Phase 1)

Alle 17 DataPlane-Feeds erreichbar und liefern IPs.

| Feed | Status | HTTP | IPs (Sample) | Reaktionszeit |
|---|---|---|---|---|
| `dataplane_dnsrd` | ✅ | 200 | ~10713 | 1910ms |
| `dataplane_dnsrdany` | ✅ | 200 | ~325 | 360ms |
| `dataplane_dnstcp` | ✅ | 200 | ~1054 | 440ms |
| `dataplane_dnsversion` | ✅ | 200 | ~7741 | 980ms |
| `dataplane_ntpmode3` | ✅ | 200 | ~4212 | 1350ms |
| `dataplane_ntpmode6` | ✅ | 200 | ~636 | 420ms |
| `dataplane_ntpmode7` | ✅ | 200 | ~703 | 550ms |
| `dataplane_proto41` | ✅ | 200 | ~53084 | 30500ms |
| `dataplane_sipinvitation` | ✅ | 200 | ~138 | 460ms |
| `dataplane_sipquery` | ✅ | 200 | ~5389 | 1380ms |
| `dataplane_sipregistration` | ✅ | 200 | ~383 | 600ms |
| `dataplane_smtpdata` | ✅ | 200 | ~356 | 380ms |
| `dataplane_smtpgreet` | ✅ | 200 | ~9540 | 1940ms |
| `dataplane_sshclient` | ✅ | 200 | ~20324 | 3130ms |
| `dataplane_sshpwauth` | ✅ | 200 | ~10005 | 1100ms |
| `dataplane_telnetlogin` | ✅ | 200 | ~41937 | 7310ms |
| `dataplane_vncrfb` | ✅ | 200 | ~1603 | 330ms |

## ❌ Fehlerhafte Feeds

| Feed | HTTP | Fehler | Reaktionszeit |
|---|---|---|---|
| `abuseipdb_tmiland` | 0 | <urlopen error timed out> | 62104ms |
| `edanwong` | 404 | HTTP 404 | 289ms |
| `fortigate_azure` | 404 | HTTP 404 | 357ms |

## ⚠️ Feeds ohne IPs (möglicherweise leer oder falsches Format)

| Feed | HTTP | Reaktionszeit |
|---|---|---|
| `blocklist_de_ssh` | 200 | 140ms |

## ✅ Alle Feeds – Übersicht

| Feed | Status | HTTP | IPs (Sample) | Reaktionszeit |
|---|---|---|---|---|
| `4ip_high_security` | ✅ | 200 | ~54812 | 890ms |
| `abuseipdb_axllent` | ✅ | 200 | ~102538 | 4430ms |
| `abuseipdb_s100_30d` | ✅ | 200 | ~133191 | 19240ms |
| `abuseipdb_s100_7d` | ✅ | 200 | ~73414 | 12670ms |
| `abuseipdb_score100` | ✅ | 200 | ~8628 | 1870ms |
| `amitambekar_threats_aa` | ✅ | 200 | ~40164 | 4130ms |
| `ashleykleynhans_abuseipdb` | ✅ | 200 | ~31614 | 5690ms |
| `binary_defense` | ✅ | 200 | ~1677 | 240ms |
| `bitwire_ipblocklist` | ✅ | 200 | ~1815769 | 28840ms |
| `black_mirror` | ✅ | 200 | ~1577401 | 23490ms |
| `blocklist_de_all` | ✅ | 200 | ~7711 | 990ms |
| `blocklist_de_export` | ✅ | 200 | ~7711 | 690ms |
| `blocklist_de_ssh` | ⚠️ | 200 | ~0 | 140ms |
| `blocklist_de_strongips` | ✅ | 200 | ~382 | 300ms |
| `blocklist_net_ua` | ✅ | 200 | ~208483 | 3470ms |
| `bsdly_bruteforcers` | ✅ | 200 | ~123209 | 4650ms |
| `bsdly_pop3` | ✅ | 200 | ~4216 | 1470ms |
| `bsdly_traplist` | ✅ | 200 | ~642 | 980ms |
| `c2_iplist` | ✅ | 200 | ~126 | 340ms |
| `cinsarmy` | ✅ | 200 | ~15000 | 550ms |
| `cinsscore` | ✅ | 200 | ~15000 | 380ms |
| `crowdsec_ssh` | ✅ | 200 | ~14269 | 310ms |
| `cypher139_ipblacklist` | ✅ | 200 | ~28637 | 3090ms |
| `danger_bruteforce` | ✅ | 200 | ~606 | 1530ms |
| `data_shield` | ✅ | 200 | ~100243 | 790ms |
| `data_shield_full` | ✅ | 200 | ~89907 | 970ms |
| `dataplane_dnsrd` | ✅ | 200 | ~10713 | 1910ms |
| `dataplane_dnsrdany` | ✅ | 200 | ~325 | 360ms |
| `dataplane_dnstcp` | ✅ | 200 | ~1054 | 440ms |
| `dataplane_dnsversion` | ✅ | 200 | ~7741 | 980ms |
| `dataplane_ntpmode3` | ✅ | 200 | ~4212 | 1350ms |
| `dataplane_ntpmode6` | ✅ | 200 | ~636 | 420ms |
| `dataplane_ntpmode7` | ✅ | 200 | ~703 | 550ms |
| `dataplane_proto41` | ✅ | 200 | ~53084 | 30500ms |
| `dataplane_sipinvitation` | ✅ | 200 | ~138 | 460ms |
| `dataplane_sipquery` | ✅ | 200 | ~5389 | 1380ms |
| `dataplane_sipregistration` | ✅ | 200 | ~383 | 600ms |
| `dataplane_smtpdata` | ✅ | 200 | ~356 | 380ms |
| `dataplane_smtpgreet` | ✅ | 200 | ~9540 | 1940ms |
| `dataplane_sshclient` | ✅ | 200 | ~20324 | 3130ms |
| `dataplane_sshpwauth` | ✅ | 200 | ~10005 | 1100ms |
| `dataplane_telnetlogin` | ✅ | 200 | ~41937 | 7310ms |
| `dataplane_vncrfb` | ✅ | 200 | ~1603 | 330ms |
| `ddrimus_http_threats` | ✅ | 200 | ~396 | 370ms |
| `dshield` | ✅ | 200 | ~40 | 370ms |
| `et_compromised` | ✅ | 200 | ~621 | 710ms |
| `f3csystems` | ✅ | 200 | ~2508 | 1080ms |
| `fadouse_botnet` | ✅ | 200 | ~11289 | 840ms |
| `fadouse_c2` | ✅ | 200 | ~12220 | 1060ms |
| `fadouse_loader` | ✅ | 200 | ~913 | 1890ms |
| `fadouse_malware` | ✅ | 200 | ~66129 | 3390ms |
| `fadouse_ransomware` | ✅ | 200 | ~319 | 470ms |
| `fadouse_rat` | ✅ | 200 | ~3908 | 690ms |
| `fadouse_stealer` | ✅ | 200 | ~1581 | 850ms |
| `fadouse_worm` | ✅ | 200 | ~150 | 590ms |
| `ffraud_confirmed` | ✅ | 200 | ~959063 | 28260ms |
| `firehol_abusers_1d` | ✅ | 200 | ~3617 | 2029ms |
| `firehol_anonymous` | ✅ | 200 | ~1750375 | 26750ms |
| `firehol_level2` | ✅ | 200 | ~4821 | 1420ms |
| `firehol_level3` | ✅ | 200 | ~11524 | 1650ms |
| `firehol_level4` | ✅ | 200 | ~159558 | 4030ms |
| `firehol_webserver` | ✅ | 200 | ~1148 | 480ms |
| `freakuency_threatfeed` | ✅ | 200 | ~19188 | 2110ms |
| `greedybear_recent` | ✅ | 200 | ~5000 | 2880ms |
| `greensnow` | ✅ | 200 | ~5225 | 1150ms |
| `hagezi_tif_cdn` | ✅ | 200 | ~33239 | 80ms |
| `interserver` | ✅ | 200 | ~3642 | 290ms |
| `ipsum_level5` | ✅ | 200 | ~3531 | 210ms |
| `ipsum_level7` | ✅ | 200 | ~295 | 170ms |
| `ipsum_master` | ✅ | 200 | ~112066 | 1210ms |
| `magicteamc_bad_ips` | ✅ | 200 | ~1284947 | 21340ms |
| `myip_ms` | ✅ | 200 | ~1429 | 2029ms |
| `netmountains_blocklist` | ✅ | 200 | ~54109 | 1270ms |
| `pgl_yoyo_adservers` | ✅ | 200 | ~8721 | 1130ms |
| `romain_marcoux` | ✅ | 200 | ~40000 | 890ms |
| `romainmarcoux_aa` | ✅ | 200 | ~300000 | 2990ms |
| `romainmarcoux_ab` | ✅ | 200 | ~300000 | 3620ms |
| `romainmarcoux_outgoing_aa` | ✅ | 200 | ~131072 | 4880ms |
| `romainmarcoux_outgoing_ab` | ✅ | 200 | ~41332 | 2720ms |
| `rtbh_com_tr` | ✅ | 200 | ~68173 | 4650ms |
| `rutgers_drop` | ✅ | 200 | ~1051 | 510ms |
| `sefinek_malicious` | ✅ | 200 | ~221586 | 5800ms |
| `serp07_dude_blacklist` | ✅ | 200 | ~6070 | 5520ms |
| `shadowwhisperer_probes` | ✅ | 200 | ~30264 | 570ms |
| `shadowwhisperer_scanners` | ✅ | 200 | ~62207 | 1470ms |
| `shadowwhisperer_threats` | ✅ | 200 | ~17152 | 580ms |
| `shadowwhisperer_threats_uncl` | ✅ | 200 | ~39482 | 840ms |
| `sky_poppy_recent` | ✅ | 200 | ~117947 | 1860ms |
| `spydi_high_confidence` | ✅ | 200 | ~9605 | 1260ms |
| `threat_live` | ✅ | 200 | ~43700 | 6490ms |
| `threathive_blocklist` | ✅ | 200 | ~171182 | 5260ms |
| `threatslist_paloalto_edl` | ✅ | 200 | ~32377 | 510ms |
| `threatview_high_conf` | ✅ | 200 | ~7928 | 1110ms |
| `ufukart_blacklist` | ✅ | 200 | ~234139 | 3200ms |
| `ultimate_hosts_ips0` | ✅ | 200 | ~144537 | 5260ms |
| `urlhaus_agh` | ✅ | 200 | ~14844 | 2180ms |
| `urlhaus_ips` | ✅ | 200 | ~1355 | 4460ms |
| `viriback_c2` | ✅ | 200 | ~8078 | 1880ms |
| `yuexuan_hfish` | ✅ | 200 | ~328 | 340ms |
| `zerof_ipextractor` | ✅ | 200 | ~12966 | 770ms |
| `abuseipdb_tmiland` | ❌ | 0 | ~0 | 62104ms |
| `edanwong` | ❌ | 404 | ~0 | 289ms |
| `fortigate_azure` | ❌ | 404 | ~0 | 357ms |

---
*Generiert: 2026-10-05 08:27 CEST (Europe/Berlin) | 103 Feeds geprüft*