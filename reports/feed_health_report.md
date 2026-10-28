# Feed Health Monitor – Report
**Aktualisiert:** 2026-10-28 07:28 CET (Europe/Berlin)

**Feeds gesamt:** 98 | ✅ 92 OK | ⚠️ 2 leer | ❌ 4 Fehler

---
## ✅ DataPlane-Feeds (Phase 1)

Alle 17 DataPlane-Feeds erreichbar und liefern IPs.

| Feed | Status | HTTP | IPs (Sample) | Reaktionszeit |
|---|---|---|---|---|
| `dataplane_dnsrd` | ✅ | 200 | ~28846 | 12630ms |
| `dataplane_dnsrdany` | ✅ | 200 | ~16280 | 5040ms |
| `dataplane_dnstcp` | ✅ | 200 | ~903 | 960ms |
| `dataplane_dnsversion` | ✅ | 200 | ~6427 | 2690ms |
| `dataplane_ntpmode3` | ✅ | 200 | ~4387 | 2070ms |
| `dataplane_ntpmode6` | ✅ | 200 | ~720 | 770ms |
| `dataplane_ntpmode7` | ✅ | 200 | ~938 | 2060ms |
| `dataplane_proto41` | ✅ | 200 | ~52119 | 38580ms |
| `dataplane_sipinvitation` | ✅ | 200 | ~98 | 740ms |
| `dataplane_sipquery` | ✅ | 200 | ~7701 | 6390ms |
| `dataplane_sipregistration` | ✅ | 200 | ~365 | 1090ms |
| `dataplane_smtpdata` | ✅ | 200 | ~422 | 780ms |
| `dataplane_smtpgreet` | ✅ | 200 | ~9142 | 3760ms |
| `dataplane_sshclient` | ✅ | 200 | ~20543 | 4220ms |
| `dataplane_sshpwauth` | ✅ | 200 | ~10356 | 920ms |
| `dataplane_telnetlogin` | ✅ | 200 | ~50216 | 19650ms |
| `dataplane_vncrfb` | ✅ | 200 | ~2458 | 240ms |

## ❌ Fehlerhafte Feeds

| Feed | HTTP | Fehler | Reaktionszeit |
|---|---|---|---|
| `blocklist_de_all` | 0 | The read operation timed out | 41432ms |
| `blocklist_net_ua` | 0 | The read operation timed out | 56001ms |
| `rtbh_com_tr` | 0 | The read operation timed out | 29128ms |
| `urlhaus_ips` | 410 | HTTP 410 | 460ms |

## ⚠️ Feeds ohne IPs (möglicherweise leer oder falsches Format)

| Feed | HTTP | Reaktionszeit |
|---|---|---|
| `greedybear_recent` | 200 | 1700ms |
| `romainmarcoux_outgoing_ab` | 200 | 1360ms |

## ✅ Alle Feeds – Übersicht

| Feed | Status | HTTP | IPs (Sample) | Reaktionszeit |
|---|---|---|---|---|
| `4ip_high_security` | ✅ | 200 | ~77384 | 1900ms |
| `abuseipdb_axllent` | ✅ | 200 | ~93921 | 3310ms |
| `abuseipdb_s100_30d` | ✅ | 200 | ~130606 | 16940ms |
| `abuseipdb_s100_7d` | ✅ | 200 | ~75540 | 12010ms |
| `abuseipdb_score100` | ✅ | 200 | ~8766 | 870ms |
| `amitambekar_threats_aa` | ✅ | 200 | ~40404 | 2470ms |
| `binary_defense` | ✅ | 200 | ~522 | 60ms |
| `bitwire_ipblocklist` | ✅ | 200 | ~1820754 | 27620ms |
| `black_mirror` | ✅ | 200 | ~1577401 | 22030ms |
| `blocklist_de_export` | ✅ | 200 | ~30564 | 14580ms |
| `blocklist_de_ssh` | ✅ | 200 | ~5307 | 1040ms |
| `blocklist_de_strongips` | ✅ | 200 | ~290 | 9120ms |
| `bsdly_bruteforcers` | ✅ | 200 | ~128613 | 9030ms |
| `bsdly_pop3` | ✅ | 200 | ~8230 | 2600ms |
| `bsdly_traplist` | ✅ | 200 | ~661 | 1920ms |
| `c2_iplist` | ✅ | 200 | ~127 | 410ms |
| `cinsarmy` | ✅ | 200 | ~15000 | 320ms |
| `cinsscore` | ✅ | 200 | ~15000 | 380ms |
| `crowdsec_ssh` | ✅ | 200 | ~9876 | 100ms |
| `cypher139_ipblacklist` | ✅ | 200 | ~29674 | 3360ms |
| `danger_bruteforce` | ✅ | 200 | ~529 | 1170ms |
| `data_shield` | ✅ | 200 | ~123046 | 830ms |
| `data_shield_full` | ✅ | 200 | ~114907 | 690ms |
| `dataplane_dnsrd` | ✅ | 200 | ~28846 | 12630ms |
| `dataplane_dnsrdany` | ✅ | 200 | ~16280 | 5040ms |
| `dataplane_dnstcp` | ✅ | 200 | ~903 | 960ms |
| `dataplane_dnsversion` | ✅ | 200 | ~6427 | 2690ms |
| `dataplane_ntpmode3` | ✅ | 200 | ~4387 | 2070ms |
| `dataplane_ntpmode6` | ✅ | 200 | ~720 | 770ms |
| `dataplane_ntpmode7` | ✅ | 200 | ~938 | 2060ms |
| `dataplane_proto41` | ✅ | 200 | ~52119 | 38580ms |
| `dataplane_sipinvitation` | ✅ | 200 | ~98 | 740ms |
| `dataplane_sipquery` | ✅ | 200 | ~7701 | 6390ms |
| `dataplane_sipregistration` | ✅ | 200 | ~365 | 1090ms |
| `dataplane_smtpdata` | ✅ | 200 | ~422 | 780ms |
| `dataplane_smtpgreet` | ✅ | 200 | ~9142 | 3760ms |
| `dataplane_sshclient` | ✅ | 200 | ~20543 | 4220ms |
| `dataplane_sshpwauth` | ✅ | 200 | ~10356 | 920ms |
| `dataplane_telnetlogin` | ✅ | 200 | ~50216 | 19650ms |
| `dataplane_vncrfb` | ✅ | 200 | ~2458 | 240ms |
| `ddrimus_http_threats` | ✅ | 200 | ~414 | 590ms |
| `dshield` | ✅ | 200 | ~40 | 260ms |
| `et_compromised` | ✅ | 200 | ~515 | 430ms |
| `f3csystems` | ✅ | 200 | ~2507 | 200ms |
| `fadouse_botnet` | ✅ | 200 | ~13095 | 730ms |
| `fadouse_c2` | ✅ | 200 | ~14206 | 720ms |
| `fadouse_loader` | ✅ | 200 | ~1033 | 1010ms |
| `fadouse_malware` | ✅ | 200 | ~71318 | 2060ms |
| `fadouse_ransomware` | ✅ | 200 | ~336 | 220ms |
| `fadouse_rat` | ✅ | 200 | ~4327 | 410ms |
| `fadouse_stealer` | ✅ | 200 | ~1683 | 570ms |
| `fadouse_worm` | ✅ | 200 | ~156 | 300ms |
| `ffraud_confirmed` | ✅ | 200 | ~962663 | 25630ms |
| `firehol_abusers_1d` | ✅ | 200 | ~4056 | 1440ms |
| `firehol_anonymous` | ✅ | 200 | ~1757916 | 22960ms |
| `firehol_level2` | ✅ | 200 | ~23358 | 2900ms |
| `firehol_level3` | ✅ | 200 | ~11962 | 2460ms |
| `firehol_level4` | ✅ | 200 | ~178942 | 4310ms |
| `firehol_webserver` | ✅ | 200 | ~1405 | 590ms |
| `freakuency_threatfeed` | ✅ | 200 | ~20639 | 1590ms |
| `greedybear_recent` | ⚠️ | 200 | ~0 | 1700ms |
| `greensnow` | ✅ | 200 | ~5565 | 740ms |
| `hagezi_tif_cdn` | ✅ | 200 | ~36214 | 6630ms |
| `interserver` | ✅ | 200 | ~3920 | 70ms |
| `ipsum_level5` | ✅ | 200 | ~6086 | 2540ms |
| `ipsum_level7` | ✅ | 200 | ~580 | 890ms |
| `ipsum_master` | ✅ | 200 | ~141943 | 7470ms |
| `magicteamc_bad_ips` | ✅ | 200 | ~1444281 | 17020ms |
| `myip_ms` | ✅ | 200 | ~1679 | 2050ms |
| `netmountains_blocklist` | ✅ | 200 | ~66800 | 2190ms |
| `pgl_yoyo_adservers` | ✅ | 200 | ~8715 | 2340ms |
| `romain_marcoux` | ✅ | 200 | ~40000 | 1080ms |
| `romainmarcoux_aa` | ✅ | 200 | ~300000 | 3910ms |
| `romainmarcoux_ab` | ✅ | 200 | ~300000 | 4780ms |
| `romainmarcoux_outgoing_aa` | ✅ | 200 | ~106524 | 4260ms |
| `romainmarcoux_outgoing_ab` | ⚠️ | 200 | ~0 | 1360ms |
| `rutgers_drop` | ✅ | 200 | ~2252 | 480ms |
| `sefinek_malicious` | ✅ | 200 | ~228199 | 8250ms |
| `serp07_dude_blacklist` | ✅ | 200 | ~6812 | 3530ms |
| `shadowwhisperer_probes` | ✅ | 200 | ~36717 | 1300ms |
| `shadowwhisperer_scanners` | ✅ | 200 | ~62752 | 740ms |
| `shadowwhisperer_threats` | ✅ | 200 | ~17373 | 880ms |
| `shadowwhisperer_threats_uncl` | ✅ | 200 | ~53606 | 1100ms |
| `sky_poppy_recent` | ✅ | 200 | ~122614 | 850ms |
| `threat_live` | ✅ | 200 | ~55236 | 16700ms |
| `threathive_blocklist` | ✅ | 200 | ~206184 | 10190ms |
| `threatslist_paloalto_edl` | ✅ | 200 | ~39915 | 150ms |
| `threatview_high_conf` | ✅ | 200 | ~22419 | 1280ms |
| `ufukart_blacklist` | ✅ | 200 | ~245504 | 3260ms |
| `ultimate_hosts_ips0` | ✅ | 200 | ~144537 | 5080ms |
| `urlhaus_agh` | ✅ | 200 | ~16207 | 1440ms |
| `viriback_c2` | ✅ | 200 | ~8095 | 1200ms |
| `yuexuan_hfish` | ✅ | 200 | ~275 | 1190ms |
| `zerof_ipextractor` | ✅ | 200 | ~32949 | 2290ms |
| `blocklist_de_all` | ❌ | 0 | ~0 | 41432ms |
| `blocklist_net_ua` | ❌ | 0 | ~0 | 56001ms |
| `rtbh_com_tr` | ❌ | 0 | ~0 | 29128ms |
| `urlhaus_ips` | ❌ | 410 | ~0 | 460ms |

---
*Generiert: 2026-10-28 07:28 CET (Europe/Berlin) | 98 Feeds geprüft*