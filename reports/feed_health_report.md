# Feed Health Monitor – Report
**Aktualisiert:** 2026-10-22 07:38 CEST (Europe/Berlin)

**Feeds gesamt:** 98 | ✅ 94 OK | ⚠️ 2 leer | ❌ 2 Fehler

---
## ✅ DataPlane-Feeds (Phase 1)

Alle 17 DataPlane-Feeds erreichbar und liefern IPs.

| Feed | Status | HTTP | IPs (Sample) | Reaktionszeit |
|---|---|---|---|---|
| `dataplane_dnsrd` | ✅ | 200 | ~9450 | 1800ms |
| `dataplane_dnsrdany` | ✅ | 200 | ~370 | 470ms |
| `dataplane_dnstcp` | ✅ | 200 | ~1214 | 400ms |
| `dataplane_dnsversion` | ✅ | 200 | ~8316 | 1600ms |
| `dataplane_ntpmode3` | ✅ | 200 | ~4165 | 1120ms |
| `dataplane_ntpmode6` | ✅ | 200 | ~655 | 800ms |
| `dataplane_ntpmode7` | ✅ | 200 | ~831 | 640ms |
| `dataplane_proto41` | ✅ | 200 | ~52513 | 17730ms |
| `dataplane_sipinvitation` | ✅ | 200 | ~101 | 570ms |
| `dataplane_sipquery` | ✅ | 200 | ~7460 | 1570ms |
| `dataplane_sipregistration` | ✅ | 200 | ~325 | 660ms |
| `dataplane_smtpdata` | ✅ | 200 | ~365 | 250ms |
| `dataplane_smtpgreet` | ✅ | 200 | ~10542 | 2220ms |
| `dataplane_sshclient` | ✅ | 200 | ~20610 | 2830ms |
| `dataplane_sshpwauth` | ✅ | 200 | ~9975 | 1640ms |
| `dataplane_telnetlogin` | ✅ | 200 | ~44675 | 7150ms |
| `dataplane_vncrfb` | ✅ | 200 | ~2180 | 760ms |

## ❌ Fehlerhafte Feeds

| Feed | HTTP | Fehler | Reaktionszeit |
|---|---|---|---|
| `threat_live` | 500 | HTTP 500 | 1813ms |
| `urlhaus_ips` | 410 | HTTP 410 | 497ms |

## ⚠️ Feeds ohne IPs (möglicherweise leer oder falsches Format)

| Feed | HTTP | Reaktionszeit |
|---|---|---|
| `greedybear_recent` | 200 | 790ms |
| `romainmarcoux_outgoing_ab` | 200 | 160ms |

## ✅ Alle Feeds – Übersicht

| Feed | Status | HTTP | IPs (Sample) | Reaktionszeit |
|---|---|---|---|---|
| `4ip_high_security` | ✅ | 200 | ~75314 | 710ms |
| `abuseipdb_axllent` | ✅ | 200 | ~93525 | 2930ms |
| `abuseipdb_s100_30d` | ✅ | 200 | ~128415 | 11630ms |
| `abuseipdb_s100_7d` | ✅ | 200 | ~75676 | 5400ms |
| `abuseipdb_score100` | ✅ | 200 | ~8864 | 320ms |
| `amitambekar_threats_aa` | ✅ | 200 | ~40404 | 1670ms |
| `binary_defense` | ✅ | 200 | ~414 | 260ms |
| `bitwire_ipblocklist` | ✅ | 200 | ~1816353 | 32850ms |
| `black_mirror` | ✅ | 200 | ~1577401 | 30590ms |
| `blocklist_de_all` | ✅ | 200 | ~27813 | 2870ms |
| `blocklist_de_export` | ✅ | 200 | ~27813 | 2940ms |
| `blocklist_de_ssh` | ✅ | 200 | ~5202 | 510ms |
| `blocklist_de_strongips` | ✅ | 200 | ~278 | 1320ms |
| `blocklist_net_ua` | ✅ | 200 | ~227186 | 5850ms |
| `bsdly_bruteforcers` | ✅ | 200 | ~127386 | 10670ms |
| `bsdly_pop3` | ✅ | 200 | ~7441 | 4580ms |
| `bsdly_traplist` | ✅ | 200 | ~640 | 3220ms |
| `c2_iplist` | ✅ | 200 | ~157 | 590ms |
| `cinsarmy` | ✅ | 200 | ~15000 | 2270ms |
| `cinsscore` | ✅ | 200 | ~15000 | 560ms |
| `crowdsec_ssh` | ✅ | 200 | ~10128 | 340ms |
| `cypher139_ipblacklist` | ✅ | 200 | ~29380 | 1270ms |
| `danger_bruteforce` | ✅ | 200 | ~470 | 1730ms |
| `data_shield` | ✅ | 200 | ~102900 | 140ms |
| `data_shield_full` | ✅ | 200 | ~92817 | 50ms |
| `dataplane_dnsrd` | ✅ | 200 | ~9450 | 1800ms |
| `dataplane_dnsrdany` | ✅ | 200 | ~370 | 470ms |
| `dataplane_dnstcp` | ✅ | 200 | ~1214 | 400ms |
| `dataplane_dnsversion` | ✅ | 200 | ~8316 | 1600ms |
| `dataplane_ntpmode3` | ✅ | 200 | ~4165 | 1120ms |
| `dataplane_ntpmode6` | ✅ | 200 | ~655 | 800ms |
| `dataplane_ntpmode7` | ✅ | 200 | ~831 | 640ms |
| `dataplane_proto41` | ✅ | 200 | ~52513 | 17730ms |
| `dataplane_sipinvitation` | ✅ | 200 | ~101 | 570ms |
| `dataplane_sipquery` | ✅ | 200 | ~7460 | 1570ms |
| `dataplane_sipregistration` | ✅ | 200 | ~325 | 660ms |
| `dataplane_smtpdata` | ✅ | 200 | ~365 | 250ms |
| `dataplane_smtpgreet` | ✅ | 200 | ~10542 | 2220ms |
| `dataplane_sshclient` | ✅ | 200 | ~20610 | 2830ms |
| `dataplane_sshpwauth` | ✅ | 200 | ~9975 | 1640ms |
| `dataplane_telnetlogin` | ✅ | 200 | ~44675 | 7150ms |
| `dataplane_vncrfb` | ✅ | 200 | ~2180 | 760ms |
| `ddrimus_http_threats` | ✅ | 200 | ~409 | 380ms |
| `dshield` | ✅ | 200 | ~40 | 590ms |
| `et_compromised` | ✅ | 200 | ~477 | 680ms |
| `f3csystems` | ✅ | 200 | ~2418 | 1290ms |
| `fadouse_botnet` | ✅ | 200 | ~12427 | 1630ms |
| `fadouse_c2` | ✅ | 200 | ~13401 | 1400ms |
| `fadouse_loader` | ✅ | 200 | ~998 | 1960ms |
| `fadouse_malware` | ✅ | 200 | ~70369 | 5230ms |
| `fadouse_ransomware` | ✅ | 200 | ~333 | 630ms |
| `fadouse_rat` | ✅ | 200 | ~4258 | 910ms |
| `fadouse_stealer` | ✅ | 200 | ~1665 | 660ms |
| `fadouse_worm` | ✅ | 200 | ~156 | 590ms |
| `ffraud_confirmed` | ✅ | 200 | ~961561 | 34720ms |
| `firehol_abusers_1d` | ✅ | 200 | ~3820 | 2660ms |
| `firehol_anonymous` | ✅ | 200 | ~1756136 | 25920ms |
| `firehol_level2` | ✅ | 200 | ~20076 | 2780ms |
| `firehol_level3` | ✅ | 200 | ~9424 | 1780ms |
| `firehol_level4` | ✅ | 200 | ~175352 | 5560ms |
| `firehol_webserver` | ✅ | 200 | ~1325 | 540ms |
| `freakuency_threatfeed` | ✅ | 200 | ~19962 | 2840ms |
| `greedybear_recent` | ⚠️ | 200 | ~0 | 790ms |
| `greensnow` | ✅ | 200 | ~5385 | 780ms |
| `hagezi_tif_cdn` | ✅ | 200 | ~37331 | 540ms |
| `interserver` | ✅ | 200 | ~3919 | 420ms |
| `ipsum_level5` | ✅ | 200 | ~5731 | 250ms |
| `ipsum_level7` | ✅ | 200 | ~497 | 260ms |
| `ipsum_master` | ✅ | 200 | ~125460 | 1410ms |
| `magicteamc_bad_ips` | ✅ | 200 | ~1420099 | 24760ms |
| `myip_ms` | ✅ | 200 | ~1598 | 2430ms |
| `netmountains_blocklist` | ✅ | 200 | ~70632 | 1930ms |
| `pgl_yoyo_adservers` | ✅ | 200 | ~8717 | 1190ms |
| `romain_marcoux` | ✅ | 200 | ~40000 | 1420ms |
| `romainmarcoux_aa` | ✅ | 200 | ~300000 | 4240ms |
| `romainmarcoux_ab` | ✅ | 200 | ~300000 | 3970ms |
| `romainmarcoux_outgoing_aa` | ✅ | 200 | ~97333 | 1260ms |
| `romainmarcoux_outgoing_ab` | ⚠️ | 200 | ~0 | 160ms |
| `rtbh_com_tr` | ✅ | 200 | ~66599 | 4970ms |
| `rutgers_drop` | ✅ | 200 | ~1834 | 1100ms |
| `sefinek_malicious` | ✅ | 200 | ~227465 | 6660ms |
| `serp07_dude_blacklist` | ✅ | 200 | ~6440 | 1780ms |
| `shadowwhisperer_probes` | ✅ | 200 | ~36270 | 690ms |
| `shadowwhisperer_scanners` | ✅ | 200 | ~62543 | 620ms |
| `shadowwhisperer_threats` | ✅ | 200 | ~16721 | 310ms |
| `shadowwhisperer_threats_uncl` | ✅ | 200 | ~42886 | 490ms |
| `sky_poppy_recent` | ✅ | 200 | ~121642 | 2460ms |
| `threathive_blocklist` | ✅ | 200 | ~202308 | 2450ms |
| `threatslist_paloalto_edl` | ✅ | 200 | ~35394 | 1040ms |
| `threatview_high_conf` | ✅ | 200 | ~19216 | 1780ms |
| `ufukart_blacklist` | ✅ | 200 | ~234541 | 3280ms |
| `ultimate_hosts_ips0` | ✅ | 200 | ~144537 | 2970ms |
| `urlhaus_agh` | ✅ | 200 | ~15921 | 1730ms |
| `viriback_c2` | ✅ | 200 | ~8089 | 2630ms |
| `yuexuan_hfish` | ✅ | 200 | ~287 | 360ms |
| `zerof_ipextractor` | ✅ | 200 | ~30470 | 990ms |
| `threat_live` | ❌ | 500 | ~0 | 1813ms |
| `urlhaus_ips` | ❌ | 410 | ~0 | 497ms |

---
*Generiert: 2026-10-22 07:38 CEST (Europe/Berlin) | 98 Feeds geprüft*