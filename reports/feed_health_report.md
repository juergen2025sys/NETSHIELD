# Feed Health Monitor – Report
**Aktualisiert:** 2026-10-04 08:33 CEST (Europe/Berlin)

**Feeds gesamt:** 103 | ✅ 99 OK | ⚠️ 1 leer | ❌ 3 Fehler

---
## ✅ DataPlane-Feeds (Phase 1)

Alle 17 DataPlane-Feeds erreichbar und liefern IPs.

| Feed | Status | HTTP | IPs (Sample) | Reaktionszeit |
|---|---|---|---|---|
| `dataplane_dnsrd` | ✅ | 200 | ~10731 | 1200ms |
| `dataplane_dnsrdany` | ✅ | 200 | ~319 | 170ms |
| `dataplane_dnstcp` | ✅ | 200 | ~1057 | 400ms |
| `dataplane_dnsversion` | ✅ | 200 | ~7766 | 1050ms |
| `dataplane_ntpmode3` | ✅ | 200 | ~3727 | 650ms |
| `dataplane_ntpmode6` | ✅ | 200 | ~646 | 570ms |
| `dataplane_ntpmode7` | ✅ | 200 | ~718 | 340ms |
| `dataplane_proto41` | ✅ | 200 | ~52836 | 32229ms |
| `dataplane_sipinvitation` | ✅ | 200 | ~140 | 230ms |
| `dataplane_sipquery` | ✅ | 200 | ~5353 | 920ms |
| `dataplane_sipregistration` | ✅ | 200 | ~395 | 250ms |
| `dataplane_smtpdata` | ✅ | 200 | ~356 | 220ms |
| `dataplane_smtpgreet` | ✅ | 200 | ~9391 | 2110ms |
| `dataplane_sshclient` | ✅ | 200 | ~19037 | 3250ms |
| `dataplane_sshpwauth` | ✅ | 200 | ~8732 | 1250ms |
| `dataplane_telnetlogin` | ✅ | 200 | ~42535 | 12690ms |
| `dataplane_vncrfb` | ✅ | 200 | ~1685 | 470ms |

## ❌ Fehlerhafte Feeds

| Feed | HTTP | Fehler | Reaktionszeit |
|---|---|---|---|
| `abuseipdb_tmiland` | 0 | <urlopen error timed out> | 61397ms |
| `edanwong` | 404 | HTTP 404 | 158ms |
| `fortigate_azure` | 404 | HTTP 404 | 522ms |

## ⚠️ Feeds ohne IPs (möglicherweise leer oder falsches Format)

| Feed | HTTP | Reaktionszeit |
|---|---|---|
| `blocklist_de_ssh` | 200 | 110ms |

## ✅ Alle Feeds – Übersicht

| Feed | Status | HTTP | IPs (Sample) | Reaktionszeit |
|---|---|---|---|---|
| `4ip_high_security` | ✅ | 200 | ~55251 | 740ms |
| `abuseipdb_axllent` | ✅ | 200 | ~102799 | 5390ms |
| `abuseipdb_s100_30d` | ✅ | 200 | ~133727 | 16810ms |
| `abuseipdb_s100_7d` | ✅ | 200 | ~72880 | 10300ms |
| `abuseipdb_score100` | ✅ | 200 | ~8542 | 540ms |
| `amitambekar_threats_aa` | ✅ | 200 | ~40164 | 2560ms |
| `ashleykleynhans_abuseipdb` | ✅ | 200 | ~31614 | 4070ms |
| `binary_defense` | ✅ | 200 | ~1397 | 370ms |
| `bitwire_ipblocklist` | ✅ | 200 | ~1815895 | 33130ms |
| `black_mirror` | ✅ | 200 | ~1577401 | 24770ms |
| `blocklist_de_all` | ✅ | 200 | ~7967 | 1110ms |
| `blocklist_de_export` | ✅ | 200 | ~7967 | 1850ms |
| `blocklist_de_ssh` | ⚠️ | 200 | ~0 | 110ms |
| `blocklist_de_strongips` | ✅ | 200 | ~385 | 190ms |
| `blocklist_net_ua` | ✅ | 200 | ~208483 | 3150ms |
| `bsdly_bruteforcers` | ✅ | 200 | ~123051 | 9740ms |
| `bsdly_pop3` | ✅ | 200 | ~3869 | 3480ms |
| `bsdly_traplist` | ✅ | 200 | ~3020 | 3570ms |
| `c2_iplist` | ✅ | 200 | ~131 | 1160ms |
| `cinsarmy` | ✅ | 200 | ~15000 | 140ms |
| `cinsscore` | ✅ | 200 | ~15000 | 290ms |
| `crowdsec_ssh` | ✅ | 200 | ~14180 | 310ms |
| `cypher139_ipblacklist` | ✅ | 200 | ~28637 | 2000ms |
| `danger_bruteforce` | ✅ | 200 | ~607 | 1910ms |
| `data_shield` | ✅ | 200 | ~100243 | 1190ms |
| `data_shield_full` | ✅ | 200 | ~89817 | 980ms |
| `dataplane_dnsrd` | ✅ | 200 | ~10731 | 1200ms |
| `dataplane_dnsrdany` | ✅ | 200 | ~319 | 170ms |
| `dataplane_dnstcp` | ✅ | 200 | ~1057 | 400ms |
| `dataplane_dnsversion` | ✅ | 200 | ~7766 | 1050ms |
| `dataplane_ntpmode3` | ✅ | 200 | ~3727 | 650ms |
| `dataplane_ntpmode6` | ✅ | 200 | ~646 | 570ms |
| `dataplane_ntpmode7` | ✅ | 200 | ~718 | 340ms |
| `dataplane_proto41` | ✅ | 200 | ~52836 | 32229ms |
| `dataplane_sipinvitation` | ✅ | 200 | ~140 | 230ms |
| `dataplane_sipquery` | ✅ | 200 | ~5353 | 920ms |
| `dataplane_sipregistration` | ✅ | 200 | ~395 | 250ms |
| `dataplane_smtpdata` | ✅ | 200 | ~356 | 220ms |
| `dataplane_smtpgreet` | ✅ | 200 | ~9391 | 2110ms |
| `dataplane_sshclient` | ✅ | 200 | ~19037 | 3250ms |
| `dataplane_sshpwauth` | ✅ | 200 | ~8732 | 1250ms |
| `dataplane_telnetlogin` | ✅ | 200 | ~42535 | 12690ms |
| `dataplane_vncrfb` | ✅ | 200 | ~1685 | 470ms |
| `ddrimus_http_threats` | ✅ | 200 | ~396 | 830ms |
| `dshield` | ✅ | 200 | ~40 | 250ms |
| `et_compromised` | ✅ | 200 | ~621 | 720ms |
| `f3csystems` | ✅ | 200 | ~2551 | 1350ms |
| `fadouse_botnet` | ✅ | 200 | ~11249 | 1160ms |
| `fadouse_c2` | ✅ | 200 | ~12182 | 1050ms |
| `fadouse_loader` | ✅ | 200 | ~906 | 2020ms |
| `fadouse_malware` | ✅ | 200 | ~65876 | 4340ms |
| `fadouse_ransomware` | ✅ | 200 | ~319 | 350ms |
| `fadouse_rat` | ✅ | 200 | ~3898 | 470ms |
| `fadouse_stealer` | ✅ | 200 | ~1572 | 650ms |
| `fadouse_worm` | ✅ | 200 | ~150 | 790ms |
| `ffraud_confirmed` | ✅ | 200 | ~959232 | 25460ms |
| `firehol_abusers_1d` | ✅ | 200 | ~3439 | 1280ms |
| `firehol_anonymous` | ✅ | 200 | ~1750375 | 25690ms |
| `firehol_level2` | ✅ | 200 | ~4281 | 1710ms |
| `firehol_level3` | ✅ | 200 | ~12414 | 2380ms |
| `firehol_level4` | ✅ | 200 | ~159558 | 2940ms |
| `firehol_webserver` | ✅ | 200 | ~1250 | 1050ms |
| `freakuency_threatfeed` | ✅ | 200 | ~19180 | 2710ms |
| `greedybear_recent` | ✅ | 200 | ~5000 | 1390ms |
| `greensnow` | ✅ | 200 | ~5324 | 13890ms |
| `hagezi_tif_cdn` | ✅ | 200 | ~33188 | 230ms |
| `interserver` | ✅ | 200 | ~3653 | 570ms |
| `ipsum_level5` | ✅ | 200 | ~3731 | 410ms |
| `ipsum_level7` | ✅ | 200 | ~311 | 440ms |
| `ipsum_master` | ✅ | 200 | ~109695 | 1060ms |
| `magicteamc_bad_ips` | ✅ | 200 | ~1275627 | 20370ms |
| `myip_ms` | ✅ | 200 | ~1538 | 1790ms |
| `netmountains_blocklist` | ✅ | 200 | ~54706 | 1990ms |
| `pgl_yoyo_adservers` | ✅ | 200 | ~8721 | 1540ms |
| `romain_marcoux` | ✅ | 200 | ~40000 | 1170ms |
| `romainmarcoux_aa` | ✅ | 200 | ~300000 | 2080ms |
| `romainmarcoux_ab` | ✅ | 200 | ~300000 | 1320ms |
| `romainmarcoux_outgoing_aa` | ✅ | 200 | ~131072 | 9450ms |
| `romainmarcoux_outgoing_ab` | ✅ | 200 | ~40380 | 2800ms |
| `rtbh_com_tr` | ✅ | 200 | ~78455 | 3490ms |
| `rutgers_drop` | ✅ | 200 | ~1253 | 440ms |
| `sefinek_malicious` | ✅ | 200 | ~221435 | 5200ms |
| `serp07_dude_blacklist` | ✅ | 200 | ~6038 | 2740ms |
| `shadowwhisperer_probes` | ✅ | 200 | ~30255 | 820ms |
| `shadowwhisperer_scanners` | ✅ | 200 | ~62181 | 2470ms |
| `shadowwhisperer_threats` | ✅ | 200 | ~17261 | 480ms |
| `shadowwhisperer_threats_uncl` | ✅ | 200 | ~39172 | 2590ms |
| `sky_poppy_recent` | ✅ | 200 | ~117827 | 2040ms |
| `spydi_high_confidence` | ✅ | 200 | ~9605 | 1040ms |
| `threat_live` | ✅ | 200 | ~43107 | 8560ms |
| `threathive_blocklist` | ✅ | 200 | ~176997 | 2660ms |
| `threatslist_paloalto_edl` | ✅ | 200 | ~32182 | 600ms |
| `threatview_high_conf` | ✅ | 200 | ~9040 | 1400ms |
| `ufukart_blacklist` | ✅ | 200 | ~237879 | 2380ms |
| `ultimate_hosts_ips0` | ✅ | 200 | ~144537 | 4130ms |
| `urlhaus_agh` | ✅ | 200 | ~14692 | 1720ms |
| `urlhaus_ips` | ✅ | 200 | ~1345 | 4610ms |
| `viriback_c2` | ✅ | 200 | ~8077 | 2009ms |
| `yuexuan_hfish` | ✅ | 200 | ~294 | 300ms |
| `zerof_ipextractor` | ✅ | 200 | ~13188 | 1620ms |
| `abuseipdb_tmiland` | ❌ | 0 | ~0 | 61397ms |
| `edanwong` | ❌ | 404 | ~0 | 158ms |
| `fortigate_azure` | ❌ | 404 | ~0 | 522ms |

---
*Generiert: 2026-10-04 08:33 CEST (Europe/Berlin) | 103 Feeds geprüft*