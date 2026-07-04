# NETSHIELD Weekly Feed Overlap Report

Erzeugt: **2026-07-04 17:09 UTC**

## Kurzfazit

- Geprüfte Feeds: **259**
- Erfolgreich mit IPs: **238**
- Fehler/keine IPs: **21**
- Klon-Warnschwelle: **95.0%** Abdeckung des kleineren Feeds
- Max. IPs je Feed für den Wochencheck: **350,000**

## Klon-Verdacht / sehr hoher Overlap

| Kleiner Feed | Größerer Feed | Gemeinsame IPs | Abdeckung kleiner Feed | Jaccard | Exakt gleich |
|---|---:|---:|---:|---:|---:|
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 56,345 | 100.00% | 100.00% | ja |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 25,607 | 100.00% | 100.00% | ja |
| `cve_to_ip_mapper_static` | `update_combined_blacklist_static` | 23,489 | 100.00% | 100.00% | ja |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | `update_combined_blacklist_static` | 19,959 | 100.00% | 100.00% | ja |
| `kraloveckey_ipsets_blocklist_cps_abusech` | `auto_feed_discovery_static` | 7,607 | 100.00% | 100.00% | ja |
| `fadouse_clash_threat_intel_c2` | `update_combined_blacklist_static` | 7,275 | 100.00% | 100.00% | ja |
| `fadouse_clash_threat_intel` | `update_combined_blacklist_static` | 6,996 | 100.00% | 100.00% | ja |
| `kraloveckey_ipsets_blocklist_bds_atif` | `update_combined_blacklist_static` | 3,355 | 100.00% | 100.00% | ja |
| `maximewewer_heimdallblocklists_spamhaus_drop` | `asn_reputation_scorer_static` | 1,678 | 100.00% | 100.00% | ja |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | `cve_to_ip_mapper_static` | 628 | 100.00% | 100.00% | ja |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 371 | 100.00% | 100.00% | ja |
| `auto_feed_discovery_static` | `update_combined_blacklist_static` | 132,543 | 100.00% | 54.40% | nein |
| `update_combined_blacklist_static` | `openprx_prx_sd_signatures` | 111,122 | 100.00% | 96.05% | nein |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 111,122 | 100.00% | 45.61% | nein |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 94,444 | 100.00% | 88.61% | nein |
| `maximewewer_heimdallblocklists` | `update_combined_blacklist_static` | 94,256 | 100.00% | 88.43% | nein |
| `configserverapps_service_blocklists_level1` | `openprx_prx_sd_signatures` | 88,570 | 100.00% | 76.55% | nein |
| `configserverapps_service_blocklists_level1` | `update_combined_blacklist_static` | 88,570 | 100.00% | 36.35% | nein |
| `configserverapps_service_blocklists_level1` | `update_combined_blacklist_static` | 88,570 | 100.00% | 79.71% | nein |
| `update_combined_blacklist_static` | `auto_feed_discovery_static` | 69,138 | 100.00% | 52.16% | nein |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 69,138 | 100.00% | 28.38% | nein |
| `configserverapps_service_blocklists_blocklist` | `update_combined_blacklist_static` | 51,243 | 100.00% | 90.95% | nein |
| `configserverapps_service_blocklists_blocklist` | `update_combined_blacklist_static` | 51,243 | 100.00% | 90.95% | nein |
| `cbuijs_hagezi` | `cbuijs_accomplist_adblock_ip` | 48,204 | 100.00% | 47.68% | nein |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 40,000 | 100.00% | 13.33% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `kraloveckey_ipsets_blocklist_ipsum` | 32,107 | 100.00% | 28.61% | nein |
| `configserverapps_service_blocklists_level2` | `ziyadnz_threat_intel_ip_feeds_blacklist` | 23,994 | 100.00% | 21.47% | nein |
| `configserverapps_service_blocklists_level2` | `openprx_prx_sd_signatures` | 23,994 | 100.00% | 20.74% | nein |
| `configserverapps_service_blocklists_level2` | `update_combined_blacklist_static` | 23,994 | 100.00% | 9.85% | nein |
| `configserverapps_service_blocklists_level2` | `update_combined_blacklist_static` | 23,994 | 100.00% | 21.59% | nein |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | `update_combined_blacklist_static` | 19,959 | 100.00% | 25.06% | nein |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 19,959 | 100.00% | 25.06% | nein |
| `configserverapps_service_blocklists_all` | `update_combined_blacklist_static` | 16,717 | 100.00% | 6.86% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `cbuijs_accomplist_adblock_ip` | 15,367 | 100.00% | 15.20% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `kraloveckey_ipsets_blocklist_ipsum` | 15,367 | 100.00% | 13.69% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `kraloveckey_ipsets_blocklist_ipsum_2` | 15,367 | 100.00% | 47.86% | nein |
| `alsyundawy_mikrotik_blacklist_ipsum` | `idleadmin_threatfeed` | 15,067 | 100.00% | 26.91% | nein |
| `alsyundawy_mikrotik_blacklist_ipsum` | `ziyadnz_threat_intel_ip_feeds_blacklist` | 15,067 | 100.00% | 13.48% | nein |
| `alsyundawy_mikrotik_blacklist_ipsum` | `openprx_prx_sd_signatures` | 15,067 | 100.00% | 13.02% | nein |
| `alsyundawy_mikrotik_blacklist_ipsum` | `update_combined_blacklist_static` | 15,067 | 100.00% | 6.18% | nein |

## Top Overlap-Paare ab 85%

| Feed A | Feed B | Gemeinsame IPs | Abdeckung kleiner Feed | Abdeckung größerer Feed | Jaccard |
|---|---|---:|---:|---:|---:|
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 56,345 | 100.00% | 100.00% | 100.00% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 25,607 | 100.00% | 100.00% | 100.00% |
| `cve_to_ip_mapper_static` | `update_combined_blacklist_static` | 23,489 | 100.00% | 100.00% | 100.00% |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | `update_combined_blacklist_static` | 19,959 | 100.00% | 100.00% | 100.00% |
| `kraloveckey_ipsets_blocklist_cps_abusech` | `auto_feed_discovery_static` | 7,607 | 100.00% | 100.00% | 100.00% |
| `fadouse_clash_threat_intel_c2` | `update_combined_blacklist_static` | 7,275 | 100.00% | 100.00% | 100.00% |
| `fadouse_clash_threat_intel` | `update_combined_blacklist_static` | 6,996 | 100.00% | 100.00% | 100.00% |
| `kraloveckey_ipsets_blocklist_bds_atif` | `update_combined_blacklist_static` | 3,355 | 100.00% | 100.00% | 100.00% |
| `maximewewer_heimdallblocklists_spamhaus_drop` | `asn_reputation_scorer_static` | 1,678 | 100.00% | 100.00% | 100.00% |
| `ziyadnz_threat_intel_ip_feeds_emerging_threats` | `cve_to_ip_mapper_static` | 628 | 100.00% | 100.00% | 100.00% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 371 | 100.00% | 100.00% | 100.00% |
| `auto_feed_discovery_static` | `update_combined_blacklist_static` | 132,543 | 100.00% | 54.40% | 54.40% |
| `openprx_prx_sd_signatures` | `update_combined_blacklist_static` | 111,122 | 100.00% | 96.05% | 96.05% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 111,122 | 100.00% | 45.61% | 45.61% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 94,444 | 100.00% | 88.61% | 88.61% |
| `maximewewer_heimdallblocklists` | `update_combined_blacklist_static` | 94,256 | 100.00% | 88.43% | 88.43% |
| `openprx_prx_sd_signatures` | `configserverapps_service_blocklists_level1` | 88,570 | 100.00% | 76.55% | 76.55% |
| `configserverapps_service_blocklists_level1` | `update_combined_blacklist_static` | 88,570 | 100.00% | 36.35% | 36.35% |
| `configserverapps_service_blocklists_level1` | `update_combined_blacklist_static` | 88,570 | 100.00% | 79.71% | 79.71% |
| `auto_feed_discovery_static` | `update_combined_blacklist_static` | 69,138 | 100.00% | 52.16% | 52.16% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 69,138 | 100.00% | 28.38% | 28.38% |
| `configserverapps_service_blocklists_blocklist` | `update_combined_blacklist_static` | 51,243 | 100.00% | 90.95% | 90.95% |
| `configserverapps_service_blocklists_blocklist` | `update_combined_blacklist_static` | 51,243 | 100.00% | 90.95% | 90.95% |
| `cbuijs_accomplist_adblock_ip` | `cbuijs_hagezi` | 48,204 | 100.00% | 47.68% | 47.68% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 40,000 | 100.00% | 13.33% | 13.33% |
| `kraloveckey_ipsets_blocklist_ipsum` | `kraloveckey_ipsets_blocklist_ipsum_2` | 32,107 | 100.00% | 28.61% | 28.61% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `configserverapps_service_blocklists_level2` | 23,994 | 100.00% | 21.47% | 21.47% |
| `openprx_prx_sd_signatures` | `configserverapps_service_blocklists_level2` | 23,994 | 100.00% | 20.74% | 20.74% |
| `configserverapps_service_blocklists_level2` | `update_combined_blacklist_static` | 23,994 | 100.00% | 9.85% | 9.85% |
| `configserverapps_service_blocklists_level2` | `update_combined_blacklist_static` | 23,994 | 100.00% | 21.59% | 21.59% |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | `update_combined_blacklist_static` | 19,959 | 100.00% | 25.06% | 25.06% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 19,959 | 100.00% | 25.06% | 25.06% |
| `configserverapps_service_blocklists_all` | `update_combined_blacklist_static` | 16,717 | 100.00% | 6.86% | 6.86% |
| `cbuijs_accomplist_adblock_ip` | `kraloveckey_ipsets_blocklist_ipsum_3` | 15,367 | 100.00% | 15.20% | 15.20% |
| `kraloveckey_ipsets_blocklist_ipsum` | `kraloveckey_ipsets_blocklist_ipsum_3` | 15,367 | 100.00% | 13.69% | 13.69% |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `kraloveckey_ipsets_blocklist_ipsum_3` | 15,367 | 100.00% | 47.86% | 47.86% |
| `idleadmin_threatfeed` | `alsyundawy_mikrotik_blacklist_ipsum` | 15,067 | 100.00% | 26.91% | 26.91% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `alsyundawy_mikrotik_blacklist_ipsum` | 15,067 | 100.00% | 13.48% | 13.48% |
| `openprx_prx_sd_signatures` | `alsyundawy_mikrotik_blacklist_ipsum` | 15,067 | 100.00% | 13.02% | 13.02% |
| `alsyundawy_mikrotik_blacklist_ipsum` | `update_combined_blacklist_static` | 15,067 | 100.00% | 6.18% | 6.18% |
| `alsyundawy_mikrotik_blacklist_ipsum` | `update_combined_blacklist_static` | 15,067 | 100.00% | 13.56% | 13.56% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `update_combined_blacklist_static` | 15,000 | 100.00% | 13.42% | 13.42% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 11,306 | 100.00% | 50.68% | 50.68% |
| `auto_feed_discovery_static` | `update_combined_blacklist_static` | 9,339 | 100.00% | 7.05% | 7.05% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 9,339 | 100.00% | 8.76% | 8.76% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 9,339 | 100.00% | 3.83% | 3.83% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 9,339 | 100.00% | 13.51% | 13.51% |
| `cbuijs_accomplist_adblock_ip` | `kraloveckey_ipsets_blocklist_yoyo_adservers` | 8,793 | 100.00% | 8.70% | 8.70% |
| `honeypot_monitor_static` | `honeypot_monitor_static` | 7,551 | 100.00% | 31.85% | 31.85% |
| `cbuijs_accomplist_adblock_ip` | `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | 7,425 | 100.00% | 7.34% | 7.34% |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | 7,425 | 100.00% | 84.44% | 84.44% |
| `cbuijs_accomplist_adblock_ip` | `kraloveckey_ipsets_blocklist_ipsum_4` | 7,411 | 100.00% | 7.33% | 7.33% |
| `kraloveckey_ipsets_blocklist_ipsum` | `kraloveckey_ipsets_blocklist_ipsum_4` | 7,411 | 100.00% | 6.60% | 6.60% |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `kraloveckey_ipsets_blocklist_ipsum_4` | 7,411 | 100.00% | 23.08% | 23.08% |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `kraloveckey_ipsets_blocklist_ipsum_4` | 7,411 | 100.00% | 48.23% | 48.23% |
| `kraloveckey_ipsets_blocklist_ipsum_4` | `update_combined_blacklist_static` | 7,411 | 100.00% | 3.04% | 3.04% |
| `fadouse_clash_threat_intel_c2` | `update_combined_blacklist_static` | 7,275 | 100.00% | 15.71% | 15.71% |
| `update_combined_blacklist_static` | `update_combined_blacklist_static` | 7,275 | 100.00% | 15.71% | 15.71% |
| `idleadmin_threatfeed` | `honeypot_monitor_static` | 7,036 | 100.00% | 12.57% | 12.57% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `honeypot_monitor_static` | 7,036 | 100.00% | 6.29% | 6.29% |

## Feed-Status

| Feed | IPs geprüft | Bester Overlap | Mit Feed | Hinweis |
|---|---:|---:|---|---|
| `antoinevastel_avastel_bot_ips_lists` | 350,000 | 0.40% | `update_combined_blacklist_static` | gekürzt geprüft |
| `update_combined_blacklist_static` | 350,000 | 100.00% | `fadouse_clash_threat_intel` | gekürzt geprüft |
| `update_combined_blacklist_static` | 350,000 | 100.00% | `fadouse_clash_threat_intel` | gekürzt geprüft |
| `update_combined_blacklist_static` | 350,000 | 100.00% | `fadouse_clash_threat_intel` | gekürzt geprüft |
| `update_combined_blacklist_static` | 350,000 | 100.00% | `fadouse_clash_threat_intel` | gekürzt geprüft |
| `update_combined_blacklist_static` | 300,000 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 243,640 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | 235,638 | 0.18% | `kraloveckey_ipsets_blocklist_iblocklist_level2` |  |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | 229,880 | 11.24% | `kraloveckey_ipsets_blocklist_myip_full` |  |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | 221,020 | 45.95% | `update_combined_blacklist_static` |  |
| `update_combined_blacklist_static` | 216,395 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 202,939 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_myip_full` | 191,733 | 92.29% | `configserverapps_service_blocklists_blocklist_full` |  |
| `configserverapps_service_blocklists_outbound` | 178,426 | 66.62% | `update_combined_blacklist_static` |  |
| `configserverapps_service_blocklists_blocklist_full` | 176,950 | 100.00% | `kraloveckey_ipsets_blocklist_myip_full` | Klon-Verdacht |
| `kamalmjt_emerging_attackers_badips` | 166,014 | 41.19% | `configserverapps_service_blocklists_abusers_30d` |  |
| `update_combined_blacklist_static` | 148,757 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_ultimate_hosts_ips0` | 144,461 | 100.00% | `update_combined_blacklist_static` | Klon-Verdacht |
| `configserverapps_service_blocklists_abusers_30d` | 143,223 | 47.74% | `kamalmjt_emerging_attackers_badips` |  |
| `update_combined_blacklist_static` | 139,998 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 137,166 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `auto_feed_discovery_static` | 132,543 | 100.00% | `idleadmin_threatfeed` | Klon-Verdacht |
| `update_combined_blacklist_static` | 131,072 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `openprx_prx_sd_signatures` | 115,697 | 99.99% | `update_combined_blacklist_static` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_ipsum` | 112,223 | 95.28% | `update_combined_blacklist_static` | Klon-Verdacht |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | 111,773 | 90.42% | `update_combined_blacklist_static` |  |
| `update_combined_blacklist_static` | 111,185 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 111,122 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | 111,001 | 98.97% | `update_combined_blacklist_static` | Klon-Verdacht |
| `leon406_subcrawler` | 110,125 | 3.92% | `update_combined_blacklist_static` |  |
| `update_combined_blacklist_static` | 106,587 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `cbuijs_accomplist` | 105,655 | 3.09% | `configserverapps_service_blocklists_abusers_30d` |  |
| `update_combined_blacklist_static` | 103,641 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `cbuijs_accomplist_adblock_ip` | 101,097 | 69.81% | `update_combined_blacklist_static` |  |
| `turbolabit_zzfirewall` | 99,795 | 81.75% | `update_combined_blacklist_static` |  |
| `configserverapps_service_blocklists_level4` | 99,671 | 99.40% | `update_combined_blacklist_static` | Klon-Verdacht |
| `update_combined_blacklist_static` | 99,462 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `configserverapps_service_blocklists_blacklist_all` | 97,356 | 88.78% | `configserverapps_service_blocklists_blacklist_30d` |  |
| `configserverapps_service_blocklists_blocklist_extralarge` | 95,813 | 98.78% | `update_combined_blacklist_static` | Klon-Verdacht |
| `update_combined_blacklist_static` | 94,444 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `maximewewer_heimdallblocklists` | 94,256 | 100.00% | `update_combined_blacklist_static` | Klon-Verdacht |
| `configserverapps_service_blocklists_blacklist_30d` | 88,590 | 97.56% | `configserverapps_service_blocklists_blacklist_all` | Klon-Verdacht |
| `configserverapps_service_blocklists_level1` | 88,570 | 100.00% | `openprx_prx_sd_signatures` | Klon-Verdacht |
| `update_combined_blacklist_static` | 87,815 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 79,649 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | 78,375 | 0.54% | `update_combined_blacklist_static` |  |
| `configserverapps_service_blocklists_http_365d` | 69,146 | 26.47% | `update_combined_blacklist_static` |  |
| `update_combined_blacklist_static` | 69,138 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 68,441 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `cbuijs_accomplist_adblock_ip_v2` | 66,455 | 0.31% | `kraloveckey_ipsets_blocklist_myip_full` |  |
| `update_combined_blacklist_static` | 65,424 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 58,824 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 56,345 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 56,345 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `idleadmin_threatfeed` | 55,995 | 95.12% | `update_combined_blacklist_static` | Klon-Verdacht |
| `update_combined_blacklist_static` | 55,464 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `configserverapps_service_blocklists_master` | 55,183 | 97.44% | `update_combined_blacklist_static` | Klon-Verdacht |
| `cbuijs_badip` | 54,142 | 59.00% | `update_combined_blacklist_static` |  |
| `configserverapps_service_blocklists_blocklist` | 51,243 | 100.00% | `update_combined_blacklist_static` | Klon-Verdacht |
| `update_combined_blacklist_static` | 49,844 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `configserverapps_service_blocklists_blacklist_15d` | 49,583 | 96.83% | `configserverapps_service_blocklists_blacklist_30d` | Klon-Verdacht |
| `alsyundawy_mikrotik_blacklist` | 48,653 | 18.50% | `update_combined_blacklist_static` |  |
| `cbuijs_hagezi` | 48,204 | 100.00% | `cbuijs_accomplist_adblock_ip` | Klon-Verdacht |
| `update_combined_blacklist_static` | 46,305 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 45,918 | 43.01% | `update_combined_blacklist_static` |  |
| `update_combined_blacklist_static` | 44,723 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | 43,892 | 0.44% | `update_combined_blacklist_static` |  |
| `configserverapps_service_blocklists_telnet_365d` | 43,812 | 37.88% | `update_combined_blacklist_static` |  |
| `update_combined_blacklist_static` | 40,000 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `configserverapps_service_blocklists_blocklist_large` | 37,246 | 96.83% | `update_combined_blacklist_static` | Klon-Verdacht |
| `update_combined_blacklist_static` | 36,419 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_ipsum_2` | 32,107 | 100.00% | `kraloveckey_ipsets_blocklist_ipsum` | Klon-Verdacht |
| `update_combined_blacklist_static` | 31,680 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 30,909 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `honeypot_monitor_static` | 29,134 | 100.00% | `idleadmin_threatfeed` | Klon-Verdacht |
| `configserverapps_service_blocklists_blocklist_core` | 27,538 | 98.20% | `update_combined_blacklist_static` | Klon-Verdacht |
| `configserverapps_service_blocklists_all_365d` | 25,931 | 85.84% | `update_combined_blacklist_static` |  |
| `update_combined_blacklist_static` | 25,607 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 25,607 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `alsyundawy_mikrotik_blacklist_blocklist` | 25,288 | 100.00% | `update_combined_blacklist_static` | Klon-Verdacht |
| `update_combined_blacklist_static` | 24,179 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `configserverapps_service_blocklists_level2` | 23,994 | 100.00% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `honeypot_monitor_static` | 23,711 | 100.00% | `idleadmin_threatfeed` | Klon-Verdacht |
| `cve_to_ip_mapper_static` | 23,489 | 100.00% | `idleadmin_threatfeed` | Klon-Verdacht |
| `update_combined_blacklist_static` | 23,489 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 22,982 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 22,309 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `agent6_6_6_wordpress_login_blocklist` | 21,578 | 5.97% | `update_combined_blacklist_static` |  |
| `update_combined_blacklist_static` | 20,138 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | 19,959 | 100.00% | `update_combined_blacklist_static` | Klon-Verdacht |
| `update_combined_blacklist_static` | 19,959 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 19,669 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `configserverapps_service_blocklists_level2_v2` | 19,479 | 99.99% | `update_combined_blacklist_static` | Klon-Verdacht |
| `update_combined_blacklist_static` | 19,038 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | 18,865 | 1.02% | `update_combined_blacklist_static` |  |
| `update_bot_detector_static` | 17,954 | 4.30% | `update_combined_blacklist_static` |  |
| `update_combined_blacklist_static` | 17,734 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `skillter_proxygather` | 17,202 | 31.39% | `ebrasha_abdal_proxy_hub` |  |
| `update_combined_blacklist_static` | 16,857 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `configserverapps_service_blocklists_all` | 16,717 | 100.00% | `update_combined_blacklist_static` | Klon-Verdacht |
| `configserverapps_service_blocklists_ftp_365d` | 16,153 | 41.75% | `update_combined_blacklist_static` |  |
| `kraloveckey_ipsets_blocklist_ipsum_3` | 15,367 | 100.00% | `cbuijs_accomplist_adblock_ip` | Klon-Verdacht |
| `alsyundawy_mikrotik_blacklist_ipsum` | 15,067 | 100.00% | `idleadmin_threatfeed` | Klon-Verdacht |
| `update_combined_blacklist_static` | 15,000 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 15,000 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 14,060 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 13,795 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 13,530 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `configserverapps_service_blocklists_forums` | 13,508 | 95.14% | `configserverapps_service_blocklists_abusers_30d` | Klon-Verdacht |
| `configserverapps_service_blocklists_level3` | 13,269 | 95.40% | `update_combined_blacklist_static` | Klon-Verdacht |
| `update_combined_blacklist_static` | 11,306 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker_globalblacklist` | 10,753 | 92.68% | `update_combined_blacklist_static` |  |
| `update_combined_blacklist_static` | 10,563 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `honeypot_monitor_static` | 10,450 | 100.00% | `idleadmin_threatfeed` | Klon-Verdacht |
| `configserverapps_service_blocklists_blacklist_today` | 10,370 | 92.05% | `configserverapps_service_blocklists_blacklist_15d` |  |
| `configserverapps_service_blocklists_rdp_365d` | 9,958 | 65.15% | `update_combined_blacklist_static` |  |
| `configserverapps_service_blocklists_highrisk` | 9,755 | 19.62% | `kraloveckey_ipsets_blocklist_dm_tor` |  |
| `update_combined_blacklist_static` | 9,344 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 9,339 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |
| `update_combined_blacklist_static` | 8,974 | 100.00% | `fadouse_clash_threat_intel` | Klon-Verdacht |

## Bewertung

Der Report löscht keine Feeds automatisch. Er markiert nur exakte oder nahezu komplette Überschneidungen. Entfernen sollte man einen Feed erst, wenn er wiederholt kaum einzigartige IPs liefert.

