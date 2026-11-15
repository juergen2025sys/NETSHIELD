# NETSHIELD Weekly Feed Overlap Report

Erzeugt: **2026-11-15 12:37 CET (Europe/Berlin)**

## Kurzfazit

- Geprüfte Feeds: **160**
- Erfolgreich mit IPs: **158**
- Fehler/keine IPs: **2**
- Klon-Warnschwelle: **95.0%** Abdeckung des kleineren Feeds
- Max. IPs je Feed für den Wochencheck: **350,000**

## Klon-Verdacht / sehr hoher Overlap

| Kleiner Feed | Größerer Feed | Gemeinsame IPs | Abdeckung kleiner Feed | Jaccard | Exakt gleich |
|---|---:|---:|---:|---:|---:|
| `kraloveckey_ipsets_blocklist_myip` | `claudiusdecimius_ioc_ipsets_myip` | 1,099 | 100.00% | 100.00% | ja |
| `kraloveckey_ipsets_blocklist_ipsum` | `openprx_prx_sd_signatures` | 136,069 | 100.00% | 96.71% | nein |
| `configserverapps_service_blocklists_level1` | `openprx_prx_sd_signatures` | 92,607 | 100.00% | 65.82% | nein |
| `configserverapps_service_blocklists_level1` | `kraloveckey_ipsets_blocklist_ipsum` | 92,607 | 100.00% | 68.06% | nein |
| `ercindedeoglu_proxies` | `gitrecon1455_fresh_proxy_list` | 54,987 | 100.00% | 25.31% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `ziyadnz_threat_intel_ip_feeds_blacklist` | 39,353 | 100.00% | 40.60% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `openprx_prx_sd_signatures` | 39,353 | 100.00% | 27.97% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `kraloveckey_ipsets_blocklist_ipsum` | 39,353 | 100.00% | 28.92% | nein |
| `configserverapps_service_blocklists_blocklist` | `cbuijs_accomplist_adblock_ip` | 31,068 | 100.00% | 23.96% | nein |
| `configserverapps_service_blocklists_level2` | `ziyadnz_threat_intel_ip_feeds_blacklist` | 27,753 | 100.00% | 28.63% | nein |
| `configserverapps_service_blocklists_level2` | `openprx_prx_sd_signatures` | 27,753 | 100.00% | 19.73% | nein |
| `configserverapps_service_blocklists_level2` | `kraloveckey_ipsets_blocklist_ipsum` | 27,753 | 100.00% | 20.40% | nein |
| `configserverapps_service_blocklists_level2` | `kraloveckey_ipsets_blocklist_ipsum_2` | 27,753 | 100.00% | 70.52% | nein |
| `ercindedeoglu_proxies_socks5` | `gitrecon1455_fresh_proxy_list` | 20,602 | 100.00% | 9.48% | nein |
| `ercindedeoglu_proxies_socks4` | `gitrecon1455_fresh_proxy_list` | 18,976 | 100.00% | 8.73% | nein |
| `oktayalver_siberkapan_list_all_feed` | `oktayalver_siberkapan_list` | 18,580 | 100.00% | 48.69% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `ziyadnz_threat_intel_ip_feeds_blacklist` | 18,171 | 100.00% | 18.75% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `openprx_prx_sd_signatures` | 18,171 | 100.00% | 12.92% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `kraloveckey_ipsets_blocklist_ipsum` | 18,171 | 100.00% | 13.35% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `kraloveckey_ipsets_blocklist_ipsum_2` | 18,171 | 100.00% | 46.17% | nein |
| `alsyundawy_mikrotik_blacklist_ipsum` | `ziyadnz_threat_intel_ip_feeds_blacklist` | 18,078 | 100.00% | 18.65% | nein |
| `alsyundawy_mikrotik_blacklist_ipsum` | `openprx_prx_sd_signatures` | 18,078 | 100.00% | 12.85% | nein |
| `alsyundawy_mikrotik_blacklist_ipsum` | `kraloveckey_ipsets_blocklist_ipsum` | 18,078 | 100.00% | 13.29% | nein |
| `alsyundawy_mikrotik_blacklist_ipsum` | `kraloveckey_ipsets_blocklist_ipsum_2` | 18,078 | 100.00% | 45.94% | nein |
| `alsyundawy_mikrotik_blacklist_ipsum` | `kraloveckey_ipsets_blocklist_ipsum_3` | 18,078 | 100.00% | 99.49% | nein |
| `oktayalver_siberkapan_list_honeypot_feed` | `oktayalver_siberkapan_list` | 11,224 | 100.00% | 29.41% | nein |
| `oktayalver_siberkapan_list_honeypot_feed` | `oktayalver_siberkapan_list_all_feed` | 11,224 | 100.00% | 60.41% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_4` | `ziyadnz_threat_intel_ip_feeds_blacklist` | 9,085 | 100.00% | 9.37% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_4` | `openprx_prx_sd_signatures` | 9,085 | 100.00% | 6.46% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_4` | `kraloveckey_ipsets_blocklist_ipsum` | 9,085 | 100.00% | 6.68% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_4` | `kraloveckey_ipsets_blocklist_ipsum_2` | 9,085 | 100.00% | 23.09% | nein |
| `kraloveckey_ipsets_blocklist_ipsum_4` | `kraloveckey_ipsets_blocklist_ipsum_3` | 9,085 | 100.00% | 50.00% | nein |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | `cbuijs_accomplist_adblock_ip` | 8,690 | 100.00% | 6.70% | nein |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | `cbuijs_accomplist_adblock_ip` | 7,338 | 100.00% | 5.66% | nein |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | `kraloveckey_ipsets_blocklist_yoyo_adservers` | 7,338 | 100.00% | 84.44% | nein |
| `noctiro_getproxy_socks5` | `mohammedcha_proxripper_socks5` | 6,875 | 100.00% | 5.80% | nein |
| `tuanminpay_live_proxy_socks5` | `tuanminpay_live_proxy` | 6,860 | 100.00% | 51.85% | nein |
| `tuanminpay_live_proxy_http` | `tuanminpay_live_proxy` | 6,368 | 100.00% | 48.13% | nein |
| `tuanminpay_live_proxy_socks4` | `tuanminpay_live_proxy` | 4,956 | 100.00% | 37.46% | nein |
| `hookzof_socks5_list` | `tuanminpay_live_proxy` | 4,760 | 100.00% | 35.98% | nein |

## Top Overlap-Paare ab 85%

| Feed A | Feed B | Gemeinsame IPs | Abdeckung kleiner Feed | Abdeckung größerer Feed | Jaccard |
|---|---|---:|---:|---:|---:|
| `kraloveckey_ipsets_blocklist_myip` | `claudiusdecimius_ioc_ipsets_myip` | 1,099 | 100.00% | 100.00% | 100.00% |
| `openprx_prx_sd_signatures` | `kraloveckey_ipsets_blocklist_ipsum` | 136,069 | 100.00% | 96.71% | 96.71% |
| `openprx_prx_sd_signatures` | `configserverapps_service_blocklists_level1` | 92,607 | 100.00% | 65.82% | 65.82% |
| `kraloveckey_ipsets_blocklist_ipsum` | `configserverapps_service_blocklists_level1` | 92,607 | 100.00% | 68.06% | 68.06% |
| `ercindedeoglu_proxies` | `gitrecon1455_fresh_proxy_list` | 54,987 | 100.00% | 25.31% | 25.31% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `kraloveckey_ipsets_blocklist_ipsum_2` | 39,353 | 100.00% | 40.60% | 40.60% |
| `openprx_prx_sd_signatures` | `kraloveckey_ipsets_blocklist_ipsum_2` | 39,353 | 100.00% | 27.97% | 27.97% |
| `kraloveckey_ipsets_blocklist_ipsum` | `kraloveckey_ipsets_blocklist_ipsum_2` | 39,353 | 100.00% | 28.92% | 28.92% |
| `cbuijs_accomplist_adblock_ip` | `configserverapps_service_blocklists_blocklist` | 31,068 | 100.00% | 23.96% | 23.96% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `configserverapps_service_blocklists_level2` | 27,753 | 100.00% | 28.63% | 28.63% |
| `openprx_prx_sd_signatures` | `configserverapps_service_blocklists_level2` | 27,753 | 100.00% | 19.73% | 19.73% |
| `kraloveckey_ipsets_blocklist_ipsum` | `configserverapps_service_blocklists_level2` | 27,753 | 100.00% | 20.40% | 20.40% |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `configserverapps_service_blocklists_level2` | 27,753 | 100.00% | 70.52% | 70.52% |
| `ercindedeoglu_proxies_socks5` | `gitrecon1455_fresh_proxy_list` | 20,602 | 100.00% | 9.48% | 9.48% |
| `ercindedeoglu_proxies_socks4` | `gitrecon1455_fresh_proxy_list` | 18,976 | 100.00% | 8.73% | 8.73% |
| `oktayalver_siberkapan_list` | `oktayalver_siberkapan_list_all_feed` | 18,580 | 100.00% | 48.69% | 48.69% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `kraloveckey_ipsets_blocklist_ipsum_3` | 18,171 | 100.00% | 18.75% | 18.75% |
| `openprx_prx_sd_signatures` | `kraloveckey_ipsets_blocklist_ipsum_3` | 18,171 | 100.00% | 12.92% | 12.92% |
| `kraloveckey_ipsets_blocklist_ipsum` | `kraloveckey_ipsets_blocklist_ipsum_3` | 18,171 | 100.00% | 13.35% | 13.35% |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `kraloveckey_ipsets_blocklist_ipsum_3` | 18,171 | 100.00% | 46.17% | 46.17% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `alsyundawy_mikrotik_blacklist_ipsum` | 18,078 | 100.00% | 18.65% | 18.65% |
| `openprx_prx_sd_signatures` | `alsyundawy_mikrotik_blacklist_ipsum` | 18,078 | 100.00% | 12.85% | 12.85% |
| `kraloveckey_ipsets_blocklist_ipsum` | `alsyundawy_mikrotik_blacklist_ipsum` | 18,078 | 100.00% | 13.29% | 13.29% |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `alsyundawy_mikrotik_blacklist_ipsum` | 18,078 | 100.00% | 45.94% | 45.94% |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `alsyundawy_mikrotik_blacklist_ipsum` | 18,078 | 100.00% | 99.49% | 99.49% |
| `oktayalver_siberkapan_list` | `oktayalver_siberkapan_list_honeypot_feed` | 11,224 | 100.00% | 29.41% | 29.41% |
| `oktayalver_siberkapan_list_all_feed` | `oktayalver_siberkapan_list_honeypot_feed` | 11,224 | 100.00% | 60.41% | 60.41% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `kraloveckey_ipsets_blocklist_ipsum_4` | 9,085 | 100.00% | 9.37% | 9.37% |
| `openprx_prx_sd_signatures` | `kraloveckey_ipsets_blocklist_ipsum_4` | 9,085 | 100.00% | 6.46% | 6.46% |
| `kraloveckey_ipsets_blocklist_ipsum` | `kraloveckey_ipsets_blocklist_ipsum_4` | 9,085 | 100.00% | 6.68% | 6.68% |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `kraloveckey_ipsets_blocklist_ipsum_4` | 9,085 | 100.00% | 23.09% | 23.09% |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `kraloveckey_ipsets_blocklist_ipsum_4` | 9,085 | 100.00% | 50.00% | 50.00% |
| `cbuijs_accomplist_adblock_ip` | `kraloveckey_ipsets_blocklist_yoyo_adservers` | 8,690 | 100.00% | 6.70% | 6.70% |
| `cbuijs_accomplist_adblock_ip` | `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | 7,338 | 100.00% | 5.66% | 5.66% |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | 7,338 | 100.00% | 84.44% | 84.44% |
| `noctiro_getproxy_socks5` | `mohammedcha_proxripper_socks5` | 6,875 | 100.00% | 5.80% | 5.80% |
| `tuanminpay_live_proxy` | `tuanminpay_live_proxy_socks5` | 6,860 | 100.00% | 51.85% | 51.85% |
| `tuanminpay_live_proxy` | `tuanminpay_live_proxy_http` | 6,368 | 100.00% | 48.13% | 48.13% |
| `tuanminpay_live_proxy` | `tuanminpay_live_proxy_socks4` | 4,956 | 100.00% | 37.46% | 37.46% |
| `tuanminpay_live_proxy` | `hookzof_socks5_list` | 4,760 | 100.00% | 35.98% | 35.98% |
| `tuanminpay_live_proxy_socks5` | `hookzof_socks5_list` | 4,760 | 100.00% | 69.39% | 69.39% |
| `noctiro_getproxy` | `mohammedcha_proxripper_http` | 4,490 | 100.00% | 3.84% | 3.84% |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | 4,000 | 100.00% | 51.66% | 51.66% |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | 3,794 | 100.00% | 49.00% | 49.00% |
| `cbuijs_accomplist_adblock_ip` | `kraloveckey_ipsets_blocklist_ipsum_5` | 3,613 | 100.00% | 2.79% | 2.79% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `kraloveckey_ipsets_blocklist_ipsum_5` | 3,613 | 100.00% | 3.73% | 3.73% |
| `openprx_prx_sd_signatures` | `kraloveckey_ipsets_blocklist_ipsum_5` | 3,613 | 100.00% | 2.57% | 2.57% |
| `kraloveckey_ipsets_blocklist_ipsum` | `kraloveckey_ipsets_blocklist_ipsum_5` | 3,613 | 100.00% | 2.66% | 2.66% |
| `kraloveckey_ipsets_blocklist_ipsum_2` | `kraloveckey_ipsets_blocklist_ipsum_5` | 3,613 | 100.00% | 9.18% | 9.18% |
| `kraloveckey_ipsets_blocklist_ipsum_3` | `kraloveckey_ipsets_blocklist_ipsum_5` | 3,613 | 100.00% | 19.88% | 19.88% |
| `kraloveckey_ipsets_blocklist_ipsum_4` | `kraloveckey_ipsets_blocklist_ipsum_5` | 3,613 | 100.00% | 39.77% | 39.77% |
| `oktayalver_siberkapan_list` | `oktayalver_siberkapan_list_nginx_feed` | 3,603 | 100.00% | 9.44% | 9.44% |
| `oktayalver_siberkapan_list_all_feed` | `oktayalver_siberkapan_list_nginx_feed` | 3,603 | 100.00% | 19.39% | 19.39% |
| `gazpitchy92_ip_blocklist` | `romainmarcoux_misc_ip_lists` | 3,584 | 100.00% | 1.02% | 1.02% |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | `kraloveckey_ipsets_blocklist_cleantalk_7d` | 1,968 | 100.00% | 25.42% | 25.42% |
| `idleadmin_threatfeed` | `maximewewer_heimdallblocklists_spamhaus_drop` | 1,753 | 100.00% | 3.24% | 3.24% |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | `maximewewer_heimdallblocklists_spamhaus_drop` | 1,753 | 100.00% | 1.81% | 1.81% |
| `maximewewer_heimdallblocklists_spamhaus_drop` | `obarve_rr37_malicious_ip_blocklist` | 1,753 | 100.00% | 6.88% | 6.88% |
| `ian_lusule_proxies` | `ian_lusule_proxies_socks5` | 1,511 | 100.00% | 50.72% | 50.72% |
| `kraloveckey_ipsets_blocklist_tor_exits_7d` | `kraloveckey_ipsets_blocklist_tor_exits_30d` | 1,300 | 100.00% | 90.40% | 90.40% |

## Feed-Status

| Feed | IPs geprüft | Bester Overlap | Mit Feed | Hinweis |
|---|---:|---:|---|---|
| `antoinevastel_avastel_bot_ips_lists` | 350,000 | 0.86% | `ankaboot_source_email_open_data` | gekürzt geprüft |
| `ankaboot_source_email_open_data` | 350,000 | 32.28% | `configserverapps_service_blocklists_abusers_30d` | gekürzt geprüft |
| `gazpitchy92_ip_blocklist` | 350,000 | 18.63% | `cbuijs_accomplist_adblock_ip` | gekürzt geprüft |
| `configserverapps_service_blocklists_http_365d` | 308,465 | 9.64% | `configserverapps_service_blocklists_ftp_365d` |  |
| `configserverapps_service_blocklists_ftp_365d` | 300,557 | 12.83% | `gazpitchy92_ip_blocklist` |  |
| `configserverapps_service_blocklists_telnet_365d` | 236,173 | 10.82% | `configserverapps_service_blocklists_ssh_365d` |  |
| `kraloveckey_ipsets_blocklist_iblocklist_level1` | 235,630 | 0.18% | `kraloveckey_ipsets_blocklist_iblocklist_level2` |  |
| `configserverapps_service_blocklists_blocklist_webcrawlers` | 231,603 | 11.76% | `kraloveckey_ipsets_blocklist_myip_full` |  |
| `kraloveckey_ipsets_blocklist_blocklist_net_ua` | 225,419 | 78.01% | `configserverapps_service_blocklists_level4` |  |
| `gitrecon1455_fresh_proxy_list` | 217,289 | 54.58% | `mohammedcha_proxripper_socks5` |  |
| `kraloveckey_ipsets_blocklist_myip_full` | 198,010 | 91.97% | `configserverapps_service_blocklists_blocklist_full` |  |
| `configserverapps_service_blocklists_level4` | 185,422 | 94.83% | `kraloveckey_ipsets_blocklist_blocklist_net_ua` |  |
| `configserverapps_service_blocklists_blocklist_full` | 182,117 | 100.00% | `kraloveckey_ipsets_blocklist_myip_full` | Klon-Verdacht |
| `configserverapps_service_blocklists_abusers_30d` | 178,623 | 63.25% | `ankaboot_source_email_open_data` |  |
| `configserverapps_service_blocklists_ssh_365d` | 142,436 | 17.94% | `configserverapps_service_blocklists_telnet_365d` |  |
| `openprx_prx_sd_signatures` | 140,694 | 96.71% | `kraloveckey_ipsets_blocklist_ipsum` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_ipsum` | 136,069 | 100.00% | `openprx_prx_sd_signatures` | Klon-Verdacht |
| `cbuijs_accomplist_adblock_ip` | 129,642 | 76.27% | `openprx_prx_sd_signatures` |  |
| `taylored_itmail_blacklists` | 121,297 | 15.03% | `configserverapps_service_blocklists_sip_365d` |  |
| `mohammedcha_proxripper_socks5` | 118,605 | 99.99% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `mohammedcha_proxripper_http` | 116,927 | 99.90% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `cbuijs_accomplist` | 116,199 | 2.99% | `gitrecon1455_fresh_proxy_list` |  |
| `mohammedcha_proxripper_socks4` | 112,841 | 99.99% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `cbuijs_badip` | 109,880 | 16.66% | `configserverapps_service_blocklists_telnet_365d` |  |
| `maximewewer_heimdallblocklists` | 105,783 | 97.78% | `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | Klon-Verdacht |
| `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | 104,347 | 99.13% | `maximewewer_heimdallblocklists` | Klon-Verdacht |
| `feezony_feezony_ip_inbound_blocklist_split` | 100,000 | 3.26% | `configserverapps_service_blocklists_level4` |  |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_19` | 100,000 | 6.33% | `gitrecon1455_fresh_proxy_list` |  |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_30` | 100,000 | 5.71% | `configserverapps_service_blocklists_level4` |  |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_35` | 100,000 | 3.75% | `openprx_prx_sd_signatures` |  |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_20` | 100,000 | 4.27% | `configserverapps_service_blocklists_level4` |  |
| `feezony_feezony_ip_inbound_blocklist_split_ipinboundblocklist_part_28` | 100,000 | 5.49% | `gazpitchy92_ip_blocklist` |  |
| `configserverapps_service_blocklists_outbound` | 96,969 | 55.84% | `gazpitchy92_ip_blocklist` |  |
| `ziyadnz_threat_intel_ip_feeds_blacklist` | 96,929 | 67.82% | `openprx_prx_sd_signatures` |  |
| `dinoz0rg_proxy_list_socks5` | 95,008 | 100.00% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `configserverapps_service_blocklists_blacklist_all` | 94,017 | 33.11% | `maximewewer_heimdallblocklists` |  |
| `configserverapps_service_blocklists_level1` | 92,607 | 100.00% | `openprx_prx_sd_signatures` | Klon-Verdacht |
| `dinoz0rg_proxy_list` | 92,003 | 100.00% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_iblocklist_level2` | 78,375 | 0.53% | `kraloveckey_ipsets_blocklist_iblocklist_level1` |  |
| `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 75,273 | 32.08% | `configserverapps_service_blocklists_http_365d` |  |
| `configserverapps_service_blocklists_master` | 72,149 | 91.83% | `openprx_prx_sd_signatures` |  |
| `cbuijs_accomplist_adblock_ip_v2` | 65,227 | 1.04% | `gitrecon1455_fresh_proxy_list` |  |
| `ercindedeoglu_proxies` | 54,987 | 100.00% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `idleadmin_threatfeed` | 54,174 | 90.47% | `openprx_prx_sd_signatures` |  |
| `mohammedcha_proxripper` | 53,374 | 99.76% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `alsyundawy_mikrotik_blacklist` | 48,653 | 8.34% | `configserverapps_service_blocklists_blacklist_all` |  |
| `kraloveckey_ipsets_blocklist_iblocklist_edu` | 43,899 | 0.44% | `kraloveckey_ipsets_blocklist_iblocklist_level1` |  |
| `kraloveckey_ipsets_blocklist_ipsum_2` | 39,353 | 100.00% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `oktayalver_siberkapan_list` | 38,162 | 56.50% | `cbuijs_accomplist_adblock_ip` |  |
| `kennybayram_soc_feeds` | 37,426 | 98.80% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `zgzyh_malicious_website_detection` | 33,774 | 59.46% | `oktayalver_siberkapan_list` |  |
| `criticalpathsecurity_public_intelligence_feeds` | 32,722 | 6.11% | `ankaboot_source_email_open_data` |  |
| `configserverapps_service_blocklists_blocklist` | 31,068 | 100.00% | `cbuijs_accomplist_adblock_ip` | Klon-Verdacht |
| `toxyl_ossh_swarm_wordlists` | 30,544 | 58.14% | `configserverapps_service_blocklists_ssh_365d` |  |
| `configserverapps_service_blocklists_rdp_365d` | 29,755 | 36.51% | `gazpitchy92_ip_blocklist` |  |
| `configserverapps_service_blocklists_sip_365d` | 28,031 | 65.04% | `taylored_itmail_blacklists` |  |
| `configserverapps_service_blocklists_level2` | 27,753 | 100.00% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `cercatrova21_blocklist` | 26,439 | 30.44% | `gazpitchy92_ip_blocklist` |  |
| `obarve_rr37_malicious_ip_blocklist` | 25,465 | 94.27% | `openprx_prx_sd_signatures` |  |
| `agent6_6_6_wordpress_login_blocklist` | 23,373 | 5.71% | `kraloveckey_ipsets_blocklist_blocklist_net_ua` |  |
| `alsyundawy_mikrotik_blacklist_blocklist` | 21,091 | 99.69% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `ercindedeoglu_proxies_socks5` | 20,602 | 100.00% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `runtechx_dns_runtech_ao` | 20,457 | 64.53% | `configserverapps_service_blocklists_ssh_365d` |  |
| `ercindedeoglu_proxies_socks4` | 18,976 | 100.00% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_iblocklist_level3` | 18,869 | 0.76% | `kraloveckey_ipsets_blocklist_iblocklist_level1` |  |
| `oktayalver_siberkapan_list_all_feed` | 18,580 | 100.00% | `oktayalver_siberkapan_list` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_ipsum_3` | 18,171 | 100.00% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `claudiusdecimius_ics_ip` | 18,164 | 13.82% | `ziyadnz_threat_intel_ip_feeds_blacklist` |  |
| `alsyundawy_mikrotik_blacklist_ipsum` | 18,078 | 100.00% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `configserverapps_service_blocklists_vnc_365d` | 17,652 | 41.20% | `gazpitchy92_ip_blocklist` |  |
| `bilsectr_sgb_api_bridge` | 16,295 | 95.91% | `theseuss_usom_siber_edl` | Klon-Verdacht |
| `theseuss_usom_siber_edl` | 15,660 | 99.80% | `bilsectr_sgb_api_bridge` | Klon-Verdacht |
| `configserverapps_service_blocklists_forums` | 14,942 | 96.49% | `configserverapps_service_blocklists_abusers_30d` | Klon-Verdacht |
| `configserverapps_service_blocklists_smtp_365d` | 14,916 | 40.53% | `configserverapps_service_blocklists_ftp_365d` |  |
| `kraloveckey_ipsets_blocklist_threatview_high_conf` | 14,692 | 88.66% | `idleadmin_threatfeed` |  |
| `configserverapps_service_blocklists_level2_v2` | 13,968 | 99.36% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `tuanminpay_live_proxy` | 13,231 | 99.69% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `alsyundawy_mikrotik_blacklist_ustc_blacklist` | 13,111 | 61.92% | `openprx_prx_sd_signatures` |  |
| `configserverapps_service_blocklists_level3` | 13,049 | 91.58% | `openprx_prx_sd_signatures` |  |
| `configserverapps_service_blocklists_all` | 12,581 | 99.39% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `oktayalver_siberkapan_list_honeypot_feed` | 11,224 | 100.00% | `oktayalver_siberkapan_list` | Klon-Verdacht |
| `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,764 | 88.87% | `openprx_prx_sd_signatures` |  |
| `kraloveckey_ipsets_blocklist_ipsum_4` | 9,085 | 100.00% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_yoyo_adservers` | 8,690 | 100.00% | `cbuijs_accomplist_adblock_ip` | Klon-Verdacht |
| `configserverapps_service_blocklists_greylist` | 8,417 | 99.60% | `openprx_prx_sd_signatures` | Klon-Verdacht |
| `configserverapps_service_blocklists_blacklist_today` | 8,048 | 96.68% | `openprx_prx_sd_signatures` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_cleantalk_30d` | 7,743 | 51.66% | `kraloveckey_ipsets_blocklist_cleantalk_new_30d` |  |
| `kraloveckey_ipsets_blocklist_iblocklist_yoyo_adservers` | 7,338 | 100.00% | `cbuijs_accomplist_adblock_ip` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_c2intel_unverified` | 7,010 | 14.48% | `configserverapps_service_blocklists_outbound` |  |
| `kraloveckey_ipsets_blocklist_dm_tor` | 6,989 | 96.94% | `openprx_prx_sd_signatures` | Klon-Verdacht |
| `infosec_tr_usom_ioc_sync` | 6,890 | 99.88% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `noctiro_getproxy_socks5` | 6,875 | 100.00% | `mohammedcha_proxripper_socks5` | Klon-Verdacht |
| `tuanminpay_live_proxy_socks5` | 6,860 | 100.00% | `tuanminpay_live_proxy` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_urlhaus_recent` | 6,560 | 99.97% | `zgzyh_malicious_website_detection` | Klon-Verdacht |
| `tuanminpay_live_proxy_http` | 6,368 | 100.00% | `tuanminpay_live_proxy` | Klon-Verdacht |
| `configserverapps_service_blocklists_highrisk` | 6,341 | 25.97% | `openprx_prx_sd_signatures` |  |
| `maximewewer_heimdallblocklists_romainmarcoux_alienvault_ssh_bruteforce` | 4,988 | 93.74% | `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` |  |
| `tuanminpay_live_proxy_socks4` | 4,956 | 100.00% | `tuanminpay_live_proxy` | Klon-Verdacht |
| `configserverapps_service_blocklists_abusers_1d` | 4,817 | 86.57% | `configserverapps_service_blocklists_abusers_30d` |  |
| `hookzof_socks5_list` | 4,760 | 100.00% | `tuanminpay_live_proxy` | Klon-Verdacht |
| `alsyundawy_mikrotik_blacklist_blocklist_ssh` | 4,695 | 99.85% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `bert_janp_open_source_threat_intel_feeds` | 4,644 | 99.61% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `noctiro_getproxy` | 4,490 | 100.00% | `mohammedcha_proxripper_http` | Klon-Verdacht |
| `configserverapps_service_blocklists_attacks_ssh` | 4,354 | 99.79% | `ziyadnz_threat_intel_ip_feeds_blacklist` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_cleantalk_new_30d` | 4,000 | 100.00% | `kraloveckey_ipsets_blocklist_cleantalk_30d` | Klon-Verdacht |
| `configserverapps_service_blocklists_http_1d` | 3,830 | 82.38% | `configserverapps_service_blocklists_http_365d` |  |
| `kraloveckey_ipsets_blocklist_cleantalk_updated_30d` | 3,794 | 100.00% | `kraloveckey_ipsets_blocklist_cleantalk_30d` | Klon-Verdacht |
| `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 3,642 | 93.55% | `gitrecon1455_fresh_proxy_list` |  |
| `kraloveckey_ipsets_blocklist_ipsum_5` | 3,613 | 100.00% | `cbuijs_accomplist_adblock_ip` | Klon-Verdacht |
| `oktayalver_siberkapan_list_nginx_feed` | 3,603 | 100.00% | `oktayalver_siberkapan_list` | Klon-Verdacht |
| `romainmarcoux_misc_ip_lists` | 3,584 | 100.00% | `gazpitchy92_ip_blocklist` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_iblocklist_ads` | 3,390 | 5.46% | `cbuijs_accomplist_adblock_ip` |  |
| `kraloveckey_ipsets_blocklist_iblocklist_spyware` | 3,348 | 99.70% | `configserverapps_service_blocklists_level4` | Klon-Verdacht |
| `configserverapps_service_blocklists_attacks_imap` | 3,345 | 99.43% | `maximewewer_heimdallblocklists_romainmarcoux_malicious_ip` | Klon-Verdacht |
| `configserverapps_service_blocklists_all_1d` | 3,343 | 94.91% | `configserverapps_service_blocklists_ssh_365d` |  |
| `ian_lusule_proxies` | 2,979 | 99.50% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `vmheaven_vmheaven_io_free_proxy_list_https` | 2,919 | 95.51% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `configserverapps_service_blocklists_botscout_30d` | 2,875 | 97.32% | `configserverapps_service_blocklists_level4` | Klon-Verdacht |
| `vmheaven_vmheaven_io_free_proxy_list` | 2,529 | 95.29% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |
| `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,485 | 97.67% | `gitrecon1455_fresh_proxy_list` | Klon-Verdacht |

## Bewertung

Der Report löscht keine Feeds automatisch. Er markiert nur exakte oder nahezu komplette Überschneidungen. Entfernen sollte man einen Feed erst, wenn er wiederholt kaum einzigartige IPs liefert.

