# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-21 01:50 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,319,282** |
| Neu (heute) | **+107** |
| Entfernt | **-85** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 0 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 82 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,343 |
| ✅ `openprx_prx_sd_signatures` | 124,199 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 589 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 3,056 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,645 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,722 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,681 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,953 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,006 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,255 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 1,690 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,457 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 931 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,113 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 606 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 586 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 491 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 308 |
| ✅ `officialputuid_proxyforeveryone` | 5,913 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,108 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 5,744 |
| ✅ `ercindedeoglu_proxies` | 49,751 |
| ✅ `ercindedeoglu_proxies_socks4` | 12,438 |
| ✅ `ercindedeoglu_proxies_socks5` | 10,986 |
| ✅ `tuanminpay_live_proxy` | 8,703 |
| ✅ `tuanminpay_live_proxy_http` | 6,209 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,683 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,917 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,633 |
| ✅ `noctiro_getproxy` | 4,625 |
| ✅ `noctiro_getproxy_socks5` | 2,484 |
| ✅ `mohammedcha_proxripper` | 53,166 |
| ✅ `mohammedcha_proxripper_socks4` | 113,357 |
| ✅ `mohammedcha_proxripper_http` | 117,039 |
| ✅ `mohammedcha_proxripper_socks5` | 115,090 |
| ✅ `celestialbrain_worldpool` | 84,080 |
| ✅ `dinoz0rg_proxy_list` | 88,090 |
| ✅ `dinoz0rg_proxy_list_http` | 1,155 |
| ✅ `dinoz0rg_proxy_list_socks5` | 86,738 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,373 |
| ✅ `ian_lusule_proxies_socks5` | 1,752 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,703 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,658 |
| ✅ `breakingtechfr_proxy_free` | 43,633 |
| ✅ `breakingtechfr_proxy_free_all` | 46,644 |
| ✅ `breakingtechfr_proxy_free_socks4` | 16,351 |
| ✅ `breakingtechfr_proxy_free_socks5` | 15,547 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,752 |
| ✅ `leon406_subcrawler` | 120,779 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 2,852 |
| ✅ `hookzof_socks5_list` | 154 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,240 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,836 |
| ✅ `cyberh4ck3r_free_proxy_list` | 2,778 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,498 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 2,046 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-21 01:50 CEST (Europe/Berlin)*