# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-21 15:05 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,316,563** |
| Neu (heute) | **+239** |
| Entfernt | **-59** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 4 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 91 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,521 |
| ✅ `openprx_prx_sd_signatures` | 121,839 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 574 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 3,096 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,642 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,718 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,845 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,953 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 3,271 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,591 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,746 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,483 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 956 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,192 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 573 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 582 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 460 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 276 |
| ✅ `officialputuid_proxyforeveryone` | 5,939 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,084 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 5,787 |
| ✅ `ercindedeoglu_proxies` | 49,981 |
| ✅ `ercindedeoglu_proxies_socks4` | 12,975 |
| ✅ `ercindedeoglu_proxies_socks5` | 11,538 |
| ✅ `tuanminpay_live_proxy` | 9,472 |
| ✅ `tuanminpay_live_proxy_http` | 6,768 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,625 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,884 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,459 |
| ✅ `noctiro_getproxy` | 4,129 |
| ✅ `noctiro_getproxy_socks5` | 3,168 |
| ✅ `mohammedcha_proxripper` | 53,368 |
| ✅ `mohammedcha_proxripper_socks4` | 112,964 |
| ✅ `mohammedcha_proxripper_http` | 117,728 |
| ✅ `mohammedcha_proxripper_socks5` | 115,456 |
| ✅ `celestialbrain_worldpool` | 84,400 |
| ✅ `dinoz0rg_proxy_list` | 88,895 |
| ✅ `dinoz0rg_proxy_list_http` | 2,001 |
| ✅ `dinoz0rg_proxy_list_socks5` | 87,561 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 4,320 |
| ✅ `ian_lusule_proxies_socks5` | 1,739 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,845 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,664 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,752 |
| ✅ `leon406_subcrawler` | 120,885 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 3,023 |
| ✅ `hookzof_socks5_list` | 123 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,189 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,797 |
| ✅ `cyberh4ck3r_free_proxy_list` | 3,295 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,513 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 2,041 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-21 15:05 CEST (Europe/Berlin)*