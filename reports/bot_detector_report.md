# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-21 12:58 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,316,751** |
| Neu (heute) | **+157** |
| Entfernt | **-41** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 0 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 91 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,521 |
| ✅ `openprx_prx_sd_signatures` | 121,835 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 564 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 3,096 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,642 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,725 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,684 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,951 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,460 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 2,469 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 1,953 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,483 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 956 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,221 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 607 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 637 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 478 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 290 |
| ✅ `officialputuid_proxyforeveryone` | 5,787 |
| ✅ `officialputuid_proxyforeveryone_https` | 4,970 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,080 |
| ✅ `ercindedeoglu_proxies` | 49,978 |
| ✅ `ercindedeoglu_proxies_socks4` | 12,975 |
| ✅ `ercindedeoglu_proxies_socks5` | 11,539 |
| ✅ `tuanminpay_live_proxy` | 8,456 |
| ✅ `tuanminpay_live_proxy_http` | 5,906 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,243 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,455 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,766 |
| ✅ `noctiro_getproxy` | 4,222 |
| ✅ `noctiro_getproxy_socks5` | 2,498 |
| ✅ `mohammedcha_proxripper` | 52,754 |
| ✅ `mohammedcha_proxripper_socks4` | 113,173 |
| ✅ `mohammedcha_proxripper_http` | 117,175 |
| ✅ `mohammedcha_proxripper_socks5` | 115,191 |
| ✅ `celestialbrain_worldpool` | 84,282 |
| ✅ `dinoz0rg_proxy_list` | 88,750 |
| ✅ `dinoz0rg_proxy_list_http` | 1,901 |
| ✅ `dinoz0rg_proxy_list_socks5` | 87,420 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,223 |
| ✅ `ian_lusule_proxies_socks5` | 1,543 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,813 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,664 |
| ✅ `breakingtechfr_proxy_free` | 43,633 |
| ✅ `breakingtechfr_proxy_free_all` | 46,644 |
| ✅ `breakingtechfr_proxy_free_socks4` | 16,351 |
| ✅ `breakingtechfr_proxy_free_socks5` | 15,547 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,752 |
| ✅ `leon406_subcrawler` | 120,885 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 3,023 |
| ✅ `hookzof_socks5_list` | 122 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,240 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,836 |
| ✅ `cyberh4ck3r_free_proxy_list` | 2,997 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,315 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 1,851 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-21 12:58 CEST (Europe/Berlin)*