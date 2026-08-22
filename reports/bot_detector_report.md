# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-22 06:59 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,319,737** |
| Neu (heute) | **+300** |
| Entfernt | **-74** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 4 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 95 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,521 |
| ✅ `openprx_prx_sd_signatures` | 125,053 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 551 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 3,096 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,645 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,734 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,658 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,951 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,279 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 2,648 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 1,912 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,496 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 956 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,020 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 602 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 567 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 472 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 269 |
| ✅ `officialputuid_proxyforeveryone` | 5,888 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,063 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,478 |
| ✅ `ercindedeoglu_proxies` | 50,211 |
| ✅ `ercindedeoglu_proxies_socks4` | 13,613 |
| ✅ `ercindedeoglu_proxies_socks5` | 12,318 |
| ✅ `tuanminpay_live_proxy` | 8,254 |
| ✅ `tuanminpay_live_proxy_http` | 5,756 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,392 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,672 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,633 |
| ✅ `noctiro_getproxy` | 4,655 |
| ✅ `noctiro_getproxy_socks5` | 3,126 |
| ✅ `mohammedcha_proxripper` | 52,708 |
| ✅ `mohammedcha_proxripper_socks4` | 113,097 |
| ✅ `mohammedcha_proxripper_http` | 117,117 |
| ✅ `mohammedcha_proxripper_socks5` | 115,539 |
| ✅ `celestialbrain_worldpool` | 83,810 |
| ✅ `dinoz0rg_proxy_list` | 89,235 |
| ✅ `dinoz0rg_proxy_list_http` | 2,057 |
| ✅ `dinoz0rg_proxy_list_socks5` | 88,020 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,390 |
| ✅ `ian_lusule_proxies_socks5` | 1,782 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 4,700 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,695 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,752 |
| ✅ `leon406_subcrawler` | 121,010 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 5,664 |
| ✅ `hookzof_socks5_list` | 124 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,189 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,797 |
| ✅ `cyberh4ck3r_free_proxy_list` | 2,765 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,507 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 2,029 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-22 06:59 CEST (Europe/Berlin)*