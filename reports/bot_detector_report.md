# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-31 10:14 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,291,779** |
| Neu (heute) | **+16** |
| Entfernt | **-6** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 63 |
| Quellen nicht erreichbar | 7 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 104 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 57,410 |
| ✅ `openprx_prx_sd_signatures` | 125,417 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 515 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,942 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,310 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,646 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,739 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 3,277 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,951 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 3,729 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 4,455 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,877 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,609 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 1,015 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,172 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 711 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 689 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 560 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 314 |
| ✅ `officialputuid_proxyforeveryone` | 7,010 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,783 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 7,013 |
| ✅ `ercindedeoglu_proxies` | 53,694 |
| ✅ `ercindedeoglu_proxies_socks4` | 18,301 |
| ✅ `ercindedeoglu_proxies_socks5` | 17,039 |
| ✅ `tuanminpay_live_proxy` | 9,308 |
| ✅ `tuanminpay_live_proxy_http` | 6,840 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,519 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,834 |
| ✅ `gitrecon1455_fresh_proxy_list` | 213,203 |
| ✅ `noctiro_getproxy` | 4,214 |
| ✅ `noctiro_getproxy_socks5` | 2,200 |
| ✅ `mohammedcha_proxripper` | 53,989 |
| ✅ `mohammedcha_proxripper_socks4` | 112,893 |
| ✅ `mohammedcha_proxripper_http` | 118,013 |
| ✅ `mohammedcha_proxripper_socks5` | 115,023 |
| ✅ `celestialbrain_worldpool` | 85,112 |
| ✅ `dinoz0rg_proxy_list` | 93,394 |
| ✅ `dinoz0rg_proxy_list_http` | 2,564 |
| ✅ `dinoz0rg_proxy_list_socks5` | 92,238 |
| ✅ `ian_lusule_proxies` | 3,325 |
| ✅ `ian_lusule_proxies_socks5` | 1,428 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,611 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,799 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,766 |
| ✅ `leon406_subcrawler` | 123,116 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 2,836 |
| ✅ `hookzof_socks5_list` | 149 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,109 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,006 |
| ❌ `cyberh4ck3r_free_proxy_list` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 0 |
| ✅ `claudiusdecimius_ioc_ipsets_botscout_30d` | 3,823 |
| ✅ `claudiusdecimius_ioc_ipsets_tor_exits` | 1,430 |
| ✅ `claudiusdecimius_ioc_ipsets_sblam` | 956 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 63 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-31 10:14 CEST (Europe/Berlin)*