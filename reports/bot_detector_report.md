# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-31 20:55 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,292,926** |
| Neu (heute) | **+473** |
| Entfernt | **-27** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 63 |
| Quellen nicht erreichbar | 7 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 104 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 57,410 |
| ✅ `openprx_prx_sd_signatures` | 125,418 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 521 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,942 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,310 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,658 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,746 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,888 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,951 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 3,105 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,833 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,525 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,609 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 1,015 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,293 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 744 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 716 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 575 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 335 |
| ✅ `officialputuid_proxyforeveryone` | 6,822 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,615 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,935 |
| ✅ `ercindedeoglu_proxies` | 53,624 |
| ✅ `ercindedeoglu_proxies_socks4` | 18,352 |
| ✅ `ercindedeoglu_proxies_socks5` | 17,081 |
| ✅ `tuanminpay_live_proxy` | 9,457 |
| ✅ `tuanminpay_live_proxy_http` | 6,917 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,777 |
| ✅ `tuanminpay_live_proxy_socks5` | 3,031 |
| ✅ `gitrecon1455_fresh_proxy_list` | 213,367 |
| ✅ `noctiro_getproxy` | 4,770 |
| ✅ `noctiro_getproxy_socks5` | 2,866 |
| ✅ `mohammedcha_proxripper` | 53,591 |
| ✅ `mohammedcha_proxripper_socks4` | 113,115 |
| ✅ `mohammedcha_proxripper_http` | 118,197 |
| ✅ `mohammedcha_proxripper_socks5` | 115,490 |
| ✅ `celestialbrain_worldpool` | 84,961 |
| ✅ `dinoz0rg_proxy_list` | 93,450 |
| ✅ `dinoz0rg_proxy_list_http` | 2,663 |
| ✅ `dinoz0rg_proxy_list_socks5` | 92,280 |
| ✅ `ian_lusule_proxies` | 3,382 |
| ✅ `ian_lusule_proxies_socks5` | 1,757 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,291 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,809 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,765 |
| ✅ `leon406_subcrawler` | 123,194 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 2,787 |
| ✅ `hookzof_socks5_list` | 157 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,087 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,006 |
| ❌ `cyberh4ck3r_free_proxy_list` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 0 |
| ✅ `claudiusdecimius_ioc_ipsets_botscout_30d` | 3,816 |
| ✅ `claudiusdecimius_ioc_ipsets_tor_exits` | 1,425 |
| ✅ `claudiusdecimius_ioc_ipsets_sblam` | 943 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 63 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-31 20:55 CEST (Europe/Berlin)*