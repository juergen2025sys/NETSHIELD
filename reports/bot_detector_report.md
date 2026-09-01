# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-09-01 15:06 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,287,764** |
| Neu (heute) | **+183** |
| Entfernt | **-193** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 63 |
| Quellen nicht erreichbar | 7 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 119 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 57,677 |
| ✅ `openprx_prx_sd_signatures` | 120,180 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 528 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,949 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,310 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,645 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,734 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,964 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,954 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,973 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,669 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,439 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,621 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 1,021 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,068 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 587 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 548 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 447 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 258 |
| ✅ `officialputuid_proxyforeveryone` | 6,420 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,546 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,717 |
| ✅ `ercindedeoglu_proxies` | 53,580 |
| ✅ `ercindedeoglu_proxies_socks4` | 18,304 |
| ✅ `ercindedeoglu_proxies_socks5` | 17,030 |
| ✅ `tuanminpay_live_proxy` | 9,342 |
| ✅ `tuanminpay_live_proxy_http` | 6,823 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,345 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,614 |
| ✅ `gitrecon1455_fresh_proxy_list` | 213,201 |
| ✅ `noctiro_getproxy` | 4,889 |
| ✅ `noctiro_getproxy_socks5` | 3,296 |
| ✅ `mohammedcha_proxripper` | 53,375 |
| ✅ `mohammedcha_proxripper_socks4` | 113,278 |
| ✅ `mohammedcha_proxripper_http` | 118,324 |
| ✅ `mohammedcha_proxripper_socks5` | 115,453 |
| ✅ `celestialbrain_worldpool` | 84,926 |
| ✅ `dinoz0rg_proxy_list` | 93,416 |
| ✅ `dinoz0rg_proxy_list_http` | 2,044 |
| ✅ `dinoz0rg_proxy_list_socks5` | 92,240 |
| ✅ `ian_lusule_proxies` | 3,569 |
| ✅ `ian_lusule_proxies_socks5` | 1,669 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,606 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,779 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,766 |
| ✅ `leon406_subcrawler` | 123,305 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 2,800 |
| ✅ `hookzof_socks5_list` | 167 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,099 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,011 |
| ❌ `cyberh4ck3r_free_proxy_list` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 0 |
| ✅ `claudiusdecimius_ioc_ipsets_botscout_30d` | 3,779 |
| ✅ `claudiusdecimius_ioc_ipsets_tor_exits` | 1,420 |
| ✅ `claudiusdecimius_ioc_ipsets_sblam` | 948 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 63 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-09-01 15:06 CEST (Europe/Berlin)*