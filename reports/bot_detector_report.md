# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-21 21:06 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,318,137** |
| Neu (heute) | **+794** |
| Entfernt | **-31** |
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
| ✅ `ebrasha_abdal_proxy_hub` | 6,654 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,729 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,826 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,953 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 3,072 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,548 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,488 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,483 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 956 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,492 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 824 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 647 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 514 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 270 |
| ✅ `officialputuid_proxyforeveryone` | 6,402 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,220 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,073 |
| ✅ `ercindedeoglu_proxies` | 50,074 |
| ✅ `ercindedeoglu_proxies_socks4` | 13,129 |
| ✅ `ercindedeoglu_proxies_socks5` | 11,810 |
| ✅ `tuanminpay_live_proxy` | 9,115 |
| ✅ `tuanminpay_live_proxy_http` | 6,615 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,887 |
| ✅ `tuanminpay_live_proxy_socks5` | 3,132 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,561 |
| ✅ `noctiro_getproxy` | 4,761 |
| ✅ `noctiro_getproxy_socks5` | 3,171 |
| ✅ `mohammedcha_proxripper` | 53,522 |
| ✅ `mohammedcha_proxripper_socks4` | 113,080 |
| ✅ `mohammedcha_proxripper_http` | 117,608 |
| ✅ `mohammedcha_proxripper_socks5` | 115,443 |
| ✅ `celestialbrain_worldpool` | 83,858 |
| ✅ `dinoz0rg_proxy_list` | 89,026 |
| ✅ `dinoz0rg_proxy_list_http` | 2,068 |
| ✅ `dinoz0rg_proxy_list_socks5` | 87,698 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,514 |
| ✅ `ian_lusule_proxies_socks5` | 1,921 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 3,521 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,679 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,752 |
| ✅ `leon406_subcrawler` | 120,924 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 4,415 |
| ✅ `hookzof_socks5_list` | 162 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,189 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,797 |
| ✅ `cyberh4ck3r_free_proxy_list` | 3,299 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,615 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 2,201 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-21 21:06 CEST (Europe/Berlin)*