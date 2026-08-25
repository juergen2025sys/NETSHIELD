# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-25 04:00 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,308,703** |
| Neu (heute) | **+14,417** |
| Entfernt | **-15,030** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 7 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 122 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,916 |
| ✅ `openprx_prx_sd_signatures` | 125,844 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 560 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,998 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,310 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,667 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,747 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,941 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,951 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 3,316 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,771 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,650 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,525 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 956 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 898 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 590 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 556 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 465 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 242 |
| ✅ `officialputuid_proxyforeveryone` | 6,381 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,294 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,276 |
| ✅ `ercindedeoglu_proxies` | 51,081 |
| ✅ `ercindedeoglu_proxies_socks4` | 15,847 |
| ✅ `ercindedeoglu_proxies_socks5` | 14,573 |
| ✅ `tuanminpay_live_proxy` | 9,630 |
| ✅ `tuanminpay_live_proxy_http` | 7,100 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,816 |
| ✅ `tuanminpay_live_proxy_socks5` | 3,048 |
| ✅ `gitrecon1455_fresh_proxy_list` | 210,406 |
| ✅ `noctiro_getproxy` | 4,553 |
| ✅ `noctiro_getproxy_socks5` | 3,116 |
| ✅ `mohammedcha_proxripper` | 53,554 |
| ✅ `mohammedcha_proxripper_socks4` | 112,878 |
| ✅ `mohammedcha_proxripper_http` | 117,242 |
| ✅ `mohammedcha_proxripper_socks5` | 115,076 |
| ✅ `celestialbrain_worldpool` | 83,868 |
| ✅ `dinoz0rg_proxy_list` | 91,039 |
| ✅ `dinoz0rg_proxy_list_http` | 2,167 |
| ✅ `dinoz0rg_proxy_list_socks5` | 89,853 |
| ✅ `darzanebor_mikroblack` | 47,606 |
| ✅ `ian_lusule_proxies` | 3,681 |
| ✅ `ian_lusule_proxies_socks5` | 1,819 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 4,303 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,798 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,732 |
| ✅ `leon406_subcrawler` | 121,790 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 5,535 |
| ✅ `hookzof_socks5_list` | 130 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,158 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,557 |
| ❌ `cyberh4ck3r_free_proxy_list` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 0 |
| ✅ `claudiusdecimius_ioc_ipsets_botscout_30d` | 3,757 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-25 04:00 CEST (Europe/Berlin)*