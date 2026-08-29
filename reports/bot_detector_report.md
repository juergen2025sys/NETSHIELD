# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-29 09:57 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,318,266** |
| Neu (heute) | **+18,733** |
| Entfernt | **-21,727** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 7 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 115 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 57,194 |
| ✅ `openprx_prx_sd_signatures` | 130,724 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 510 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,909 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,310 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,642 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,724 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,790 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,950 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,568 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,097 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,149 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,560 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 959 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 928 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 489 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 464 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 371 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 252 |
| ✅ `officialputuid_proxyforeveryone` | 6,503 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,562 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,355 |
| ✅ `ercindedeoglu_proxies` | 53,516 |
| ✅ `ercindedeoglu_proxies_socks4` | 18,250 |
| ✅ `ercindedeoglu_proxies_socks5` | 16,981 |
| ✅ `tuanminpay_live_proxy` | 8,715 |
| ✅ `tuanminpay_live_proxy_http` | 6,266 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,055 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,347 |
| ✅ `gitrecon1455_fresh_proxy_list` | 212,721 |
| ✅ `noctiro_getproxy` | 3,881 |
| ✅ `noctiro_getproxy_socks5` | 2,719 |
| ✅ `mohammedcha_proxripper` | 53,088 |
| ✅ `mohammedcha_proxripper_socks4` | 112,746 |
| ✅ `mohammedcha_proxripper_http` | 116,313 |
| ✅ `mohammedcha_proxripper_socks5` | 114,782 |
| ✅ `celestialbrain_worldpool` | 84,210 |
| ✅ `dinoz0rg_proxy_list` | 93,219 |
| ✅ `dinoz0rg_proxy_list_http` | 2,203 |
| ✅ `dinoz0rg_proxy_list_socks5` | 92,039 |
| ✅ `darzanebor_mikroblack` | 47,606 |
| ✅ `ian_lusule_proxies` | 3,124 |
| ✅ `ian_lusule_proxies_socks5` | 1,563 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,615 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,796 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,757 |
| ✅ `leon406_subcrawler` | 122,690 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 2,758 |
| ✅ `hookzof_socks5_list` | 128 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,134 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,001 |
| ❌ `cyberh4ck3r_free_proxy_list` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 0 |
| ✅ `claudiusdecimius_ioc_ipsets_botscout_30d` | 3,781 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-29 09:57 CEST (Europe/Berlin)*