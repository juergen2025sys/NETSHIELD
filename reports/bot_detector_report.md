# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-22 00:50 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,318,255** |
| Neu (heute) | **+77** |
| Entfernt | **-66** |
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
| ✅ `ebrasha_abdal_proxy_hub` | 6,650 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,736 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,756 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,954 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,866 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,269 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,372 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,483 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 956 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,046 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 577 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 582 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 477 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 272 |
| ✅ `officialputuid_proxyforeveryone` | 6,577 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,469 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,402 |
| ✅ `ercindedeoglu_proxies` | 50,131 |
| ✅ `ercindedeoglu_proxies_socks4` | 13,360 |
| ✅ `ercindedeoglu_proxies_socks5` | 12,045 |
| ✅ `tuanminpay_live_proxy` | 8,857 |
| ✅ `tuanminpay_live_proxy_http` | 6,291 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,606 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,836 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,619 |
| ✅ `noctiro_getproxy` | 4,761 |
| ✅ `noctiro_getproxy_socks5` | 3,171 |
| ✅ `mohammedcha_proxripper` | 53,283 |
| ✅ `mohammedcha_proxripper_socks4` | 112,997 |
| ✅ `mohammedcha_proxripper_http` | 117,623 |
| ✅ `mohammedcha_proxripper_socks5` | 115,414 |
| ✅ `celestialbrain_worldpool` | 83,904 |
| ✅ `dinoz0rg_proxy_list` | 89,153 |
| ✅ `dinoz0rg_proxy_list_http` | 2,811 |
| ✅ `dinoz0rg_proxy_list_socks5` | 87,932 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,565 |
| ✅ `ian_lusule_proxies_socks5` | 1,721 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 3,521 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,679 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,752 |
| ✅ `leon406_subcrawler` | 120,964 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 4,415 |
| ✅ `hookzof_socks5_list` | 189 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,189 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,797 |
| ✅ `cyberh4ck3r_free_proxy_list` | 3,052 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,478 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 2,023 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-22 00:50 CEST (Europe/Berlin)*