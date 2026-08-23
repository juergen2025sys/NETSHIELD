# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-23 19:08 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,307,550** |
| Neu (heute) | **+76** |
| Entfernt | **-24** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 4 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 104 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,759 |
| ✅ `openprx_prx_sd_signatures` | 124,613 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 555 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,964 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,636 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,715 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,553 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,951 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,057 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 2,518 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 1,764 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,521 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 930 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 898 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 590 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 556 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 465 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 242 |
| ✅ `officialputuid_proxyforeveryone` | 5,788 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,037 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 5,824 |
| ✅ `ercindedeoglu_proxies` | 50,547 |
| ✅ `ercindedeoglu_proxies_socks4` | 14,638 |
| ✅ `ercindedeoglu_proxies_socks5` | 13,350 |
| ✅ `tuanminpay_live_proxy` | 7,972 |
| ✅ `tuanminpay_live_proxy_http` | 5,519 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,130 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,439 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,967 |
| ✅ `noctiro_getproxy` | 4,023 |
| ✅ `noctiro_getproxy_socks5` | 2,676 |
| ✅ `mohammedcha_proxripper` | 52,544 |
| ✅ `mohammedcha_proxripper_socks4` | 112,763 |
| ✅ `mohammedcha_proxripper_http` | 116,609 |
| ✅ `mohammedcha_proxripper_socks5` | 115,144 |
| ✅ `celestialbrain_worldpool` | 83,833 |
| ✅ `dinoz0rg_proxy_list` | 90,303 |
| ✅ `dinoz0rg_proxy_list_http` | 1,240 |
| ✅ `dinoz0rg_proxy_list_socks5` | 89,111 |
| ✅ `darzanebor_mikroblack` | 47,606 |
| ✅ `ian_lusule_proxies` | 3,142 |
| ✅ `ian_lusule_proxies_socks5` | 1,616 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 4,809 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,733 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,746 |
| ✅ `leon406_subcrawler` | 121,540 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 6,959 |
| ✅ `hookzof_socks5_list` | 102 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,162 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,664 |
| ✅ `cyberh4ck3r_free_proxy_list` | 2,641 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,300 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 1,856 |
| ✅ `claudiusdecimius_ioc_ipsets_botscout_30d` | 3,735 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-23 19:08 CEST (Europe/Berlin)*