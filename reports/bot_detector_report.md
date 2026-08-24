# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-24 04:07 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,308,585** |
| Neu (heute) | **+490,952** |
| Entfernt | **-490,477** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 7 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 83 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,759 |
| ✅ `openprx_prx_sd_signatures` | 125,887 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 557 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,964 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,657 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,727 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,780 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,951 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,841 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,382 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,417 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,521 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 930 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 898 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 590 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 556 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 465 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 242 |
| ✅ `officialputuid_proxyforeveryone` | 6,080 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,160 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,046 |
| ✅ `ercindedeoglu_proxies` | 50,638 |
| ✅ `ercindedeoglu_proxies_socks4` | 14,953 |
| ✅ `ercindedeoglu_proxies_socks5` | 13,652 |
| ✅ `tuanminpay_live_proxy` | 9,321 |
| ✅ `tuanminpay_live_proxy_http` | 6,827 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,609 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,842 |
| ✅ `gitrecon1455_fresh_proxy_list` | 210,072 |
| ✅ `noctiro_getproxy` | 4,663 |
| ✅ `noctiro_getproxy_socks5` | 2,380 |
| ✅ `mohammedcha_proxripper` | 53,108 |
| ✅ `mohammedcha_proxripper_socks4` | 113,113 |
| ✅ `mohammedcha_proxripper_http` | 117,406 |
| ✅ `mohammedcha_proxripper_socks5` | 114,991 |
| ✅ `celestialbrain_worldpool` | 83,861 |
| ✅ `dinoz0rg_proxy_list` | 90,478 |
| ✅ `dinoz0rg_proxy_list_http` | 1,799 |
| ✅ `dinoz0rg_proxy_list_socks5` | 89,269 |
| ✅ `darzanebor_mikroblack` | 47,606 |
| ✅ `ian_lusule_proxies` | 3,013 |
| ✅ `ian_lusule_proxies_socks5` | 1,308 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 4,719 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,742 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,734 |
| ✅ `leon406_subcrawler` | 121,610 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 6,468 |
| ✅ `hookzof_socks5_list` | 118 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,162 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,664 |
| ❌ `cyberh4ck3r_free_proxy_list` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 0 |
| ✅ `claudiusdecimius_ioc_ipsets_botscout_30d` | 3,735 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-24 04:07 CEST (Europe/Berlin)*