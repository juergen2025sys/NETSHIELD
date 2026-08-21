# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-21 10:25 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,316,430** |
| Neu (heute) | **+7** |
| Entfernt | **-4** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 0 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 91 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,521 |
| ✅ `openprx_prx_sd_signatures` | 121,835 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 564 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 3,096 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,642 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,715 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,718 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,951 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,790 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,045 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,367 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,483 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 956 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 801 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 543 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 594 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 493 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 290 |
| ✅ `officialputuid_proxyforeveryone` | 6,080 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,123 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,154 |
| ✅ `ercindedeoglu_proxies` | 49,922 |
| ✅ `ercindedeoglu_proxies_socks4` | 12,964 |
| ✅ `ercindedeoglu_proxies_socks5` | 11,527 |
| ✅ `tuanminpay_live_proxy` | 8,305 |
| ✅ `tuanminpay_live_proxy_http` | 5,828 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,097 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,448 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,721 |
| ✅ `noctiro_getproxy` | 4,222 |
| ✅ `noctiro_getproxy_socks5` | 2,498 |
| ✅ `mohammedcha_proxripper` | 52,961 |
| ✅ `mohammedcha_proxripper_socks4` | 113,171 |
| ✅ `mohammedcha_proxripper_http` | 117,148 |
| ✅ `mohammedcha_proxripper_socks5` | 115,167 |
| ✅ `celestialbrain_worldpool` | 84,377 |
| ✅ `dinoz0rg_proxy_list` | 88,602 |
| ✅ `dinoz0rg_proxy_list_http` | 2,544 |
| ✅ `dinoz0rg_proxy_list_socks5` | 87,272 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,031 |
| ✅ `ian_lusule_proxies_socks5` | 1,539 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,828 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,669 |
| ✅ `breakingtechfr_proxy_free` | 43,633 |
| ✅ `breakingtechfr_proxy_free_all` | 46,644 |
| ✅ `breakingtechfr_proxy_free_socks4` | 16,351 |
| ✅ `breakingtechfr_proxy_free_socks5` | 15,547 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,752 |
| ✅ `leon406_subcrawler` | 120,850 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 3,130 |
| ✅ `hookzof_socks5_list` | 175 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,240 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,836 |
| ✅ `cyberh4ck3r_free_proxy_list` | 2,743 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,247 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 1,845 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-21 10:25 CEST (Europe/Berlin)*