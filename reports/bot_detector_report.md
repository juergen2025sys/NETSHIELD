# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-20 21:02 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,318,369** |
| Neu (heute) | **+185** |
| Entfernt | **-89** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 0 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 82 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,343 |
| ✅ `openprx_prx_sd_signatures` | 124,199 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 589 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 3,056 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,645 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,721 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,603 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,952 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,091 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 2,338 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 1,746 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,457 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 931 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,070 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 572 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 579 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 473 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 264 |
| ✅ `officialputuid_proxyforeveryone` | 5,741 |
| ✅ `officialputuid_proxyforeveryone_https` | 4,951 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 5,811 |
| ✅ `ercindedeoglu_proxies` | 49,570 |
| ✅ `ercindedeoglu_proxies_socks4` | 12,055 |
| ✅ `ercindedeoglu_proxies_socks5` | 10,579 |
| ✅ `tuanminpay_live_proxy` | 8,421 |
| ✅ `tuanminpay_live_proxy_http` | 5,891 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,493 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,760 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,424 |
| ✅ `noctiro_getproxy` | 4,625 |
| ✅ `noctiro_getproxy_socks5` | 2,484 |
| ✅ `mohammedcha_proxripper` | 52,438 |
| ✅ `mohammedcha_proxripper_socks4` | 113,292 |
| ✅ `mohammedcha_proxripper_http` | 116,651 |
| ✅ `mohammedcha_proxripper_socks5` | 114,992 |
| ✅ `celestialbrain_worldpool` | 83,827 |
| ✅ `dinoz0rg_proxy_list` | 87,922 |
| ✅ `dinoz0rg_proxy_list_http` | 1,065 |
| ✅ `dinoz0rg_proxy_list_socks5` | 86,573 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,307 |
| ✅ `ian_lusule_proxies_socks5` | 1,756 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,575 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,651 |
| ✅ `breakingtechfr_proxy_free` | 43,633 |
| ✅ `breakingtechfr_proxy_free_all` | 46,644 |
| ✅ `breakingtechfr_proxy_free_socks4` | 16,351 |
| ✅ `breakingtechfr_proxy_free_socks5` | 15,547 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,764 |
| ✅ `leon406_subcrawler` | 120,728 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 2,852 |
| ✅ `hookzof_socks5_list` | 104 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,240 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,836 |
| ✅ `cyberh4ck3r_free_proxy_list` | 2,676 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,471 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 2,067 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-20 21:02 CEST (Europe/Berlin)*