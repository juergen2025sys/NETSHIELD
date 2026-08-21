# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-21 03:14 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,319,432** |
| Neu (heute) | **+477,415** |
| Entfernt | **-477,265** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 0 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 91 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,343 |
| ✅ `openprx_prx_sd_signatures` | 124,199 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 589 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 3,056 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,650 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,726 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,626 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,953 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,130 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 2,375 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 1,741 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,457 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 931 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 906 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 563 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 582 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 466 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 276 |
| ✅ `officialputuid_proxyforeveryone` | 5,913 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,108 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 5,744 |
| ✅ `ercindedeoglu_proxies` | 49,753 |
| ✅ `ercindedeoglu_proxies_socks4` | 12,438 |
| ✅ `ercindedeoglu_proxies_socks5` | 10,988 |
| ✅ `tuanminpay_live_proxy` | 8,545 |
| ✅ `tuanminpay_live_proxy_http` | 6,030 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,360 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,591 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,640 |
| ✅ `noctiro_getproxy` | 4,281 |
| ✅ `noctiro_getproxy_socks5` | 3,183 |
| ✅ `mohammedcha_proxripper` | 52,546 |
| ✅ `mohammedcha_proxripper_socks4` | 112,594 |
| ✅ `mohammedcha_proxripper_http` | 116,247 |
| ✅ `mohammedcha_proxripper_socks5` | 115,104 |
| ✅ `celestialbrain_worldpool` | 84,090 |
| ✅ `dinoz0rg_proxy_list` | 88,436 |
| ✅ `dinoz0rg_proxy_list_http` | 1,249 |
| ✅ `dinoz0rg_proxy_list_socks5` | 87,095 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,373 |
| ✅ `ian_lusule_proxies_socks5` | 1,752 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,787 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,661 |
| ✅ `breakingtechfr_proxy_free` | 43,633 |
| ✅ `breakingtechfr_proxy_free_all` | 46,644 |
| ✅ `breakingtechfr_proxy_free_socks4` | 16,351 |
| ✅ `breakingtechfr_proxy_free_socks5` | 15,547 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,752 |
| ✅ `leon406_subcrawler` | 120,802 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 2,852 |
| ✅ `hookzof_socks5_list` | 163 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,240 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,836 |
| ✅ `cyberh4ck3r_free_proxy_list` | 2,729 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,558 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 2,148 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-21 03:14 CEST (Europe/Berlin)*