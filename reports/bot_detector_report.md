# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-23 04:09 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,320,828** |
| Neu (heute) | **+491,029** |
| Entfernt | **-491,674** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 4 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 104 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,598 |
| ✅ `openprx_prx_sd_signatures` | 124,614 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 555 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,974 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,650 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,733 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,840 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,952 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 3,443 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,828 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,804 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,496 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 940 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 898 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 590 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 556 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 465 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 242 |
| ✅ `officialputuid_proxyforeveryone` | 6,538 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,185 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,281 |
| ✅ `ercindedeoglu_proxies` | 50,434 |
| ✅ `ercindedeoglu_proxies_socks4` | 14,266 |
| ✅ `ercindedeoglu_proxies_socks5` | 12,980 |
| ✅ `tuanminpay_live_proxy` | 8,903 |
| ✅ `tuanminpay_live_proxy_http` | 6,407 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,573 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,867 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,915 |
| ✅ `noctiro_getproxy` | 4,421 |
| ✅ `noctiro_getproxy_socks5` | 3,264 |
| ✅ `mohammedcha_proxripper` | 53,699 |
| ✅ `mohammedcha_proxripper_socks4` | 113,448 |
| ✅ `mohammedcha_proxripper_http` | 117,785 |
| ✅ `mohammedcha_proxripper_socks5` | 115,583 |
| ✅ `celestialbrain_worldpool` | 83,548 |
| ✅ `dinoz0rg_proxy_list` | 89,878 |
| ✅ `dinoz0rg_proxy_list_http` | 2,129 |
| ✅ `dinoz0rg_proxy_list_socks5` | 88,685 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,757 |
| ✅ `ian_lusule_proxies_socks5` | 1,804 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 4,610 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,716 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,749 |
| ✅ `leon406_subcrawler` | 121,413 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 6,225 |
| ✅ `hookzof_socks5_list` | 153 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,184 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,750 |
| ✅ `cyberh4ck3r_free_proxy_list` | 3,470 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,644 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 2,122 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-23 04:09 CEST (Europe/Berlin)*