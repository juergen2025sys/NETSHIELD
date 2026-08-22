# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-22 12:48 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,320,898** |
| Neu (heute) | **+1,120** |
| Entfernt | **-588** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 4 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 95 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,598 |
| ✅ `openprx_prx_sd_signatures` | 125,053 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 551 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,974 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,641 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,743 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,692 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,953 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,855 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,303 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,318 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,496 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 940 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 898 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 590 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 556 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 465 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 242 |
| ✅ `officialputuid_proxyforeveryone` | 6,036 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,040 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,117 |
| ✅ `ercindedeoglu_proxies` | 50,282 |
| ✅ `ercindedeoglu_proxies_socks4` | 13,763 |
| ✅ `ercindedeoglu_proxies_socks5` | 12,469 |
| ✅ `tuanminpay_live_proxy` | 9,030 |
| ✅ `tuanminpay_live_proxy_http` | 6,504 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,797 |
| ✅ `tuanminpay_live_proxy_socks5` | 3,129 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,829 |
| ✅ `noctiro_getproxy` | 4,255 |
| ✅ `noctiro_getproxy_socks5` | 3,464 |
| ✅ `mohammedcha_proxripper` | 53,298 |
| ✅ `mohammedcha_proxripper_socks4` | 113,111 |
| ✅ `mohammedcha_proxripper_http` | 117,562 |
| ✅ `mohammedcha_proxripper_socks5` | 115,675 |
| ✅ `celestialbrain_worldpool` | 84,305 |
| ✅ `dinoz0rg_proxy_list` | 89,466 |
| ✅ `dinoz0rg_proxy_list_http` | 1,779 |
| ✅ `dinoz0rg_proxy_list_socks5` | 88,263 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,649 |
| ✅ `ian_lusule_proxies_socks5` | 1,827 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 4,727 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,712 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,749 |
| ✅ `leon406_subcrawler` | 121,290 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 6,083 |
| ✅ `hookzof_socks5_list` | 179 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,189 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,797 |
| ✅ `cyberh4ck3r_free_proxy_list` | 3,244 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,552 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 2,100 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-22 12:48 CEST (Europe/Berlin)*