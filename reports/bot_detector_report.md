# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-21 07:22 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,316,348** |
| Neu (heute) | **+10** |
| Entfernt | **-1** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 0 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 91 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,343 |
| ✅ `openprx_prx_sd_signatures` | 121,836 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 564 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 3,056 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,640 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,724 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,799 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,951 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 3,229 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,606 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,594 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,483 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 931 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,149 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 607 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 675 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 471 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 276 |
| ✅ `officialputuid_proxyforeveryone` | 6,154 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,254 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 5,859 |
| ✅ `ercindedeoglu_proxies` | 49,868 |
| ✅ `ercindedeoglu_proxies_socks4` | 12,813 |
| ✅ `ercindedeoglu_proxies_socks5` | 11,374 |
| ✅ `tuanminpay_live_proxy` | 8,816 |
| ✅ `tuanminpay_live_proxy_http` | 6,315 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,658 |
| ✅ `tuanminpay_live_proxy_socks5` | 3,021 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,722 |
| ✅ `noctiro_getproxy` | 4,281 |
| ✅ `noctiro_getproxy_socks5` | 3,183 |
| ✅ `mohammedcha_proxripper` | 53,351 |
| ✅ `mohammedcha_proxripper_socks4` | 113,056 |
| ✅ `mohammedcha_proxripper_http` | 117,653 |
| ✅ `mohammedcha_proxripper_socks5` | 115,519 |
| ✅ `celestialbrain_worldpool` | 84,018 |
| ✅ `dinoz0rg_proxy_list` | 88,602 |
| ✅ `dinoz0rg_proxy_list_http` | 2,544 |
| ✅ `dinoz0rg_proxy_list_socks5` | 87,272 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,353 |
| ✅ `ian_lusule_proxies_socks5` | 1,777 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,828 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,669 |
| ✅ `breakingtechfr_proxy_free` | 43,633 |
| ✅ `breakingtechfr_proxy_free_all` | 46,644 |
| ✅ `breakingtechfr_proxy_free_socks4` | 16,351 |
| ✅ `breakingtechfr_proxy_free_socks5` | 15,547 |
| ✅ `kraloveckey_ipsets_blocklist_maltrail_scanners` | 16,854 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,752 |
| ✅ `leon406_subcrawler` | 120,820 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 3,130 |
| ✅ `hookzof_socks5_list` | 162 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,240 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,836 |
| ✅ `cyberh4ck3r_free_proxy_list` | 2,873 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,449 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 2,082 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-21 07:22 CEST (Europe/Berlin)*