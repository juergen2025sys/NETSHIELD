# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-08-23 10:57 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,307,124** |
| Neu (heute) | **+339** |
| Entfernt | **-143** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 62 |
| Quellen nicht erreichbar | 4 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 104 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 55,759 |
| ✅ `openprx_prx_sd_signatures` | 124,612 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 555 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,964 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,311 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,639 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,741 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 2,865 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,953 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 2,823 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 2,972 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,414 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,522 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 930 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 898 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 590 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 556 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 465 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 242 |
| ✅ `officialputuid_proxyforeveryone` | 6,291 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,295 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,193 |
| ✅ `ercindedeoglu_proxies` | 50,489 |
| ✅ `ercindedeoglu_proxies_socks4` | 14,404 |
| ✅ `ercindedeoglu_proxies_socks5` | 13,125 |
| ✅ `tuanminpay_live_proxy` | 9,101 |
| ✅ `tuanminpay_live_proxy_http` | 6,610 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,445 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,764 |
| ✅ `gitrecon1455_fresh_proxy_list` | 209,835 |
| ✅ `noctiro_getproxy` | 4,185 |
| ✅ `noctiro_getproxy_socks5` | 3,433 |
| ✅ `mohammedcha_proxripper` | 52,980 |
| ✅ `mohammedcha_proxripper_socks4` | 113,016 |
| ✅ `mohammedcha_proxripper_http` | 117,089 |
| ✅ `mohammedcha_proxripper_socks5` | 115,301 |
| ✅ `celestialbrain_worldpool` | 84,132 |
| ✅ `dinoz0rg_proxy_list` | 90,143 |
| ✅ `dinoz0rg_proxy_list_http` | 2,443 |
| ✅ `dinoz0rg_proxy_list_socks5` | 88,949 |
| ✅ `darzanebor_mikroblack` | 47,607 |
| ✅ `ian_lusule_proxies` | 3,207 |
| ✅ `ian_lusule_proxies_socks5` | 1,413 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 4,685 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,734 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,749 |
| ✅ `leon406_subcrawler` | 121,464 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 6,500 |
| ✅ `hookzof_socks5_list` | 187 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,184 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,750 |
| ✅ `cyberh4ck3r_free_proxy_list` | 2,699 |
| ✅ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 2,125 |
| ✅ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 1,712 |
| ✅ `claudiusdecimius_ioc_ipsets_botscout_30d` | 3,703 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 62 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-08-23 10:57 CEST (Europe/Berlin)*