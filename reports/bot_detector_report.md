# Bot-Detector Blacklist – Report
**Aktualisiert:** 2026-09-01 12:36 CEST (Europe/Berlin)  
**Quelle:** Proxy-Feeds aus auto_feed_discovery (dynamisch ausgewaehlt via is_bot_detector_feed_name())

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Gesamt IPs | **1,287,774** |
| Neu (heute) | **+607** |
| Entfernt | **-421** |
| FP-Filter entfernt | 0 |
| Whitelist-Filter entfernt | 0 |
| Quellen gesamt | 63 |
| Quellen nicht erreichbar | 7 |

### Pro Quelle

| Quelle | IPs |
|---|---|
| ✅ `turntuptechnologies_iocs_scanner` | 119 |
| ✅ `kraloveckey_ipsets_blocklist_r2_drop2_scanners` | 57,677 |
| ✅ `openprx_prx_sd_signatures` | 120,180 |
| ✅ `openprx_prx_sd_signatures_url_blocklist` | 527 |
| ✅ `kraloveckey_ipsets_blocklist_socks_proxy_30d` | 2,949 |
| ✅ `alsyundawy_mikrotik_blacklist` | 48,653 |
| ✅ `antoinevastel_avastel_bot_ips_lists` | 500,000 |
| ✅ `ipanalytics_ai_crawler_blocklist` | 2,310 |
| ✅ `ebrasha_abdal_proxy_hub` | 6,644 |
| ✅ `ebrasha_abdal_proxy_hub_socks4_proxy_list_by_ebrasha` | 3,753 |
| ✅ `ebrasha_abdal_proxy_hub_http_proxy_list_by_ebrasha` | 3,091 |
| ✅ `ebrasha_abdal_proxy_hub_socks5_proxy_list_by_ebrasha` | 1,953 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list` | 3,083 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_https` | 3,593 |
| ✅ `vmheaven_vmheaven_io_free_proxy_list_http_anonymous` | 2,512 |
| ✅ `configserverapps_service_blocklists_blocklist_webcrawlers` | 230,621 |
| ✅ `kraloveckey_ipsets_blocklist_sslproxies_30d` | 1,021 |
| ✅ `vpslabcloud_vpslab_free_proxy_list` | 1,202 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl` | 631 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_elite` | 641 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_all_ssl_elite` | 512 |
| ✅ `vpslabcloud_vpslab_free_proxy_list_socks5_all` | 291 |
| ✅ `officialputuid_proxyforeveryone` | 6,717 |
| ✅ `officialputuid_proxyforeveryone_https` | 5,648 |
| ✅ `officialputuid_proxyforeveryone_proxies` | 6,687 |
| ✅ `ercindedeoglu_proxies` | 53,579 |
| ✅ `ercindedeoglu_proxies_socks4` | 18,307 |
| ✅ `ercindedeoglu_proxies_socks5` | 17,032 |
| ✅ `tuanminpay_live_proxy` | 9,184 |
| ✅ `tuanminpay_live_proxy_http` | 6,602 |
| ✅ `tuanminpay_live_proxy_socks4` | 4,444 |
| ✅ `tuanminpay_live_proxy_socks5` | 2,708 |
| ✅ `gitrecon1455_fresh_proxy_list` | 213,087 |
| ✅ `noctiro_getproxy` | 4,581 |
| ✅ `noctiro_getproxy_socks5` | 2,384 |
| ✅ `mohammedcha_proxripper` | 53,782 |
| ✅ `mohammedcha_proxripper_socks4` | 112,605 |
| ✅ `mohammedcha_proxripper_http` | 117,484 |
| ✅ `mohammedcha_proxripper_socks5` | 114,832 |
| ✅ `celestialbrain_worldpool` | 85,020 |
| ✅ `dinoz0rg_proxy_list` | 93,410 |
| ✅ `dinoz0rg_proxy_list_http` | 2,497 |
| ✅ `dinoz0rg_proxy_list_socks5` | 92,251 |
| ✅ `ian_lusule_proxies` | 3,512 |
| ✅ `ian_lusule_proxies_socks5` | 1,652 |
| ✅ `configserverapps_service_blocklists_attacks_bots` | 2,606 |
| ✅ `configserverapps_service_blocklists_botscout_30d` | 3,779 |
| ❌ `breakingtechfr_proxy_free` | 0 |
| ❌ `breakingtechfr_proxy_free_all` | 0 |
| ❌ `breakingtechfr_proxy_free_socks4` | 0 |
| ❌ `breakingtechfr_proxy_free_socks5` | 0 |
| ✅ `mitchellkrogza_nginx_ultimate_bad_bot_blocker` | 10,766 |
| ✅ `leon406_subcrawler` | 123,305 |
| ✅ `kalidada18_threatbase_threatbase_ip_botnet` | 2,800 |
| ✅ `hookzof_socks5_list` | 167 |
| ✅ `claudiusdecimius_ioc_ipsets_socks_proxy_30d` | 4,087 |
| ✅ `claudiusdecimius_ioc_ipsets_myip` | 1,006 |
| ❌ `cyberh4ck3r_free_proxy_list` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks4_proxies` | 0 |
| ❌ `cyberh4ck3r_free_proxy_list_socks5_proxies` | 0 |
| ✅ `claudiusdecimius_ioc_ipsets_botscout_30d` | 3,816 |
| ✅ `claudiusdecimius_ioc_ipsets_tor_exits` | 1,425 |
| ✅ `claudiusdecimius_ioc_ipsets_sblam` | 943 |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.
> Diese 63 Quellen sind dort aus dem Auto-Feed-Loop ausgeschlossen (Doppelzaehlungs-Schutz).

---
*Generiert: 2026-09-01 12:36 CEST (Europe/Berlin)*