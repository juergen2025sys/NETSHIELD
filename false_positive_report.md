# False Positive Checker – Report
**Aktualisiert:** 2026-04-26 06:54 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 4640811 |
| Whitelist-Treffer (dieser Run) | **13** |
| FP-Set gesamt (kumuliert) | **13** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `52.123.128.14` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.250.154.94` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.250.154.95` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.251.14.95` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.251.20.95` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.251.110.94` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.251.127.84` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.251.151.119` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.251.153.119` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.251.154.119` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.251.157.119` | Bekannte legitime IP-Range (CDN/Cloud) |
| `216.239.36.223` | Bekannte legitime IP-Range (CDN/Cloud) |
| `216.239.38.223` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-04-26 06:54 UTC*