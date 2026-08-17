# False Positive Checker – Report
**Aktualisiert:** 2026-08-17 22:29 CEST (Europe/Berlin)

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 9218560 |
| Whitelist-Treffer (dieser Run) | **5** |
| FP-Set gesamt (kumuliert) | **5** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `state/false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `104.19.230.21` | Bekannte legitime IP-Range (CDN/Cloud) |
| `142.251.155.119` | Bekannte legitime IP-Range (CDN/Cloud) |
| `104.19.229.21` | Bekannte legitime IP-Range (CDN/Cloud) |
| `20.42.72.131` | Bekannte legitime IP-Range (CDN/Cloud) |
| `204.79.197.203` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-08-17 22:29 CEST (Europe/Berlin)*