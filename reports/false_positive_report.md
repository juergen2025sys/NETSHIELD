# False Positive Checker – Report
**Aktualisiert:** 2026-11-08 19:16 CET (Europe/Berlin)

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 11194511 |
| Whitelist-Treffer (dieser Run) | **4** |
| FP-Set gesamt (kumuliert) | **9** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `state/false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `209.250.236.126` | Bekannte legitime IP-Range (CDN/Cloud) |
| `45.32.150.247` | Bekannte legitime IP-Range (CDN/Cloud) |
| `34.142.140.180` | Bekannte legitime IP-Range (CDN/Cloud) |
| `136.244.112.177` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-11-08 19:16 CET (Europe/Berlin)*