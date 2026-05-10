# False Positive Checker – Report
**Aktualisiert:** 2026-05-10 20:52 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 5120209 |
| Whitelist-Treffer (dieser Run) | **5** |
| FP-Set gesamt (kumuliert) | **5** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `216.239.34.21` | Bekannte legitime IP-Range (CDN/Cloud) |
| `57.144.248.1` | Bekannte legitime IP-Range (CDN/Cloud) |
| `216.239.34.223` | Bekannte legitime IP-Range (CDN/Cloud) |
| `216.239.34.36` | Bekannte legitime IP-Range (CDN/Cloud) |
| `57.144.248.141` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-05-10 20:52 UTC*