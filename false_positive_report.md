# False Positive Checker – Report
**Aktualisiert:** 2026-05-11 16:05 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 5137852 |
| Whitelist-Treffer (dieser Run) | **6** |
| FP-Set gesamt (kumuliert) | **6** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `150.171.22.14` | Bekannte legitime IP-Range (CDN/Cloud) |
| `155.133.250.4` | Bekannte legitime IP-Range (CDN/Cloud) |
| `150.171.22.17` | Bekannte legitime IP-Range (CDN/Cloud) |
| `155.133.250.20` | Bekannte legitime IP-Range (CDN/Cloud) |
| `150.171.22.11` | Bekannte legitime IP-Range (CDN/Cloud) |
| `150.171.22.12` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-05-11 16:05 UTC*