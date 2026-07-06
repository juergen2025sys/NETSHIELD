# False Positive Checker – Report
**Aktualisiert:** 2026-07-06 21:39 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 7389744 |
| Whitelist-Treffer (dieser Run) | **4** |
| FP-Set gesamt (kumuliert) | **4** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `state/false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `185.56.65.171` | Bekannte legitime IP-Range (CDN/Cloud) |
| `104.18.86.42` | Bekannte legitime IP-Range (CDN/Cloud) |
| `185.56.65.169` | Bekannte legitime IP-Range (CDN/Cloud) |
| `185.56.65.170` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-07-06 21:39 UTC*