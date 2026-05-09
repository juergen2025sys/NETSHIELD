# False Positive Checker – Report
**Aktualisiert:** 2026-05-09 07:02 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 5068205 |
| Whitelist-Treffer (dieser Run) | **2** |
| FP-Set gesamt (kumuliert) | **2** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `66.33.60.66` | Bekannte legitime IP-Range (CDN/Cloud) |
| `66.33.60.194` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-05-09 07:02 UTC*