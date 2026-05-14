# False Positive Checker – Report
**Aktualisiert:** 2026-05-14 07:37 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 5193704 |
| Whitelist-Treffer (dieser Run) | **2** |
| FP-Set gesamt (kumuliert) | **2** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `54.93.92.48` | Bekannte legitime IP-Range (CDN/Cloud) |
| `54.93.92.121` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-05-14 07:37 UTC*