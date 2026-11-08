# False Positive Checker – Report
**Aktualisiert:** 2026-11-08 12:36 CET (Europe/Berlin)

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 11187895 |
| Whitelist-Treffer (dieser Run) | **1** |
| FP-Set gesamt (kumuliert) | **5** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `state/false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `20.201.200.49` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-11-08 12:36 CET (Europe/Berlin)*