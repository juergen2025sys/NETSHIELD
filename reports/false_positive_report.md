# False Positive Checker – Report
**Aktualisiert:** 2026-09-26 18:58 CEST (Europe/Berlin)

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 11752320 |
| Whitelist-Treffer (dieser Run) | **1** |
| FP-Set gesamt (kumuliert) | **4** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `state/false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `45.144.208.39` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-09-26 18:58 CEST (Europe/Berlin)*