# False Positive Checker – Report
**Aktualisiert:** 2026-08-20 22:31 CEST (Europe/Berlin)

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 9321518 |
| Whitelist-Treffer (dieser Run) | **2** |
| FP-Set gesamt (kumuliert) | **2** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `state/false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `104.21.4.98` | Bekannte legitime IP-Range (CDN/Cloud) |
| `172.67.153.249` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-08-20 22:31 CEST (Europe/Berlin)*