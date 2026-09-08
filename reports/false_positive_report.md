# False Positive Checker – Report
**Aktualisiert:** 2026-09-08 19:10 CEST (Europe/Berlin)

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 10762899 |
| Whitelist-Treffer (dieser Run) | **4** |
| FP-Set gesamt (kumuliert) | **4** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `state/false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `76.76.21.98` | Bekannte legitime IP-Range (CDN/Cloud) |
| `66.33.60.130` | Bekannte legitime IP-Range (CDN/Cloud) |
| `76.76.21.61` | Bekannte legitime IP-Range (CDN/Cloud) |
| `66.33.60.67` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-09-08 19:10 CEST (Europe/Berlin)*