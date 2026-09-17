# False Positive Checker – Report
**Aktualisiert:** 2026-09-17 11:44 CEST (Europe/Berlin)

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 11375018 |
| Whitelist-Treffer (dieser Run) | **2** |
| FP-Set gesamt (kumuliert) | **2** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `state/false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `212.227.17.190` | Bekannte legitime IP-Range (CDN/Cloud) |
| `213.165.67.108` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-09-17 11:44 CEST (Europe/Berlin)*