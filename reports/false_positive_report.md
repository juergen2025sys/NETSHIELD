# False Positive Checker – Report
**Aktualisiert:** 2026-07-09 16:13 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 7516027 |
| Whitelist-Treffer (dieser Run) | **3** |
| FP-Set gesamt (kumuliert) | **3** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `state/false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `172.66.43.99` | Bekannte legitime IP-Range (CDN/Cloud) |
| `188.114.97.4` | Bekannte legitime IP-Range (CDN/Cloud) |
| `172.66.40.157` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-07-09 16:13 UTC*