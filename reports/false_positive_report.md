# False Positive Checker – Report
**Aktualisiert:** 2026-07-10 21:07 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 7556094 |
| Whitelist-Treffer (dieser Run) | **7** |
| FP-Set gesamt (kumuliert) | **7** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `state/false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf über `is_in_fp_set()` angewendet.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `44.233.10.151` | Bekannte legitime IP-Range (CDN/Cloud) |
| `54.191.80.30` | Bekannte legitime IP-Range (CDN/Cloud) |
| `18.246.111.155` | Bekannte legitime IP-Range (CDN/Cloud) |
| `151.101.129.229` | Bekannte legitime IP-Range (CDN/Cloud) |
| `184.33.252.198` | Bekannte legitime IP-Range (CDN/Cloud) |
| `35.82.239.165` | Bekannte legitime IP-Range (CDN/Cloud) |
| `100.20.95.107` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-07-10 21:07 UTC*