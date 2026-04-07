# False Positive Checker – Report
**Aktualisiert:** 2026-04-07 19:27 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 4220304 |
| Whitelist-Treffer (dieser Run) | **79** |
| FP-Set gesamt (kumuliert) | **79** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf angewendet.
> Der `fp-` Cache-Slot dieses Workflows ist absichtlich isoliert und überschreibt den Combined-Cache nicht; dauerhafte Wirkung entsteht erst durch das nächste Combined-Update.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `3.0.0.0/8` | Bekannte legitime IP-Range (CDN/Cloud) |
| `3.120.0.132` | Bekannte legitime IP-Range (CDN/Cloud) |
| `3.121.0.15` | Bekannte legitime IP-Range (CDN/Cloud) |
| `3.121.0.226` | Bekannte legitime IP-Range (CDN/Cloud) |
| `13.107.136.10` | Bekannte legitime IP-Range (CDN/Cloud) |
| `13.107.137.11` | Bekannte legitime IP-Range (CDN/Cloud) |
| `13.107.138.10` | Bekannte legitime IP-Range (CDN/Cloud) |
| `13.248.213.45/32` | Bekannte legitime IP-Range (CDN/Cloud) |
| `18.194.0.144` | Bekannte legitime IP-Range (CDN/Cloud) |
| `20.42.65.90` | Bekannte legitime IP-Range (CDN/Cloud) |
| `20.42.65.92` | Bekannte legitime IP-Range (CDN/Cloud) |
| `20.71.22.186` | Bekannte legitime IP-Range (CDN/Cloud) |
| `23.11.41.157` | Bekannte legitime IP-Range (CDN/Cloud) |
| `23.227.38.64/29` | Bekannte legitime IP-Range (CDN/Cloud) |
| `34.128.128.0` | Bekannte legitime IP-Range (CDN/Cloud) |
| `40.115.97.48` | Bekannte legitime IP-Range (CDN/Cloud) |
| `40.115.97.239` | Bekannte legitime IP-Range (CDN/Cloud) |
| `52.0.0.0/10` | Bekannte legitime IP-Range (CDN/Cloud) |
| `52.57.0.134` | Bekannte legitime IP-Range (CDN/Cloud) |
| `52.64.0.0/12` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-04-07 19:27 UTC*