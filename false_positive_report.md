# False Positive Checker – Report
**Aktualisiert:** 2026-04-08 20:49 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 4248335 |
| Whitelist-Treffer (dieser Run) | **13** |
| FP-Set gesamt (kumuliert) | **13** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf angewendet.
> Der `fp-` Cache-Slot dieses Workflows ist absichtlich isoliert und überschreibt den Combined-Cache nicht; dauerhafte Wirkung entsteht erst durch das nächste Combined-Update.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `3.0.0.0/8` | Bekannte legitime IP-Range (CDN/Cloud) |
| `23.227.38.64/29` | Bekannte legitime IP-Range (CDN/Cloud) |
| `52.0.0.0/10` | Bekannte legitime IP-Range (CDN/Cloud) |
| `52.64.0.0/12` | Bekannte legitime IP-Range (CDN/Cloud) |
| `54.64.0.0/11` | Bekannte legitime IP-Range (CDN/Cloud) |
| `74.208.0.0/16` | Bekannte legitime IP-Range (CDN/Cloud) |
| `82.165.0.0/16` | Bekannte legitime IP-Range (CDN/Cloud) |
| `141.8.192.0/21` | Bekannte legitime IP-Range (CDN/Cloud) |
| `166.117.0.0/16` | Bekannte legitime IP-Range (CDN/Cloud) |
| `184.104.0.0/15` | Bekannte legitime IP-Range (CDN/Cloud) |
| `192.0.0.0/11` | Bekannte legitime IP-Range (CDN/Cloud) |
| `212.227.0.0/16` | Bekannte legitime IP-Range (CDN/Cloud) |
| `217.72.192.0/20` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-04-08 20:49 UTC*