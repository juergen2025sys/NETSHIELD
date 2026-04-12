# False Positive Checker – Report
**Aktualisiert:** 2026-04-12 08:35 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 4384740 |
| Whitelist-Treffer (dieser Run) | **24** |
| FP-Set gesamt (kumuliert) | **24** |

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
| `66.22.231.178` | Bekannte legitime IP-Range (CDN/Cloud) |
| `66.22.244.33` | Bekannte legitime IP-Range (CDN/Cloud) |
| `66.22.244.44` | Bekannte legitime IP-Range (CDN/Cloud) |
| `66.22.244.136` | Bekannte legitime IP-Range (CDN/Cloud) |
| `66.22.244.143` | Bekannte legitime IP-Range (CDN/Cloud) |
| `66.22.244.144` | Bekannte legitime IP-Range (CDN/Cloud) |
| `66.22.244.154` | Bekannte legitime IP-Range (CDN/Cloud) |
| `66.22.244.156` | Bekannte legitime IP-Range (CDN/Cloud) |
| `74.208.0.0/16` | Bekannte legitime IP-Range (CDN/Cloud) |
| `82.165.0.0/16` | Bekannte legitime IP-Range (CDN/Cloud) |
| `160.1.0.0/16` | Bekannte legitime IP-Range (CDN/Cloud) |
| `166.117.0.0/16` | Bekannte legitime IP-Range (CDN/Cloud) |
| `184.104.0.0/15` | Bekannte legitime IP-Range (CDN/Cloud) |
| `192.0.0.0/11` | Bekannte legitime IP-Range (CDN/Cloud) |
| `194.242.2.0/23` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-04-12 08:35 UTC*