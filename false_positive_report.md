# False Positive Checker – Report
**Aktualisiert:** 2026-04-11 20:38 UTC

---
## Ergebnis

| Metrik | Wert |
|---|---|
| Geprüfte IPs (gesamt) | 4273841 |
| Whitelist-Treffer (dieser Run) | **3** |
| FP-Set gesamt (kumuliert) | **3** |

> ℹ️ FPs werden nicht mehr direkt aus `combined_threat_blacklist_ipv4.txt` entfernt.
> `false_positives_set.json` wird beim nächsten `update_combined_blacklist`-Lauf angewendet.
> Der `fp-` Cache-Slot dieses Workflows ist absichtlich isoliert und überschreibt den Combined-Cache nicht; dauerhafte Wirkung entsteht erst durch das nächste Combined-Update.

## Whitelist-Treffer

| IP | Grund |
|---|---|
| `51.195.0.0/16` | Bekannte legitime IP-Range (CDN/Cloud) |
| `62.0.0.0/8` | Bekannte legitime IP-Range (CDN/Cloud) |
| `217.160.0.0/16` | Bekannte legitime IP-Range (CDN/Cloud) |

---
*Generiert: 2026-04-11 20:38 UTC*