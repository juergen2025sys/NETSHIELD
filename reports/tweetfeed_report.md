# TweetFeed Monitor – Report
**Aktualisiert:** 2026-07-10 06:27 UTC  
**Quelle:** [tweetfeed.live](https://tweetfeed.live) – IOCs aus Twitter/X-Security-Community  
**Endpoint:** `/v1/year/ip` (letzte 365 Tage, Typ=IP)

---
## Pipeline

| Schritt | Anzahl |
|---|---:|
| Response-Format | **csv:109907-rows** |
| Eindeutige IPs (roh) | **10,664** |
| Private/Reserved entfernt | **11** |
| FP-Filter entfernt | **0** |
| Whitelist-Filter entfernt | **7** |

---
| Metrik | Wert |
|---|---|
| Gesamt TweetFeed-IPs | **10,646** |
| Neu | **+21** |
| Entfernt | **-109** |

---
> ⚠️ **Confidence-Hinweis (Quelle):** IOCs stammen aus Twitter/X-Posts und sind
> nicht 100% verifiziert. TweetFeed empfiehlt explizit **keine direkte Blacklist-Nutzung**,
> sondern Einsatz als Watchlist/Threat-Hunting-Quelle. Daher wird `tweetfeed_ips.txt` im
> combined-Workflow als **non-HQ** Feed eingelesen – Promotion in active/conf40 nur wenn
> andere Quellen die IP zusätzlich bestätigen (Confidence-Scoring).

> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-07-10 06:27 UTC*