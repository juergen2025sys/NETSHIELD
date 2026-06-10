# TweetFeed Monitor – Report
**Aktualisiert:** 2026-06-10 06:50 UTC  
**Quelle:** [tweetfeed.live](https://tweetfeed.live) – IOCs aus Twitter/X-Security-Community  
**Endpoint:** `/v1/year/ip` (letzte 365 Tage, Typ=IP)

---
## Pipeline

| Schritt | Anzahl |
|---|---:|
| Response-Format | **csv:117272-rows** |
| Eindeutige IPs (roh) | **12,269** |
| Private/Reserved entfernt | **17** |
| FP-Filter entfernt | **0** |
| Whitelist-Filter entfernt | **8** |

---
| Metrik | Wert |
|---|---|
| Gesamt TweetFeed-IPs | **12,244** |
| Neu | **+14** |
| Entfernt | **-58** |

---
> ⚠️ **Confidence-Hinweis (Quelle):** IOCs stammen aus Twitter/X-Posts und sind
> nicht 100% verifiziert. TweetFeed empfiehlt explizit **keine direkte Blacklist-Nutzung**,
> sondern Einsatz als Watchlist/Threat-Hunting-Quelle. Daher wird `tweetfeed_ips.txt` im
> combined-Workflow als **non-HQ** Feed eingelesen – Promotion in active/conf40 nur wenn
> andere Quellen die IP zusätzlich bestätigen (Confidence-Scoring).

> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-06-10 06:50 UTC*