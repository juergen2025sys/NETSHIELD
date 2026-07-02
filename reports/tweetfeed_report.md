# TweetFeed Monitor – Report
**Aktualisiert:** 2026-07-02 06:24 UTC  
**Quelle:** [tweetfeed.live](https://tweetfeed.live) – IOCs aus Twitter/X-Security-Community  
**Endpoint:** `/v1/year/ip` (letzte 365 Tage, Typ=IP)

---
## Pipeline

| Schritt | Anzahl |
|---|---:|
| Response-Format | **csv:110030-rows** |
| Eindeutige IPs (roh) | **11,174** |
| Private/Reserved entfernt | **13** |
| FP-Filter entfernt | **0** |
| Whitelist-Filter entfernt | **8** |

---
| Metrik | Wert |
|---|---|
| Gesamt TweetFeed-IPs | **11,153** |
| Neu | **+10** |
| Entfernt | **-65** |

---
> ⚠️ **Confidence-Hinweis (Quelle):** IOCs stammen aus Twitter/X-Posts und sind
> nicht 100% verifiziert. TweetFeed empfiehlt explizit **keine direkte Blacklist-Nutzung**,
> sondern Einsatz als Watchlist/Threat-Hunting-Quelle. Daher wird `tweetfeed_ips.txt` im
> combined-Workflow als **non-HQ** Feed eingelesen – Promotion in active/conf40 nur wenn
> andere Quellen die IP zusätzlich bestätigen (Confidence-Scoring).

> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-07-02 06:24 UTC*