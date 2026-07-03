# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-07-03 06:00 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 7,039,007  
**Davon in bekannten ASN-Ranges:** 1,194,280

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 120 | 29,679 | 12408.6 | +0 | +4 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 334,439 | 110161.3 | +0 | +13 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 51,597 | 5418.0 | +0 | +17 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 28,718 | 1668.2 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 20,574 | 43820.7 | +0 | +0 | 567 |
| 6 | AS24940 | Hetzner | DE | 🟠 99 | 31,840 | 11327.4 | +0 | +3 | 82 |
| 7 | AS16276 | OVH | FR | 🟠 99 | 55,470 | 12204.6 | +0 | +3 | 600 |
| 8 | AS20473 | Vultr | US | 🟠 98 | 24,045 | 17562.8 | +0 | +1 | 1453 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 26,729 | 21071.7 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,222 | 14502.4 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 14,999 | 26308.9 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 34,404 | 7252.6 | +0 | +6 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 469,959 | 2466.2 | +0 | +18 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,630 | 5836.1 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 4,873 | 5714.6 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 2,666 | 2135.3 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,569 | 1821.9 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 64 | 53,747 | 809.5 | +0 | +3 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 2,120 | 520.0 | +0 | +0 | 328 |

---

### Score-Formel (normalisiert auf ASN-Größe)
```
score = A (Abuse-Dichte) + B (Absolute Präsenz) + C (Feed-Bonus) + D (Basis-Reputation)
A: BL-Hits pro 1M IPs im ASN  → max 60
B: Absolute BL-Treffer-Stufe   → max 20
C: Spamhaus DROP + ET-Bonus    → max 10
D: Basis-Reputation (RU/CN++)  → max 40
```
- **Abuse-Dichte**: verhindert dass große Netze (AWS) kleine (Contabo) verdrängen
- **Absolute Präsenz**: große Netze mit viel Abuse bleiben trotzdem trackbar
- **Feed-Bonus**: IPs auch in Spamhaus DROP oder Emerging Threats

---
*Datenquelle: [ScaniteX ASN Database](https://scanitex.com/en/resources/asn-database) (BGP via RIPE Stat, kein API-Key)*  
*Generiert: 2026-07-03 06:00 UTC*