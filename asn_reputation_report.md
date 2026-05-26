# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-26 06:14 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 5,657,036  
**Davon in bekannten ASN-Ranges:** 997,335

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 27,482 | 11490.0 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 299,072 | 98511.7 | +0 | +25 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 106 | 17,661 | 37616.3 | +0 | +2 | 567 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 22,978 | 1334.8 | +0 | +0 | 3183 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 41,501 | 4357.9 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 21,317 | 15570.2 | +0 | +0 | 1453 |
| 7 | AS12876 | Scaleway | FR | 🟠 95 | 10,872 | 19069.9 | +0 | +5 | 22 |
| 8 | AS24940 | Hetzner | DE | 🟠 93 | 28,318 | 10074.4 | +0 | +1 | 82 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 21,084 | 16621.5 | +0 | +0 | 341 |
| 10 | AS16276 | OVH | FR | 🟠 90 | 48,232 | 10612.0 | +0 | +0 | 600 |
| 11 | AS22612 | Namecheap | US | 🟠 90 | 2,069 | 13503.8 | +0 | +0 | 312 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 30,761 | 6484.6 | +0 | +6 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 365,050 | 1915.6 | +0 | +17 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,183 | 5272.6 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,084 | 4789.3 | +0 | +5 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,414 | 1933.5 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,387 | 1610.6 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 47,307 | 712.5 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,563 | 383.4 | +0 | +0 | 328 |

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
*Generiert: 2026-05-26 06:14 UTC*