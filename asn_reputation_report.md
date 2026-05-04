# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-04 05:40 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,625,669  
**Davon in bekannten ASN-Ranges:** 858,838

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 113 | 24,503 | 10244.5 | +0 | +1 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 250,267 | 82435.7 | +0 | +20 | 827 |
| 3 | AS12389 | Rostelecom | RU | 🔴 100 | 18,193 | 1056.8 | +0 | +0 | 3183 |
| 4 | AS51167 | Contabo | DE | 🔴 100 | 14,618 | 31135.0 | +0 | +0 | 567 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 38,612 | 4054.5 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 19,316 | 14108.7 | +0 | +0 | 1453 |
| 7 | AS63949 | Linode (Akamai) | US | 🟠 90 | 15,352 | 12102.7 | +0 | +0 | 341 |
| 8 | AS22612 | Namecheap | US | 🟠 90 | 1,759 | 11480.5 | +0 | +0 | 312 |
| 9 | AS12876 | Scaleway | FR | 🟠 90 | 9,567 | 16780.9 | +0 | +13 | 22 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,856 | 5661.4 | +0 | +6 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 314,183 | 1648.7 | +0 | +9 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 26,202 | 9321.6 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 75 | 44,533 | 9798.2 | +0 | +0 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,538 | 4459.6 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 3,466 | 4064.6 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,187 | 1751.7 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,183 | 1373.7 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,130 | 649.6 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,373 | 336.8 | +0 | +0 | 328 |

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
*Generiert: 2026-05-04 05:40 UTC*