# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-17 07:21 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,396,832  
**Davon in bekannten ASN-Ranges:** 1,130,712

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 28,926 | 12093.8 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 326,027 | 107390.4 | +0 | +17 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 48,801 | 5124.4 | +0 | +13 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 25,508 | 1481.8 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 19,081 | 40640.8 | +0 | +0 | 567 |
| 6 | AS20473 | Vultr | US | 🟠 98 | 22,284 | 16276.5 | +0 | +1 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 96 | 29,847 | 10618.4 | +0 | +2 | 82 |
| 8 | AS16276 | OVH | FR | 🟠 93 | 50,024 | 11006.3 | +0 | +1 | 600 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 24,066 | 18972.3 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,156 | 14071.6 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 11,191 | 19629.5 | +0 | +0 | 22 |
| 12 | AS16509 | Amazon AWS | US | 🟠 85 | 443,580 | 2327.7 | +0 | +20 | 14341 |
| 13 | AS31898 | Oracle Cloud | US | 🟠 81 | 33,220 | 7003.0 | +0 | +2 | 1971 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,748 | 5984.8 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,343 | 5093.0 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 68 | 2,483 | 1988.8 | +0 | +1 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,431 | 1661.7 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 61 | 51,411 | 774.3 | +0 | +2 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,585 | 388.8 | +0 | +0 | 328 |

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
*Generiert: 2026-06-17 07:21 UTC*