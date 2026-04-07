# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-07 04:39 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,841,370  
**Davon in bekannten ASN-Ranges:** 799,245

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 223,714 | 73689.4 | +0 | +106 | 827 |
| 2 | AS51167 | Contabo | DE | 🔴 103 | 12,723 | 27098.8 | +0 | +1 | 567 |
| 3 | AS132203 | Tencent Cloud | CN | 🔴 101 | 23,441 | 9800.5 | +0 | +2 | 1050 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 35,524 | 3730.3 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,140 | 13249.7 | +0 | +0 | 1453 |
| 6 | AS22612 | Namecheap | US | 🟠 90 | 1,649 | 10762.6 | +0 | +0 | 312 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 15,386 | 893.8 | +0 | +0 | 3183 |
| 8 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,689 | 5415.4 | +0 | +7 | 1971 |
| 9 | AS16509 | Amazon AWS | US | 🟠 85 | 303,860 | 1594.5 | +0 | +17 | 14341 |
| 10 | AS24940 | Hetzner | DE | 🟠 81 | 23,687 | 8426.9 | +0 | +2 | 82 |
| 11 | AS16276 | OVH | FR | 🟠 81 | 41,223 | 9069.9 | +0 | +2 | 600 |
| 12 | AS12876 | Scaleway | FR | 🟠 80 | 8,683 | 15230.3 | +0 | +0 | 22 |
| 13 | AS63949 | Linode (Akamai) | US | 🟠 75 | 12,530 | 9878.0 | +0 | +0 | 341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 2,918 | 3678.1 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 3,363 | 3943.8 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,958 | 1568.3 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 917 | 1064.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 42,625 | 642.0 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,215 | 298.1 | +0 | +0 | 328 |

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
*Generiert: 2026-04-07 04:39 UTC*