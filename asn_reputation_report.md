# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-06 05:35 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,677,235  
**Davon in bekannten ASN-Ranges:** 862,419

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 113 | 24,509 | 10247.1 | +0 | +1 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 252,374 | 83129.8 | +0 | +21 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 106 | 14,675 | 31256.4 | +0 | +2 | 567 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 18,479 | 1073.5 | +0 | +0 | 3183 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 38,686 | 4062.3 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 19,344 | 14129.1 | +0 | +0 | 1453 |
| 7 | AS63949 | Linode (Akamai) | US | 🟠 90 | 15,516 | 12232.0 | +0 | +0 | 341 |
| 8 | AS22612 | Namecheap | US | 🟠 90 | 1,768 | 11539.3 | +0 | +0 | 312 |
| 9 | AS12876 | Scaleway | FR | 🟠 90 | 9,576 | 16796.7 | +0 | +13 | 22 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,882 | 5666.9 | +0 | +6 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 314,645 | 1651.1 | +0 | +12 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 84 | 26,262 | 9343.0 | +0 | +3 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 75 | 44,597 | 9812.3 | +0 | +0 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,571 | 4501.2 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,487 | 4089.2 | +0 | +5 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,228 | 1784.5 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,188 | 1379.5 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,258 | 651.5 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,374 | 337.1 | +0 | +0 | 328 |

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
*Generiert: 2026-05-06 05:35 UTC*