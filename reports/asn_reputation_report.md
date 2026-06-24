# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-24 06:13 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,533,517  
**Davon in bekannten ASN-Ranges:** 1,140,571

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 120 | 29,086 | 12160.7 | +0 | +5 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 326,625 | 107587.4 | +0 | +16 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 49,541 | 5202.1 | +0 | +18 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 26,072 | 1514.5 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 19,379 | 41275.5 | +0 | +0 | 567 |
| 6 | AS16276 | OVH | FR | 🟠 99 | 50,022 | 11005.9 | +0 | +3 | 600 |
| 7 | AS20473 | Vultr | US | 🟠 98 | 22,544 | 16466.4 | +0 | +1 | 1453 |
| 8 | AS24940 | Hetzner | DE | 🟠 96 | 30,155 | 10728.0 | +0 | +2 | 82 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 24,596 | 19390.1 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,117 | 13817.1 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 11,544 | 20248.7 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 33,719 | 7108.2 | +0 | +6 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 449,280 | 2357.6 | +0 | +18 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,484 | 5652.0 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 4,451 | 5219.7 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 2,256 | 1807.0 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,385 | 1608.2 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 65 | 51,725 | 779.1 | +0 | +4 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,590 | 390.0 | +0 | +0 | 328 |

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
*Generiert: 2026-06-24 06:13 UTC*