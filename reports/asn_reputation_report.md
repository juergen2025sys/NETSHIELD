# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-19 07:20 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,435,715  
**Davon in bekannten ASN-Ranges:** 1,136,038

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 28,981 | 12116.8 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 328,535 | 108216.5 | +0 | +16 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 49,076 | 5153.3 | +0 | +16 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 25,729 | 1494.6 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 19,150 | 40787.7 | +0 | +0 | 567 |
| 6 | AS20473 | Vultr | US | 🟠 98 | 22,347 | 16322.5 | +0 | +1 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 96 | 29,919 | 10644.0 | +0 | +2 | 82 |
| 8 | AS16276 | OVH | FR | 🟠 93 | 50,124 | 11028.3 | +0 | +1 | 600 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 24,260 | 19125.2 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,164 | 14123.9 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 11,263 | 19755.8 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 33,431 | 7047.5 | +0 | +4 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 444,810 | 2334.2 | +0 | +20 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,749 | 5986.1 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,382 | 5138.8 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 2,486 | 1991.2 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,433 | 1664.0 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 61 | 51,611 | 777.4 | +0 | +2 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,588 | 389.6 | +0 | +0 | 328 |

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
*Generiert: 2026-06-19 07:20 UTC*