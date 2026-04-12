# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-12 04:52 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,892,629  
**Davon in bekannten ASN-Ranges:** 748,627

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 24,438 | 10217.4 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 233,060 | 76767.9 | +0 | +72 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 12,951 | 27584.4 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 36,028 | 3783.2 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,417 | 13452.0 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 93 | 13,343 | 10518.9 | +0 | +1 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,654 | 10795.2 | +0 | +0 | 312 |
| 8 | AS12389 | Rostelecom | RU | 🟠 85 | 16,005 | 929.7 | +0 | +0 | 3183 |
| 9 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,463 | 5367.8 | +0 | +7 | 1971 |
| 10 | AS16509 | Amazon AWS | US | 🟠 85 | 239,077 | 1254.6 | +0 | +16 | 14341 |
| 11 | AS12876 | Scaleway | FR | 🟠 83 | 8,942 | 15684.6 | +0 | +1 | 22 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 24,092 | 8571.0 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 81 | 41,787 | 9194.0 | +0 | +2 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 2,963 | 3734.8 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 2,945 | 3453.6 | +0 | +5 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,970 | 1577.9 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 931 | 1081.1 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,343 | 652.8 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,218 | 298.8 | +0 | +0 | 328 |

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
*Generiert: 2026-04-12 04:52 UTC*