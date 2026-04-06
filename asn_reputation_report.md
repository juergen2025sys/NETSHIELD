# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-06 04:50 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,817,851  
**Davon in bekannten ASN-Ranges:** 794,875

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 222,309 | 73226.6 | +0 | +150 | 827 |
| 2 | AS132203 | Tencent Cloud | CN | 🔴 105 | 23,396 | 9781.7 | +0 | +4 | 1050 |
| 3 | AS51167 | Contabo | DE | 🔴 103 | 12,663 | 26971.0 | +0 | +1 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 35,437 | 3721.1 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,086 | 13210.2 | +0 | +0 | 1453 |
| 6 | AS22612 | Namecheap | US | 🟠 90 | 1,645 | 10736.5 | +0 | +0 | 312 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 15,183 | 882.0 | +0 | +0 | 3183 |
| 8 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,614 | 5399.6 | +0 | +9 | 1971 |
| 9 | AS16509 | Amazon AWS | US | 🟠 85 | 302,214 | 1585.9 | +0 | +18 | 14341 |
| 10 | AS16276 | OVH | FR | 🟠 84 | 41,069 | 9036.0 | +0 | +3 | 600 |
| 11 | AS12876 | Scaleway | FR | 🟠 80 | 8,645 | 15163.7 | +0 | +0 | 22 |
| 12 | AS24940 | Hetzner | DE | 🟠 78 | 23,615 | 8401.3 | +0 | +1 | 82 |
| 13 | AS47583 | Hostinger | LT | 🟠 78 | 2,909 | 3666.8 | +0 | +1 | 860 |
| 14 | AS63949 | Linode (Akamai) | US | 🟠 75 | 12,382 | 9761.3 | +0 | +0 | 341 |
| 15 | AS8560 | IONOS | DE | 🟠 71 | 3,345 | 3922.7 | +0 | +2 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,958 | 1568.3 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 917 | 1064.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 42,273 | 636.7 | +0 | +0 | 931 |
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
*Generiert: 2026-04-06 04:50 UTC*