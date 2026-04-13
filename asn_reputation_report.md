# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-13 05:20 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,913,601  
**Davon in bekannten ASN-Ranges:** 744,749

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 24,476 | 10233.3 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 234,019 | 77083.8 | +0 | +72 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 11,975 | 25505.6 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 36,093 | 3790.0 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,506 | 13517.0 | +0 | +0 | 1453 |
| 6 | AS22612 | Namecheap | US | 🟠 90 | 1,643 | 10723.4 | +0 | +0 | 312 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 16,043 | 932.0 | +0 | +0 | 3183 |
| 8 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,511 | 5377.9 | +0 | +7 | 1971 |
| 9 | AS16509 | Amazon AWS | US | 🟠 85 | 239,950 | 1259.2 | +0 | +16 | 14341 |
| 10 | AS12876 | Scaleway | FR | 🟠 83 | 7,387 | 12957.1 | +0 | +1 | 22 |
| 11 | AS24940 | Hetzner | DE | 🟠 81 | 23,557 | 8380.6 | +0 | +2 | 82 |
| 12 | AS16276 | OVH | FR | 🟠 81 | 40,134 | 8830.3 | +0 | +2 | 600 |
| 13 | AS63949 | Linode (Akamai) | US | 🟠 78 | 12,617 | 9946.5 | +0 | +1 | 341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 2,801 | 3530.6 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 2,832 | 3321.1 | +0 | +5 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,968 | 1576.3 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 930 | 1079.9 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,103 | 649.2 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,204 | 295.4 | +0 | +0 | 328 |

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
*Generiert: 2026-04-13 05:20 UTC*