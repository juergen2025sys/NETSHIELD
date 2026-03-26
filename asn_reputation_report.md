# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-03-26 04:38 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,589,895  
**Davon in bekannten ASN-Ranges:** 757,138

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 207,631 | 68391.8 | +0 | +235 | 827 |
| 2 | AS51167 | Contabo | DE | 🔴 103 | 12,089 | 25748.5 | +0 | +1 | 567 |
| 3 | AS132203 | Tencent Cloud | CN | 🔴 101 | 23,020 | 9624.5 | +0 | +2 | 1050 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 32,844 | 3448.8 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 17,549 | 12818.0 | +0 | +0 | 1453 |
| 6 | AS22612 | Namecheap | US | 🟠 90 | 1,622 | 10586.4 | +0 | +0 | 312 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 14,195 | 824.6 | +0 | +0 | 3183 |
| 8 | AS16276 | OVH | FR | 🟠 85 | 39,050 | 8591.8 | +0 | +4 | 600 |
| 9 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,068 | 5284.5 | +0 | +9 | 1971 |
| 10 | AS16509 | Amazon AWS | US | 🟠 85 | 294,725 | 1546.6 | +0 | +18 | 14341 |
| 11 | AS12876 | Scaleway | FR | 🟠 80 | 8,313 | 14581.4 | +0 | +0 | 22 |
| 12 | AS24940 | Hetzner | DE | 🟠 78 | 22,969 | 8171.5 | +0 | +1 | 82 |
| 13 | AS47583 | Hostinger | LT | 🟠 78 | 2,843 | 3583.6 | +0 | +1 | 860 |
| 14 | AS63949 | Linode (Akamai) | US | 🟠 75 | 10,843 | 8548.0 | +0 | +0 | 341 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,236 | 3794.8 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,947 | 1559.5 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 910 | 1056.7 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 58 | 37,082 | 558.5 | +0 | +1 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,202 | 294.9 | +0 | +0 | 328 |

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
*Generiert: 2026-03-26 04:38 UTC*