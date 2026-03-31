# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-03-31 04:41 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,690,352  
**Davon in bekannten ASN-Ranges:** 776,806

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 214,729 | 70729.8 | +0 | +186 | 827 |
| 2 | AS132203 | Tencent Cloud | CN | 🔴 104 | 23,191 | 9696.0 | +0 | +3 | 1050 |
| 3 | AS51167 | Contabo | DE | 🔴 103 | 12,369 | 26344.8 | +0 | +1 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 34,033 | 3573.7 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 17,770 | 12979.4 | +0 | +0 | 1453 |
| 6 | AS22612 | Namecheap | US | 🟠 90 | 1,630 | 10638.6 | +0 | +0 | 312 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 14,586 | 847.3 | +0 | +0 | 3183 |
| 8 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,344 | 5342.7 | +0 | +7 | 1971 |
| 9 | AS16509 | Amazon AWS | US | 🟠 85 | 298,094 | 1564.3 | +0 | +27 | 14341 |
| 10 | AS16276 | OVH | FR | 🟠 84 | 39,945 | 8788.7 | +0 | +3 | 600 |
| 11 | AS12876 | Scaleway | FR | 🟠 80 | 8,466 | 14849.7 | +0 | +0 | 22 |
| 12 | AS24940 | Hetzner | DE | 🟠 78 | 23,300 | 8289.2 | +0 | +1 | 82 |
| 13 | AS47583 | Hostinger | LT | 🟠 78 | 2,868 | 3615.1 | +0 | +1 | 860 |
| 14 | AS63949 | Linode (Akamai) | US | 🟠 75 | 11,627 | 9166.1 | +0 | +0 | 341 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 3,284 | 3851.1 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,954 | 1565.1 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 916 | 1063.7 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 41,492 | 624.9 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,208 | 296.3 | +0 | +0 | 328 |

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
*Generiert: 2026-03-31 04:41 UTC*