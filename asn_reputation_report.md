# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-08 04:43 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,878,760  
**Davon in bekannten ASN-Ranges:** 804,234

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 116 | 24,250 | 10138.8 | +0 | +2 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 225,871 | 74399.9 | +0 | +105 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 103 | 12,784 | 27228.7 | +0 | +1 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 35,614 | 3739.7 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,183 | 13281.1 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 93 | 12,763 | 10061.6 | +0 | +1 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,651 | 10775.6 | +0 | +0 | 312 |
| 8 | AS12389 | Rostelecom | RU | 🟠 85 | 15,638 | 908.4 | +0 | +0 | 3183 |
| 9 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,750 | 5428.3 | +0 | +7 | 1971 |
| 10 | AS16509 | Amazon AWS | US | 🟠 85 | 304,654 | 1598.7 | +0 | +17 | 14341 |
| 11 | AS24940 | Hetzner | DE | 🟠 81 | 23,794 | 8465.0 | +0 | +2 | 82 |
| 12 | AS16276 | OVH | FR | 🟠 81 | 41,352 | 9098.3 | +0 | +2 | 600 |
| 13 | AS12876 | Scaleway | FR | 🟠 80 | 8,717 | 15290.0 | +0 | +0 | 22 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 2,927 | 3689.4 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,374 | 3956.7 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,958 | 1568.3 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 917 | 1064.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 42,822 | 645.0 | +0 | +0 | 931 |
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
*Generiert: 2026-04-08 04:43 UTC*