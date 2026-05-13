# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-13 05:55 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,862,269  
**Davon in bekannten ASN-Ranges:** 877,015

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 113 | 24,674 | 10316.0 | +0 | +1 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 260,414 | 85778.1 | +0 | +24 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 106 | 14,915 | 31767.6 | +0 | +2 | 567 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 19,531 | 1134.6 | +0 | +0 | 3183 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 39,315 | 4128.3 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 19,399 | 14169.3 | +0 | +0 | 1453 |
| 7 | AS63949 | Linode (Akamai) | US | 🟠 90 | 17,033 | 13427.9 | +0 | +0 | 341 |
| 8 | AS22612 | Namecheap | US | 🟠 90 | 1,783 | 11637.2 | +0 | +0 | 312 |
| 9 | AS12876 | Scaleway | FR | 🟠 90 | 9,720 | 17049.3 | +0 | +9 | 22 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,910 | 5672.8 | +0 | +5 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 316,500 | 1660.9 | +0 | +16 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 26,485 | 9422.3 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 75 | 44,770 | 9850.3 | +0 | +0 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,588 | 4522.6 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 3,535 | 4145.5 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,252 | 1803.8 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,187 | 1378.3 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,537 | 655.7 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,467 | 359.9 | +0 | +0 | 328 |

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
*Generiert: 2026-05-13 05:55 UTC*