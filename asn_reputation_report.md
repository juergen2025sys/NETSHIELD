# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-29 05:32 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,417,287  
**Davon in bekannten ASN-Ranges:** 841,013

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 116 | 24,348 | 10179.8 | +0 | +2 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 243,867 | 80327.6 | +0 | +20 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 13,275 | 28274.5 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 38,239 | 4015.3 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,715 | 13669.7 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 90 | 14,131 | 11140.1 | +0 | +0 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,676 | 10938.8 | +0 | +0 | 312 |
| 8 | AS12876 | Scaleway | FR | 🟠 90 | 9,413 | 16510.8 | +0 | +13 | 22 |
| 9 | AS12389 | Rostelecom | RU | 🟠 85 | 16,977 | 986.2 | +0 | +0 | 3183 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,600 | 5607.5 | +0 | +6 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 312,383 | 1639.3 | +0 | +19 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 24,863 | 8845.3 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 78 | 42,971 | 9454.5 | +0 | +1 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,463 | 4365.1 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,360 | 3940.3 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,998 | 1600.3 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 923 | 1071.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 42,588 | 641.5 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,223 | 300.0 | +0 | +0 | 328 |

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
*Generiert: 2026-04-29 05:32 UTC*