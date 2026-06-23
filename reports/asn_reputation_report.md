# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-23 06:15 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,006,371  
**Davon in bekannten ASN-Ranges:** 1,084,697

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 306,389 | 100921.8 | +0 | +17 | 827 |
| 2 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 47,181 | 4954.3 | +0 | +18 | 877 |
| 3 | AS132203 | Tencent Cloud | CN | 🔴 105 | 20,717 | 8661.6 | +0 | +4 | 1050 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 22,518 | 1308.1 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 17,267 | 36777.1 | +0 | +0 | 567 |
| 6 | AS20473 | Vultr | US | 🟠 98 | 22,016 | 16080.8 | +0 | +1 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 96 | 28,684 | 10204.6 | +0 | +2 | 82 |
| 8 | AS16276 | OVH | FR | 🟠 96 | 46,405 | 10210.1 | +0 | +2 | 600 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 21,573 | 17007.0 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 1,998 | 13040.4 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 10,630 | 18645.5 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 32,024 | 6750.9 | +0 | +7 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 444,175 | 2330.8 | +0 | +18 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,940 | 4966.3 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 4,069 | 4771.7 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 2,143 | 1716.4 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,321 | 1533.9 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 64 | 50,128 | 755.0 | +0 | +3 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,519 | 372.6 | +0 | +0 | 328 |

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
*Generiert: 2026-06-23 06:15 UTC*