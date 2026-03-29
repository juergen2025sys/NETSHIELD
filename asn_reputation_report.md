# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-03-29 04:42 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,649,103  
**Davon in bekannten ASN-Ranges:** 767,048

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 211,354 | 69618.1 | +0 | +223 | 827 |
| 2 | AS132203 | Tencent Cloud | CN | 🔴 104 | 23,101 | 9658.4 | +0 | +3 | 1050 |
| 3 | AS51167 | Contabo | DE | 🔴 103 | 12,275 | 26144.6 | +0 | +1 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 33,657 | 3534.2 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 17,719 | 12942.2 | +0 | +0 | 1453 |
| 6 | AS22612 | Namecheap | US | 🟠 90 | 1,626 | 10612.5 | +0 | +0 | 312 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 14,430 | 838.2 | +0 | +0 | 3183 |
| 8 | AS16276 | OVH | FR | 🟠 85 | 39,694 | 8733.5 | +0 | +4 | 600 |
| 9 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,246 | 5322.0 | +0 | +9 | 1971 |
| 10 | AS16509 | Amazon AWS | US | 🟠 85 | 296,878 | 1557.9 | +0 | +18 | 14341 |
| 11 | AS12876 | Scaleway | FR | 🟠 80 | 8,427 | 14781.3 | +0 | +0 | 22 |
| 12 | AS24940 | Hetzner | DE | 🟠 78 | 23,185 | 8248.3 | +0 | +1 | 82 |
| 13 | AS47583 | Hostinger | LT | 🟠 78 | 2,854 | 3597.4 | +0 | +1 | 860 |
| 14 | AS63949 | Linode (Akamai) | US | 🟠 75 | 11,253 | 8871.2 | +0 | +0 | 341 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,260 | 3823.0 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,950 | 1561.9 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 916 | 1063.7 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 38,017 | 572.6 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,206 | 295.8 | +0 | +0 | 328 |

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
*Generiert: 2026-03-29 04:42 UTC*