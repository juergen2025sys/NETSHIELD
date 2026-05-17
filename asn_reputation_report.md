# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-17 05:54 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,962,885  
**Davon in bekannten ASN-Ranges:** 886,189

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 116 | 25,452 | 10641.3 | +0 | +2 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 263,293 | 86726.4 | +0 | +24 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 106 | 15,037 | 32027.4 | +0 | +2 | 567 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 20,094 | 1167.3 | +0 | +0 | 3183 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 39,921 | 4192.0 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 19,446 | 14203.6 | +0 | +0 | 1453 |
| 7 | AS63949 | Linode (Akamai) | US | 🟠 90 | 17,648 | 13912.7 | +0 | +0 | 341 |
| 8 | AS22612 | Namecheap | US | 🟠 90 | 1,803 | 11767.7 | +0 | +0 | 312 |
| 9 | AS12876 | Scaleway | FR | 🟠 90 | 9,785 | 17163.3 | +0 | +5 | 22 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,982 | 5688.0 | +0 | +5 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 317,150 | 1664.3 | +0 | +7 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 78 | 26,614 | 9468.2 | +0 | +1 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 75 | 44,910 | 9881.1 | +0 | +0 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,627 | 4571.8 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,560 | 4174.8 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,266 | 1815.0 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,202 | 1395.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 45,925 | 691.7 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,474 | 361.6 | +0 | +0 | 328 |

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
*Generiert: 2026-05-17 05:54 UTC*