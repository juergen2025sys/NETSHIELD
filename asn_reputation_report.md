# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-18 04:38 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,262,974  
**Davon in bekannten ASN-Ranges:** 826,712

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 24,587 | 10279.7 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 239,182 | 78784.4 | +0 | +12 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 13,134 | 27974.2 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 36,358 | 3817.8 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,568 | 13562.3 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 90 | 13,200 | 10406.2 | +0 | +0 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,652 | 10782.2 | +0 | +0 | 312 |
| 8 | AS12876 | Scaleway | FR | 🟠 90 | 9,201 | 16138.9 | +0 | +8 | 22 |
| 9 | AS12389 | Rostelecom | RU | 🟠 85 | 16,339 | 949.1 | +0 | +0 | 3183 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,211 | 5525.5 | +0 | +6 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 308,317 | 1617.9 | +0 | +19 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 24,440 | 8694.8 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 81 | 41,452 | 9120.3 | +0 | +2 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 2,988 | 3766.3 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,299 | 3868.7 | +0 | +6 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,971 | 1578.7 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 932 | 1082.2 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,675 | 657.8 | +0 | +0 | 931 |
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
*Generiert: 2026-04-18 04:38 UTC*