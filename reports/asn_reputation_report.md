# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-22 07:33 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,513,717  
**Davon in bekannten ASN-Ranges:** 1,143,757

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 29,060 | 12149.8 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 331,093 | 109059.1 | +0 | +16 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 49,375 | 5184.7 | +0 | +16 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 26,098 | 1516.0 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 19,328 | 41166.8 | +0 | +0 | 567 |
| 6 | AS20473 | Vultr | US | 🟠 98 | 22,583 | 16494.9 | +0 | +1 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 96 | 30,164 | 10731.2 | +0 | +2 | 82 |
| 8 | AS16276 | OVH | FR | 🟠 93 | 50,411 | 11091.5 | +0 | +1 | 600 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 24,555 | 19357.8 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,165 | 14130.4 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 11,387 | 19973.3 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 33,661 | 7096.0 | +0 | +4 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 447,301 | 2347.2 | +0 | +20 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,775 | 6018.8 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,437 | 5203.2 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 2,500 | 2002.4 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,433 | 1664.0 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 61 | 51,842 | 780.8 | +0 | +2 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,589 | 389.8 | +0 | +0 | 328 |

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
*Generiert: 2026-06-22 07:33 UTC*