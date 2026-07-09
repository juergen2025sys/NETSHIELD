# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-07-09 06:12 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 7,475,379  
**Davon in bekannten ASN-Ranges:** 1,252,049

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 120 | 30,763 | 12861.8 | +0 | +5 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 337,673 | 111226.5 | +0 | +17 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 56,518 | 5934.8 | +0 | +17 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 30,009 | 1743.2 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 21,314 | 45396.8 | +0 | +0 | 567 |
| 6 | AS24940 | Hetzner | DE | 🟠 99 | 33,946 | 12076.6 | +0 | +3 | 82 |
| 7 | AS16276 | OVH | FR | 🟠 99 | 57,847 | 12727.5 | +0 | +3 | 600 |
| 8 | AS20473 | Vultr | US | 🟠 98 | 26,294 | 19205.5 | +0 | +1 | 1453 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 26,619 | 20985.0 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,376 | 15507.5 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 15,694 | 27527.9 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 36,154 | 7621.5 | +0 | +6 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 503,265 | 2640.9 | +0 | +18 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,729 | 5960.8 | +0 | +0 | 860 |
| 15 | AS26496 | GoDaddy | US | 🟠 71 | 3,046 | 2439.7 | +0 | +2 | 184 |
| 16 | AS8560 | IONOS | DE | 🟠 71 | 5,127 | 6012.4 | +0 | +2 | 462 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,693 | 1965.9 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 64 | 56,858 | 856.4 | +0 | +3 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 2,124 | 521.0 | +0 | +0 | 328 |

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
*Generiert: 2026-07-09 06:12 UTC*