# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-09 05:27 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,757,857  
**Davon in bekannten ASN-Ranges:** 866,736

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 113 | 24,577 | 10275.5 | +0 | +1 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 254,249 | 83747.4 | +0 | +20 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 106 | 14,790 | 31501.3 | +0 | +2 | 567 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 18,821 | 1093.3 | +0 | +0 | 3183 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 38,805 | 4074.8 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 19,387 | 14160.5 | +0 | +0 | 1453 |
| 7 | AS63949 | Linode (Akamai) | US | 🟠 90 | 15,774 | 12435.4 | +0 | +0 | 341 |
| 8 | AS22612 | Namecheap | US | 🟠 90 | 1,776 | 11591.5 | +0 | +0 | 312 |
| 9 | AS12876 | Scaleway | FR | 🟠 90 | 9,729 | 17065.1 | +0 | +13 | 22 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,910 | 5672.8 | +0 | +5 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 315,497 | 1655.6 | +0 | +16 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 26,346 | 9372.9 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 75 | 44,707 | 9836.5 | +0 | +0 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,584 | 4517.6 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,510 | 4116.2 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,252 | 1803.8 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,188 | 1379.5 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,460 | 654.6 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,374 | 337.1 | +0 | +0 | 328 |

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
*Generiert: 2026-05-09 05:27 UTC*