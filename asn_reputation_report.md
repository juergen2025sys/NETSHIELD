# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-01 04:52 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,697,532  
**Davon in bekannten ASN-Ranges:** 777,893

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 215,376 | 70942.9 | +0 | +186 | 827 |
| 2 | AS132203 | Tencent Cloud | CN | 🔴 105 | 23,196 | 9698.1 | +0 | +4 | 1050 |
| 3 | AS51167 | Contabo | DE | 🔴 103 | 12,387 | 26383.2 | +0 | +1 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 34,096 | 3580.3 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 17,774 | 12982.4 | +0 | +0 | 1453 |
| 6 | AS22612 | Namecheap | US | 🟠 90 | 1,631 | 10645.1 | +0 | +0 | 312 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 14,625 | 849.6 | +0 | +0 | 3183 |
| 8 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,360 | 5346.1 | +0 | +7 | 1971 |
| 9 | AS16509 | Amazon AWS | US | 🟠 85 | 298,173 | 1564.7 | +0 | +27 | 14341 |
| 10 | AS16276 | OVH | FR | 🟠 84 | 40,001 | 8801.0 | +0 | +3 | 600 |
| 11 | AS12876 | Scaleway | FR | 🟠 80 | 8,476 | 14867.2 | +0 | +0 | 22 |
| 12 | AS24940 | Hetzner | DE | 🟠 78 | 23,311 | 8293.1 | +0 | +1 | 82 |
| 13 | AS47583 | Hostinger | LT | 🟠 78 | 2,871 | 3618.9 | +0 | +1 | 860 |
| 14 | AS63949 | Linode (Akamai) | US | 🟠 75 | 11,687 | 9213.4 | +0 | +0 | 341 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 3,287 | 3854.7 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,955 | 1565.9 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 917 | 1064.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 41,562 | 626.0 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,208 | 296.3 | +0 | +0 | 328 |

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
*Generiert: 2026-04-01 04:52 UTC*