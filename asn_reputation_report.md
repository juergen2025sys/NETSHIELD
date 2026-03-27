# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-03-27 04:39 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,610,690  
**Davon in bekannten ASN-Ranges:** 760,982

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 208,968 | 68832.2 | +0 | +235 | 827 |
| 2 | AS51167 | Contabo | DE | 🔴 103 | 12,161 | 25901.8 | +0 | +1 | 567 |
| 3 | AS132203 | Tencent Cloud | CN | 🔴 101 | 23,044 | 9634.5 | +0 | +2 | 1050 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 33,466 | 3514.2 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 17,607 | 12860.4 | +0 | +0 | 1453 |
| 6 | AS22612 | Namecheap | US | 🟠 90 | 1,622 | 10586.4 | +0 | +0 | 312 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 14,304 | 830.9 | +0 | +0 | 3183 |
| 8 | AS16276 | OVH | FR | 🟠 85 | 39,368 | 8661.8 | +0 | +4 | 600 |
| 9 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,139 | 5299.5 | +0 | +9 | 1971 |
| 10 | AS16509 | Amazon AWS | US | 🟠 85 | 295,473 | 1550.5 | +0 | +18 | 14341 |
| 11 | AS12876 | Scaleway | FR | 🟠 80 | 8,347 | 14641.0 | +0 | +0 | 22 |
| 12 | AS24940 | Hetzner | DE | 🟠 78 | 23,070 | 8207.4 | +0 | +1 | 82 |
| 13 | AS47583 | Hostinger | LT | 🟠 78 | 2,846 | 3587.3 | +0 | +1 | 860 |
| 14 | AS63949 | Linode (Akamai) | US | 🟠 75 | 11,018 | 8686.0 | +0 | +0 | 341 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,244 | 3804.2 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,947 | 1559.5 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 911 | 1057.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 58 | 37,244 | 561.0 | +0 | +1 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,203 | 295.1 | +0 | +0 | 328 |

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
*Generiert: 2026-03-27 04:39 UTC*