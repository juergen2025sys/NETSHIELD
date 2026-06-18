# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-18 07:00 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,420,736  
**Davon in bekannten ASN-Ranges:** 1,134,396

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 28,960 | 12108.0 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 327,773 | 107965.5 | +0 | +16 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 48,905 | 5135.4 | +0 | +15 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 25,662 | 1490.7 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 19,117 | 40717.4 | +0 | +0 | 567 |
| 6 | AS20473 | Vultr | US | 🟠 98 | 22,331 | 16310.9 | +0 | +1 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 96 | 29,886 | 10632.3 | +0 | +2 | 82 |
| 8 | AS16276 | OVH | FR | 🟠 93 | 50,093 | 11021.5 | +0 | +1 | 600 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 24,186 | 19066.9 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,163 | 14117.3 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 11,250 | 19733.0 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 33,380 | 7036.7 | +0 | +4 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 444,549 | 2332.8 | +0 | +20 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,748 | 5984.8 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,351 | 5102.4 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 68 | 2,485 | 1990.4 | +0 | +1 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,432 | 1662.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 61 | 51,540 | 776.3 | +0 | +2 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,585 | 388.8 | +0 | +0 | 328 |

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
*Generiert: 2026-06-18 07:00 UTC*