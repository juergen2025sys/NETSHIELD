# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-10 06:38 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,184,853  
**Davon in bekannten ASN-Ranges:** 1,104,212

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 28,515 | 11921.9 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 317,623 | 104622.2 | +0 | +12 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 104 | 46,475 | 4880.2 | +0 | +3 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 24,520 | 1424.4 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 18,821 | 40087.0 | +0 | +0 | 567 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 21,894 | 15991.7 | +0 | +0 | 1453 |
| 7 | AS12876 | Scaleway | FR | 🟠 91 | 11,254 | 19740.0 | +0 | +2 | 22 |
| 8 | AS24940 | Hetzner | DE | 🟠 90 | 29,433 | 10471.1 | +0 | +0 | 82 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 23,362 | 18417.3 | +0 | +0 | 341 |
| 10 | AS16276 | OVH | FR | 🟠 90 | 49,542 | 10900.3 | +0 | +0 | 600 |
| 11 | AS22612 | Namecheap | US | 🟠 90 | 2,145 | 13999.8 | +0 | +0 | 312 |
| 12 | AS16509 | Amazon AWS | US | 🟠 85 | 432,104 | 2267.5 | +0 | +19 | 14341 |
| 13 | AS31898 | Oracle Cloud | US | 🟠 84 | 31,864 | 6717.1 | +0 | +3 | 1971 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,691 | 5912.9 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,304 | 5047.3 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,474 | 1981.6 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,435 | 1666.3 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 52,179 | 785.9 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,577 | 386.9 | +0 | +0 | 328 |

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
*Generiert: 2026-06-10 06:38 UTC*