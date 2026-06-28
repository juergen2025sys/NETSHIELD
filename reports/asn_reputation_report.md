# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-28 06:27 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,623,083  
**Davon in bekannten ASN-Ranges:** 1,148,198

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 120 | 29,078 | 12157.3 | +0 | +4 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 327,286 | 107805.1 | +0 | +14 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 50,729 | 5326.9 | +0 | +18 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 26,753 | 1554.1 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 19,513 | 41560.9 | +0 | +0 | 567 |
| 6 | AS24940 | Hetzner | DE | 🟠 99 | 30,345 | 10795.5 | +0 | +3 | 82 |
| 7 | AS16276 | OVH | FR | 🟠 99 | 50,259 | 11058.0 | +0 | +3 | 600 |
| 8 | AS20473 | Vultr | US | 🟠 98 | 22,713 | 16589.9 | +0 | +1 | 1453 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 24,968 | 19683.4 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,130 | 13901.9 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 11,680 | 20487.2 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 33,887 | 7143.6 | +0 | +7 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 452,390 | 2374.0 | +0 | +18 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,498 | 5669.7 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,505 | 5283.0 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 2,263 | 1812.6 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,390 | 1614.1 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 64 | 52,217 | 786.5 | +0 | +3 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,594 | 391.0 | +0 | +0 | 328 |

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
*Generiert: 2026-06-28 06:27 UTC*