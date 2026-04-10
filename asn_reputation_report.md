# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-10 04:52 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,911,188  
**Davon in bekannten ASN-Ranges:** 807,751

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 116 | 24,336 | 10174.7 | +0 | +2 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 228,619 | 75305.1 | +0 | +104 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 12,874 | 27420.4 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 35,798 | 3759.0 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,222 | 13309.6 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 93 | 13,032 | 10273.7 | +0 | +1 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,653 | 10788.7 | +0 | +0 | 312 |
| 8 | AS12389 | Rostelecom | RU | 🟠 85 | 15,852 | 920.9 | +0 | +0 | 3183 |
| 9 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,803 | 5439.4 | +0 | +7 | 1971 |
| 10 | AS16509 | Amazon AWS | US | 🟠 85 | 304,045 | 1595.5 | +0 | +17 | 14341 |
| 11 | AS24940 | Hetzner | DE | 🟠 81 | 23,885 | 8497.3 | +0 | +2 | 82 |
| 12 | AS16276 | OVH | FR | 🟠 81 | 41,459 | 9121.8 | +0 | +2 | 600 |
| 13 | AS12876 | Scaleway | FR | 🟠 80 | 8,804 | 15442.6 | +0 | +0 | 22 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 2,929 | 3692.0 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,307 | 3878.1 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,959 | 1569.1 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 918 | 1066.0 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,040 | 648.3 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,216 | 298.3 | +0 | +0 | 328 |

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
*Generiert: 2026-04-10 04:52 UTC*