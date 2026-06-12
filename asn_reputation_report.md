# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-12 06:51 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,261,730  
**Davon in bekannten ASN-Ranges:** 1,118,423

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 28,599 | 11957.1 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 321,133 | 105778.4 | +0 | +12 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 104 | 46,997 | 4935.0 | +0 | +3 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 24,942 | 1448.9 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 18,986 | 40438.4 | +0 | +0 | 567 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 22,045 | 16102.0 | +0 | +0 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 90 | 29,573 | 10520.9 | +0 | +0 | 82 |
| 8 | AS63949 | Linode (Akamai) | US | 🟠 90 | 23,592 | 18598.6 | +0 | +0 | 341 |
| 9 | AS16276 | OVH | FR | 🟠 90 | 49,738 | 10943.4 | +0 | +0 | 600 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,145 | 13999.8 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 88 | 11,357 | 19920.7 | +0 | +1 | 22 |
| 12 | AS16509 | Amazon AWS | US | 🟠 85 | 439,991 | 2308.9 | +0 | +19 | 14341 |
| 13 | AS31898 | Oracle Cloud | US | 🟠 84 | 32,026 | 6751.3 | +0 | +3 | 1971 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,745 | 5981.0 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,338 | 5087.1 | +0 | +5 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 68 | 2,466 | 1975.2 | +0 | +1 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,426 | 1655.9 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 58 | 52,750 | 794.5 | +0 | +1 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,574 | 386.1 | +0 | +0 | 328 |

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
*Generiert: 2026-06-12 06:51 UTC*