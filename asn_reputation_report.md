# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-09 06:16 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,161,349  
**Davon in bekannten ASN-Ranges:** 1,101,984

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 28,441 | 11891.0 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 316,531 | 104262.5 | +0 | +12 | 827 |
| 3 | AS12389 | Rostelecom | RU | 🔴 100 | 24,373 | 1415.8 | +0 | +0 | 3183 |
| 4 | AS51167 | Contabo | DE | 🔴 100 | 18,788 | 40016.7 | +0 | +0 | 567 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 98 | 46,346 | 4866.6 | +0 | +1 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 21,867 | 15972.0 | +0 | +0 | 1453 |
| 7 | AS12876 | Scaleway | FR | 🟠 91 | 11,247 | 19727.7 | +0 | +2 | 22 |
| 8 | AS24940 | Hetzner | DE | 🟠 90 | 29,406 | 10461.5 | +0 | +0 | 82 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 23,269 | 18344.0 | +0 | +0 | 341 |
| 10 | AS16276 | OVH | FR | 🟠 90 | 49,506 | 10892.4 | +0 | +0 | 600 |
| 11 | AS22612 | Namecheap | US | 🟠 90 | 2,139 | 13960.7 | +0 | +0 | 312 |
| 12 | AS16509 | Amazon AWS | US | 🟠 85 | 431,775 | 2265.8 | +0 | +19 | 14341 |
| 13 | AS31898 | Oracle Cloud | US | 🟠 84 | 31,844 | 6712.9 | +0 | +3 | 1971 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,684 | 5904.1 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,292 | 5033.2 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,470 | 1978.4 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,435 | 1666.3 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 51,997 | 783.2 | +0 | +0 | 931 |
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
*Generiert: 2026-06-09 06:16 UTC*