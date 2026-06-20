# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-20 06:37 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,460,121  
**Davon in bekannten ASN-Ranges:** 1,139,248

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 29,013 | 12130.1 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 329,538 | 108546.9 | +0 | +16 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 49,196 | 5165.9 | +0 | +16 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 25,807 | 1499.2 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 19,229 | 40956.0 | +0 | +0 | 567 |
| 6 | AS20473 | Vultr | US | 🟠 98 | 22,448 | 16396.3 | +0 | +1 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 96 | 30,066 | 10696.3 | +0 | +2 | 82 |
| 8 | AS16276 | OVH | FR | 🟠 93 | 50,229 | 11051.4 | +0 | +1 | 600 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 24,356 | 19200.9 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,166 | 14136.9 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 11,319 | 19854.0 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 33,532 | 7068.8 | +0 | +4 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 446,018 | 2340.5 | +0 | +20 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,755 | 5993.6 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,406 | 5166.9 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 2,488 | 1992.8 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,433 | 1664.0 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 61 | 51,661 | 778.1 | +0 | +2 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,588 | 389.6 | +0 | +0 | 328 |

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
*Generiert: 2026-06-20 06:37 UTC*