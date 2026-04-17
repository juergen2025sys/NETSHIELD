# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-17 04:54 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,222,801  
**Davon in bekannten ASN-Ranges:** 824,293

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 24,557 | 10267.1 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 237,978 | 78387.9 | +0 | +13 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 13,065 | 27827.2 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 36,290 | 3810.7 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,550 | 13549.2 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 90 | 13,002 | 10250.1 | +0 | +0 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,647 | 10749.5 | +0 | +0 | 312 |
| 8 | AS12876 | Scaleway | FR | 🟠 90 | 9,172 | 16088.1 | +0 | +8 | 22 |
| 9 | AS12389 | Rostelecom | RU | 🟠 85 | 16,278 | 945.6 | +0 | +0 | 3183 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,161 | 5514.9 | +0 | +5 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 307,937 | 1615.9 | +0 | +19 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 24,363 | 8667.4 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 81 | 41,396 | 9108.0 | +0 | +2 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 2,978 | 3753.7 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,282 | 3848.8 | +0 | +6 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,971 | 1578.7 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 932 | 1082.2 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,528 | 655.6 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,206 | 295.8 | +0 | +0 | 328 |

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
*Generiert: 2026-04-17 04:54 UTC*