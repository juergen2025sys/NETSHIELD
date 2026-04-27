# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-27 05:31 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,375,593  
**Davon in bekannten ASN-Ranges:** 839,621

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 116 | 24,282 | 10152.1 | +0 | +2 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 242,354 | 79829.3 | +0 | +12 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 13,219 | 28155.2 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 38,185 | 4009.7 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,702 | 13660.2 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 90 | 13,966 | 11010.0 | +0 | +0 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,674 | 10925.8 | +0 | +0 | 312 |
| 8 | AS12876 | Scaleway | FR | 🟠 90 | 9,407 | 16500.3 | +0 | +8 | 22 |
| 9 | AS12389 | Rostelecom | RU | 🟠 85 | 16,651 | 967.3 | +0 | +0 | 3183 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,557 | 5598.4 | +0 | +6 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 311,535 | 1634.8 | +0 | +19 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 24,799 | 8822.5 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 81 | 42,698 | 9394.5 | +0 | +2 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,463 | 4365.1 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,354 | 3933.2 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,997 | 1599.5 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 923 | 1071.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 44,633 | 672.2 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,222 | 299.8 | +0 | +0 | 328 |

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
*Generiert: 2026-04-27 05:31 UTC*