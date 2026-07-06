# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-07-06 06:44 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 7,370,278  
**Davon in bekannten ASN-Ranges:** 1,240,984

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 120 | 30,700 | 12835.5 | +0 | +4 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 340,000 | 111993.0 | +0 | +13 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 56,032 | 5883.7 | +0 | +17 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 29,598 | 1719.4 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 21,116 | 44975.1 | +0 | +0 | 567 |
| 6 | AS24940 | Hetzner | DE | 🟠 99 | 33,687 | 11984.5 | +0 | +3 | 82 |
| 7 | AS16276 | OVH | FR | 🟠 99 | 57,134 | 12570.7 | +0 | +3 | 600 |
| 8 | AS20473 | Vultr | US | 🟠 98 | 25,714 | 18781.8 | +0 | +1 | 1453 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 27,421 | 21617.2 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,357 | 15383.5 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 15,499 | 27185.9 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 34,882 | 7353.4 | +0 | +6 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 494,674 | 2595.8 | +0 | +18 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,733 | 5965.9 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 5,015 | 5881.1 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 2,963 | 2373.2 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,665 | 1933.4 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 64 | 55,626 | 837.8 | +0 | +3 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 2,168 | 531.8 | +0 | +0 | 328 |

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
*Generiert: 2026-07-06 06:44 UTC*