# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-07-10 06:11 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 7,530,619  
**Davon in bekannten ASN-Ranges:** 1,257,560

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 120 | 30,822 | 12886.5 | +0 | +5 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 338,771 | 111588.2 | +0 | +18 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 56,622 | 5945.7 | +0 | +16 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 30,222 | 1755.6 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 21,370 | 45516.1 | +0 | +0 | 567 |
| 6 | AS16276 | OVH | FR | 🔴 100 | 58,115 | 12786.5 | +0 | +4 | 600 |
| 7 | AS24940 | Hetzner | DE | 🟠 99 | 34,163 | 12153.9 | +0 | +3 | 82 |
| 8 | AS20473 | Vultr | US | 🟠 98 | 27,038 | 19748.9 | +0 | +1 | 1453 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 26,882 | 21192.3 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,377 | 15514.0 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 15,728 | 27587.6 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 36,321 | 7656.7 | +0 | +6 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 505,221 | 2651.2 | +0 | +18 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,753 | 5991.1 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 5,142 | 6030.0 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 3,056 | 2447.7 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,708 | 1983.3 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 64 | 57,029 | 859.0 | +0 | +3 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 2,220 | 544.6 | +0 | +0 | 328 |

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
*Generiert: 2026-07-10 06:11 UTC*