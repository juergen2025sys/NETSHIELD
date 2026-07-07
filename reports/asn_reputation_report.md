# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-07-07 06:16 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 7,405,599  
**Davon in bekannten ASN-Ranges:** 1,243,080

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 120 | 30,725 | 12845.9 | +0 | +5 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 340,829 | 112266.1 | +0 | +17 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 56,190 | 5900.3 | +0 | +17 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 29,683 | 1724.3 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 21,146 | 45039.0 | +0 | +0 | 567 |
| 6 | AS24940 | Hetzner | DE | 🟠 99 | 33,767 | 12013.0 | +0 | +3 | 82 |
| 7 | AS16276 | OVH | FR | 🟠 99 | 57,212 | 12587.8 | +0 | +3 | 600 |
| 8 | AS20473 | Vultr | US | 🟠 98 | 26,012 | 18999.5 | +0 | +1 | 1453 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 27,491 | 21672.4 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,363 | 15422.7 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 15,537 | 27252.5 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 34,927 | 7362.9 | +0 | +6 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 494,930 | 2597.2 | +0 | +18 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,734 | 5967.1 | +0 | +0 | 860 |
| 15 | AS26496 | GoDaddy | US | 🟠 71 | 2,965 | 2374.8 | +0 | +2 | 184 |
| 16 | AS8560 | IONOS | DE | 🟠 71 | 5,024 | 5891.6 | +0 | +2 | 462 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,666 | 1934.5 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 64 | 55,709 | 839.1 | +0 | +3 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 2,170 | 532.3 | +0 | +0 | 328 |

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
*Generiert: 2026-07-07 06:16 UTC*