# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-30 05:36 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,431,491  
**Davon in bekannten ASN-Ranges:** 842,991

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 116 | 24,416 | 10208.2 | +0 | +2 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 244,927 | 80676.8 | +0 | +21 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 13,303 | 28334.2 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 38,298 | 4021.6 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,722 | 13674.8 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 90 | 14,326 | 11293.8 | +0 | +0 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,677 | 10945.3 | +0 | +0 | 312 |
| 8 | AS12876 | Scaleway | FR | 🟠 90 | 9,405 | 16496.8 | +0 | +13 | 22 |
| 9 | AS12389 | Rostelecom | RU | 🟠 85 | 17,159 | 996.8 | +0 | +0 | 3183 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,620 | 5611.7 | +0 | +6 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 312,618 | 1640.5 | +0 | +9 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 24,857 | 8843.1 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 78 | 43,010 | 9463.1 | +0 | +1 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,467 | 4370.1 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,367 | 3948.5 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,998 | 1600.3 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 924 | 1072.9 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 42,673 | 642.7 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,224 | 300.2 | +0 | +0 | 328 |

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
*Generiert: 2026-04-30 05:36 UTC*