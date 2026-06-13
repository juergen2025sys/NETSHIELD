# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-13 15:51 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,304,022  
**Davon in bekannten ASN-Ranges:** 1,119,707

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 116 | 28,722 | 12008.5 | +0 | +2 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 322,645 | 106276.4 | +0 | +13 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 104 | 47,585 | 4996.7 | +0 | +3 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 25,215 | 1464.8 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 18,907 | 40270.2 | +0 | +0 | 567 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 22,145 | 16175.0 | +0 | +0 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 90 | 29,672 | 10556.1 | +0 | +0 | 82 |
| 8 | AS63949 | Linode (Akamai) | US | 🟠 90 | 23,699 | 18683.0 | +0 | +0 | 341 |
| 9 | AS16276 | OVH | FR | 🟠 90 | 49,796 | 10956.2 | +0 | +0 | 600 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,149 | 14026.0 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 88 | 11,144 | 19547.0 | +0 | +1 | 22 |
| 12 | AS16509 | Amazon AWS | US | 🟠 85 | 440,581 | 2312.0 | +0 | +19 | 14341 |
| 13 | AS31898 | Oracle Cloud | US | 🟠 84 | 32,135 | 6774.3 | +0 | +3 | 1971 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,731 | 5963.4 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,276 | 5014.4 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 68 | 2,471 | 1979.2 | +0 | +1 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,427 | 1657.0 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 58 | 50,830 | 765.6 | +0 | +1 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,577 | 386.9 | +0 | +0 | 328 |

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
*Generiert: 2026-06-13 15:51 UTC*