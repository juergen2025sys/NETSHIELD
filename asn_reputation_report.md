# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-24 05:14 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,870,690  
**Davon in bekannten ASN-Ranges:** 792,388

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 231,373 | 76212.2 | +0 | +12 | 827 |
| 2 | AS132203 | Tencent Cloud | CN | 🔴 104 | 16,826 | 7034.9 | +0 | +3 | 1050 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 12,188 | 25959.3 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 35,357 | 3712.7 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 17,968 | 13124.1 | +0 | +0 | 1453 |
| 6 | AS12876 | Scaleway | FR | 🟠 90 | 8,778 | 15397.0 | +0 | +8 | 22 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 13,035 | 757.2 | +0 | +0 | 3183 |
| 8 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,347 | 5554.1 | +0 | +5 | 1971 |
| 9 | AS16509 | Amazon AWS | US | 🟠 85 | 305,616 | 1603.8 | +0 | +19 | 14341 |
| 10 | AS24940 | Hetzner | DE | 🟠 81 | 22,911 | 8150.8 | +0 | +2 | 82 |
| 11 | AS16276 | OVH | FR | 🟠 81 | 37,897 | 8338.1 | +0 | +2 | 600 |
| 12 | AS63949 | Linode (Akamai) | US | 🟠 75 | 12,130 | 9562.6 | +0 | +0 | 341 |
| 13 | AS47583 | Hostinger | LT | 🟠 75 | 2,706 | 3410.9 | +0 | +0 | 860 |
| 14 | AS22612 | Namecheap | US | 🟠 75 | 1,517 | 9901.0 | +0 | +0 | 312 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 2,990 | 3506.4 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,581 | 1266.3 | +0 | +0 | 184 |
| 17 | AS8075 | Microsoft Azure | US | 🟡 55 | 41,149 | 619.8 | +0 | +0 | 931 |
| 18 | AS36351 | IBM Cloud | US | 🟡 50 | 1,184 | 290.4 | +0 | +0 | 328 |
| 19 | AS46606 | Bluehost (Unified Layer) | US | ⚪ 45 | 835 | 969.6 | +0 | +0 | 285 |

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
*Generiert: 2026-04-24 05:14 UTC*