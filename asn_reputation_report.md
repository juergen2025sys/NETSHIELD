# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-31 06:27 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 5,829,587  
**Davon in bekannten ASN-Ranges:** 1,033,515

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 27,834 | 11637.2 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 306,387 | 100921.2 | +0 | +18 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 106 | 18,182 | 38726.0 | +0 | +2 | 567 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 23,502 | 1365.2 | +0 | +0 | 3183 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 42,510 | 4463.8 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 21,518 | 15717.0 | +0 | +0 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 93 | 28,706 | 10212.5 | +0 | +1 | 82 |
| 8 | AS63949 | Linode (Akamai) | US | 🟠 90 | 22,156 | 17466.6 | +0 | +0 | 341 |
| 9 | AS16276 | OVH | FR | 🟠 90 | 48,830 | 10743.6 | +0 | +0 | 600 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,108 | 13758.4 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 88 | 11,017 | 19324.3 | +0 | +1 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 31,221 | 6581.6 | +0 | +6 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 387,469 | 2033.3 | +0 | +17 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,295 | 5413.8 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,184 | 4906.6 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,443 | 1956.7 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,419 | 1647.7 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 48,168 | 725.5 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,566 | 384.1 | +0 | +0 | 328 |

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
*Generiert: 2026-05-31 06:27 UTC*