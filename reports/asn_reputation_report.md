# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-26 06:17 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,582,803  
**Davon in bekannten ASN-Ranges:** 1,145,668

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 120 | 29,123 | 12176.1 | +0 | +4 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 328,024 | 108048.2 | +0 | +15 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 50,192 | 5270.5 | +0 | +18 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 26,340 | 1530.1 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 19,454 | 41435.2 | +0 | +0 | 567 |
| 6 | AS24940 | Hetzner | DE | 🟠 99 | 30,258 | 10764.6 | +0 | +3 | 82 |
| 7 | AS16276 | OVH | FR | 🟠 99 | 50,176 | 11039.8 | +0 | +3 | 600 |
| 8 | AS20473 | Vultr | US | 🟠 98 | 22,621 | 16522.7 | +0 | +1 | 1453 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 24,824 | 19569.9 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,121 | 13843.2 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 11,616 | 20374.9 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 33,815 | 7128.4 | +0 | +7 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 450,916 | 2366.2 | +0 | +18 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,503 | 5676.0 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,478 | 5251.3 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 2,262 | 1811.8 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,386 | 1609.4 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 65 | 51,965 | 782.7 | +0 | +4 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,594 | 391.0 | +0 | +0 | 328 |

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
*Generiert: 2026-06-26 06:17 UTC*