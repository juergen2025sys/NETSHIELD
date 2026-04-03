# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-03 04:35 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,755,294  
**Davon in bekannten ASN-Ranges:** 786,707

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 218,936 | 72115.6 | +0 | +150 | 827 |
| 2 | AS132203 | Tencent Cloud | CN | 🔴 105 | 23,303 | 9742.8 | +0 | +4 | 1050 |
| 3 | AS51167 | Contabo | DE | 🔴 103 | 12,530 | 26687.7 | +0 | +1 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 35,164 | 3692.5 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 17,983 | 13135.0 | +0 | +0 | 1453 |
| 6 | AS22612 | Namecheap | US | 🟠 90 | 1,634 | 10664.7 | +0 | +0 | 312 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 14,834 | 861.7 | +0 | +0 | 3183 |
| 8 | AS16276 | OVH | FR | 🟠 85 | 40,662 | 8946.5 | +0 | +4 | 600 |
| 9 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,501 | 5375.8 | +0 | +8 | 1971 |
| 10 | AS16509 | Amazon AWS | US | 🟠 85 | 299,999 | 1574.3 | +0 | +18 | 14341 |
| 11 | AS12876 | Scaleway | FR | 🟠 80 | 8,570 | 15032.1 | +0 | +0 | 22 |
| 12 | AS24940 | Hetzner | DE | 🟠 78 | 23,447 | 8341.5 | +0 | +1 | 82 |
| 13 | AS47583 | Hostinger | LT | 🟠 78 | 2,886 | 3637.8 | +0 | +1 | 860 |
| 14 | AS63949 | Linode (Akamai) | US | 🟠 75 | 11,971 | 9437.3 | +0 | +0 | 341 |
| 15 | AS8560 | IONOS | DE | 🟠 71 | 3,310 | 3881.6 | +0 | +2 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,956 | 1566.7 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 917 | 1064.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 41,892 | 631.0 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,212 | 297.3 | +0 | +0 | 328 |

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
*Generiert: 2026-04-03 04:35 UTC*