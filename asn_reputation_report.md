# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-22 04:51 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,369,101  
**Davon in bekannten ASN-Ranges:** 838,776

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 24,771 | 10356.6 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 244,317 | 80475.9 | +0 | +12 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 13,288 | 28302.2 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 38,237 | 4015.1 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,661 | 13630.2 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 90 | 13,830 | 10902.8 | +0 | +0 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,680 | 10964.9 | +0 | +0 | 312 |
| 8 | AS12876 | Scaleway | FR | 🟠 90 | 9,308 | 16326.6 | +0 | +8 | 22 |
| 9 | AS12389 | Rostelecom | RU | 🟠 85 | 16,682 | 969.1 | +0 | +0 | 3183 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,484 | 5583.0 | +0 | +5 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 310,051 | 1627.0 | +0 | +19 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 24,927 | 8868.0 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 81 | 41,819 | 9201.0 | +0 | +2 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,034 | 3824.3 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,348 | 3926.2 | +0 | +6 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,987 | 1591.5 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 937 | 1088.0 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 44,199 | 665.7 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,216 | 298.3 | +0 | +0 | 328 |

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
*Generiert: 2026-04-22 04:51 UTC*