# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-01 07:10 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 5,941,005  
**Davon in bekannten ASN-Ranges:** 1,046,082

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 28,159 | 11773.1 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 310,265 | 102198.6 | +0 | +18 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 106 | 18,269 | 38911.3 | +0 | +2 | 567 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 23,684 | 1375.8 | +0 | +0 | 3183 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 43,028 | 4518.2 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 21,558 | 15746.2 | +0 | +0 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 93 | 28,991 | 10313.9 | +0 | +1 | 82 |
| 8 | AS63949 | Linode (Akamai) | US | 🟠 90 | 22,525 | 17757.5 | +0 | +0 | 341 |
| 9 | AS16276 | OVH | FR | 🟠 90 | 48,984 | 10777.5 | +0 | +0 | 600 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,114 | 13797.5 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 88 | 11,099 | 19468.1 | +0 | +1 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 31,365 | 6612.0 | +0 | +6 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 393,121 | 2062.9 | +0 | +17 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,347 | 5479.3 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,204 | 4930.0 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,446 | 1959.1 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,421 | 1650.0 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 48,935 | 737.0 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,567 | 384.4 | +0 | +0 | 328 |

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
*Generiert: 2026-06-01 07:10 UTC*