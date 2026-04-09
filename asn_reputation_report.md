# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-09 04:39 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,825,695  
**Davon in bekannten ASN-Ranges:** 737,932

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 116 | 24,300 | 10159.7 | +0 | +2 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 227,453 | 74921.0 | +0 | +103 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 103 | 12,850 | 27369.3 | +0 | +1 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 35,724 | 3751.3 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,216 | 13305.2 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 93 | 12,897 | 10167.3 | +0 | +1 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,651 | 10775.6 | +0 | +0 | 312 |
| 8 | AS12389 | Rostelecom | RU | 🟠 85 | 15,764 | 915.7 | +0 | +0 | 3183 |
| 9 | AS31898 | Oracle Cloud | US | 🟠 85 | 25,249 | 5322.7 | +0 | +6 | 1971 |
| 10 | AS16509 | Amazon AWS | US | 🟠 85 | 236,941 | 1243.4 | +0 | +16 | 14341 |
| 11 | AS24940 | Hetzner | DE | 🟠 81 | 23,850 | 8484.9 | +0 | +2 | 82 |
| 12 | AS16276 | OVH | FR | 🟠 81 | 41,416 | 9112.4 | +0 | +2 | 600 |
| 13 | AS12876 | Scaleway | FR | 🟠 80 | 8,760 | 15365.4 | +0 | +0 | 22 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 2,929 | 3692.0 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 2,918 | 3421.9 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,959 | 1569.1 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 917 | 1064.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 42,923 | 646.5 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,215 | 298.1 | +0 | +0 | 328 |

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
*Generiert: 2026-04-09 04:39 UTC*