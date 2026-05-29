# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-29 06:21 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 5,756,752  
**Davon in bekannten ASN-Ranges:** 1,018,925

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 27,785 | 11616.7 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 304,262 | 100221.2 | +0 | +19 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 106 | 18,021 | 38383.1 | +0 | +2 | 567 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 23,319 | 1354.6 | +0 | +0 | 3183 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 42,216 | 4433.0 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 21,468 | 15680.5 | +0 | +0 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 93 | 28,588 | 10170.5 | +0 | +1 | 82 |
| 8 | AS63949 | Linode (Akamai) | US | 🟠 90 | 21,468 | 16924.2 | +0 | +0 | 341 |
| 9 | AS16276 | OVH | FR | 🟠 90 | 48,650 | 10704.0 | +0 | +0 | 600 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,103 | 13725.7 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 88 | 10,964 | 19231.3 | +0 | +1 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 31,057 | 6547.0 | +0 | +7 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 377,096 | 1978.8 | +0 | +17 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,268 | 5379.8 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,168 | 4887.8 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,439 | 1953.5 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,419 | 1647.7 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 48,066 | 724.0 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,568 | 384.6 | +0 | +0 | 328 |

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
*Generiert: 2026-05-29 06:21 UTC*