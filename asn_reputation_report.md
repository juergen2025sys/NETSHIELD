# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-27 06:35 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 5,686,507  
**Davon in bekannten ASN-Ranges:** 1,003,369

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 120 | 27,505 | 11499.7 | +0 | +4 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 300,434 | 98960.3 | +0 | +20 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 106 | 17,708 | 37716.4 | +0 | +2 | 567 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 23,102 | 1342.0 | +0 | +0 | 3183 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 41,654 | 4373.9 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 21,361 | 15602.4 | +0 | +0 | 1453 |
| 7 | AS12876 | Scaleway | FR | 🟠 95 | 10,886 | 19094.5 | +0 | +5 | 22 |
| 8 | AS24940 | Hetzner | DE | 🟠 93 | 28,383 | 10097.5 | +0 | +1 | 82 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 21,207 | 16718.4 | +0 | +0 | 341 |
| 10 | AS16276 | OVH | FR | 🟠 90 | 48,299 | 10626.8 | +0 | +0 | 600 |
| 11 | AS22612 | Namecheap | US | 🟠 90 | 2,076 | 13549.5 | +0 | +0 | 312 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 30,844 | 6502.1 | +0 | +6 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 368,865 | 1935.7 | +0 | +17 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,195 | 5287.7 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,103 | 4811.6 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,417 | 1935.9 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,391 | 1615.2 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 47,373 | 713.5 | +0 | +0 | 931 |
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
*Generiert: 2026-05-27 06:35 UTC*