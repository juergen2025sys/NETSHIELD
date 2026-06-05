# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-05 06:39 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,050,576  
**Davon in bekannten ASN-Ranges:** 1,075,748

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 28,332 | 11845.4 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 313,346 | 103213.4 | +0 | +17 | 827 |
| 3 | AS12389 | Rostelecom | RU | 🔴 100 | 24,018 | 1395.2 | +0 | +0 | 3183 |
| 4 | AS51167 | Contabo | DE | 🔴 100 | 18,528 | 39462.9 | +0 | +0 | 567 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 98 | 45,891 | 4818.9 | +0 | +1 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 21,697 | 15847.8 | +0 | +0 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 90 | 29,193 | 10385.7 | +0 | +0 | 82 |
| 8 | AS63949 | Linode (Akamai) | US | 🟠 90 | 22,997 | 18129.6 | +0 | +0 | 341 |
| 9 | AS16276 | OVH | FR | 🟠 90 | 49,261 | 10838.5 | +0 | +0 | 600 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,127 | 13882.4 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 88 | 11,179 | 19608.4 | +0 | +1 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 31,612 | 6664.0 | +0 | +4 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 411,938 | 2161.7 | +0 | +24 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,468 | 5631.9 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 4,244 | 4976.9 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,464 | 1973.5 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,425 | 1654.7 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 51,460 | 775.1 | +0 | +0 | 931 |
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
*Generiert: 2026-06-05 06:39 UTC*