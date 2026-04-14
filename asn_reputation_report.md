# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-04-14 04:50 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,082,504  
**Davon in bekannten ASN-Ranges:** 819,474

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 24,498 | 10242.5 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 235,136 | 77451.7 | +0 | +18 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 100 | 13,000 | 27688.8 | +0 | +0 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 36,170 | 3798.1 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 18,509 | 13519.2 | +0 | +0 | 1453 |
| 6 | AS63949 | Linode (Akamai) | US | 🟠 90 | 12,743 | 10045.9 | +0 | +0 | 341 |
| 7 | AS22612 | Namecheap | US | 🟠 90 | 1,645 | 10736.5 | +0 | +0 | 312 |
| 8 | AS12876 | Scaleway | FR | 🟠 90 | 8,992 | 15772.3 | +0 | +4 | 22 |
| 9 | AS12389 | Rostelecom | RU | 🟠 85 | 16,155 | 938.5 | +0 | +0 | 3183 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,075 | 5496.8 | +0 | +7 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 307,472 | 1613.5 | +0 | +17 | 14341 |
| 12 | AS16276 | OVH | FR | 🟠 84 | 41,300 | 9086.9 | +0 | +3 | 600 |
| 13 | AS24940 | Hetzner | DE | 🟠 81 | 24,214 | 8614.4 | +0 | +2 | 82 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 2,968 | 3741.1 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,263 | 3826.5 | +0 | +6 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,969 | 1577.1 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 931 | 1081.1 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,228 | 651.1 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,206 | 295.8 | +0 | +0 | 328 |

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
*Generiert: 2026-04-14 04:50 UTC*