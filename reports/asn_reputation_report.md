# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-16 07:35 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,368,536  
**Davon in bekannten ASN-Ranges:** 1,126,730

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 116 | 28,803 | 12042.4 | +0 | +2 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 325,154 | 107102.9 | +0 | +17 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 48,578 | 5101.0 | +0 | +8 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 25,444 | 1478.1 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 19,040 | 40553.4 | +0 | +0 | 567 |
| 6 | AS20473 | Vultr | US | 🟠 98 | 22,242 | 16245.9 | +0 | +1 | 1453 |
| 7 | AS24940 | Hetzner | DE | 🟠 96 | 29,797 | 10600.6 | +0 | +2 | 82 |
| 8 | AS63949 | Linode (Akamai) | US | 🟠 90 | 23,920 | 18857.2 | +0 | +0 | 341 |
| 9 | AS16276 | OVH | FR | 🟠 90 | 49,921 | 10983.7 | +0 | +0 | 600 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,156 | 14071.6 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 11,173 | 19597.9 | +0 | +0 | 22 |
| 12 | AS16509 | Amazon AWS | US | 🟠 85 | 442,532 | 2322.2 | +0 | +20 | 14341 |
| 13 | AS31898 | Oracle Cloud | US | 🟠 81 | 32,257 | 6800.0 | +0 | +2 | 1971 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,752 | 5989.8 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,322 | 5068.4 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 68 | 2,481 | 1987.2 | +0 | +1 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,431 | 1661.7 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 61 | 51,148 | 770.4 | +0 | +2 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,579 | 387.3 | +0 | +0 | 328 |

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
*Generiert: 2026-06-16 07:35 UTC*