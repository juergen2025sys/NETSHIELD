# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-03 05:36 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 4,541,093  
**Davon in bekannten ASN-Ranges:** 856,383

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 113 | 24,497 | 10242.0 | +0 | +1 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 249,167 | 82073.4 | +0 | +20 | 827 |
| 3 | AS12389 | Rostelecom | RU | 🔴 100 | 17,724 | 1029.6 | +0 | +0 | 3183 |
| 4 | AS51167 | Contabo | DE | 🔴 100 | 14,591 | 31077.5 | +0 | +0 | 567 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 38,563 | 4049.4 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 19,308 | 14102.8 | +0 | +0 | 1453 |
| 7 | AS63949 | Linode (Akamai) | US | 🟠 90 | 15,259 | 12029.4 | +0 | +0 | 341 |
| 8 | AS22612 | Namecheap | US | 🟠 90 | 1,747 | 11402.2 | +0 | +0 | 312 |
| 9 | AS12876 | Scaleway | FR | 🟠 90 | 9,531 | 16717.8 | +0 | +13 | 22 |
| 10 | AS31898 | Oracle Cloud | US | 🟠 85 | 26,838 | 5657.6 | +0 | +6 | 1971 |
| 11 | AS16509 | Amazon AWS | US | 🟠 85 | 313,830 | 1646.8 | +0 | +9 | 14341 |
| 12 | AS24940 | Hetzner | DE | 🟠 81 | 26,165 | 9308.5 | +0 | +2 | 82 |
| 13 | AS16276 | OVH | FR | 🟠 75 | 44,444 | 9778.6 | +0 | +0 | 600 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,498 | 4409.2 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 3,457 | 4054.0 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,178 | 1744.5 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,177 | 1366.7 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 43,044 | 648.3 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,365 | 334.8 | +0 | +0 | 328 |

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
*Generiert: 2026-05-03 05:36 UTC*