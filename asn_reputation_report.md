# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-03-12 19:45 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 2,859,128  
**Davon in bekannten ASN-Ranges:** 661,471

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|
| 1 | AS12389 | Rostelecom | RU | 🔴 9999 | 9,688 | +0 | +0 | 3183 |
| 2 | AS45102 | Alibaba Cloud | CN | 🔴 9999 | 28,614 | +0 | +0 | 877 |
| 3 | AS132203 | Tencent Cloud | CN | 🔴 9999 | 14,481 | +0 | +0 | 1050 |
| 4 | AS14061 | DigitalOcean | US | 🔴 9999 | 171,620 | +0 | +2 | 827 |
| 5 | AS20473 | Vultr | US | 🔴 9999 | 16,001 | +0 | +0 | 1453 |
| 6 | AS51167 | Contabo | DE | 🔴 9999 | 10,052 | +0 | +0 | 567 |
| 7 | AS24940 | Hetzner | DE | 🔴 9999 | 20,169 | +0 | +0 | 82 |
| 8 | AS63949 | Linode (Akamai) | US | 🔴 9999 | 7,634 | +0 | +2 | 341 |
| 9 | AS16276 | OVH | FR | 🔴 9999 | 32,392 | +0 | +0 | 600 |
| 10 | AS12876 | Scaleway | FR | 🔴 9999 | 7,131 | +0 | +0 | 22 |
| 11 | AS31898 | Oracle Cloud | US | 🔴 9999 | 23,926 | +0 | +0 | 1971 |
| 12 | AS16509 | Amazon AWS | US | 🔴 9999 | 277,786 | +0 | +2 | 14341 |
| 13 | AS8075 | Microsoft Azure | US | 🔴 9999 | 32,600 | +0 | +0 | 931 |
| 14 | AS8560 | IONOS | DE | 🔴 5330 | 2,660 | +0 | +0 | 462 |
| 15 | AS47583 | Hostinger | LT | 🔴 3780 | 1,880 | +0 | +0 | 860 |
| 16 | AS26496 | GoDaddy | US | 🔴 2990 | 1,490 | +0 | +0 | 184 |
| 17 | AS22612 | Namecheap | US | 🔴 2872 | 1,426 | +0 | +0 | 312 |
| 18 | AS36351 | IBM Cloud | US | 🔴 2292 | 1,141 | +0 | +0 | 328 |
| 19 | AS46606 | Bluehost (Unified Layer) | US | 🔴 1570 | 780 | +0 | +0 | 285 |

---

### Score-Formel
```
score = base_score + (BL-Treffer × 2) + (DROP-Bonus × 5) + (ET-Bonus × 3)
```
- **base_score**: Basis-Reputation (RU/CN-Provider höher bewertet)
- **BL-Treffer**: Blacklist-IPs die in ASN-Prefixes liegen (100% Coverage)
- **DROP-Bonus**: IPs auch in Spamhaus DROP
- **ET-Bonus**: IPs auch in Emerging Threats

---
*Datenquelle: [ScaniteX ASN Database](https://scanitex.com/en/resources/asn-database) (BGP via RIPE Stat, kein API-Key)*  
*Generiert: 2026-03-12 19:45 UTC*