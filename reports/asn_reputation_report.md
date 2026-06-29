# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-06-29 06:58 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 6,914,923  
**Davon in bekannten ASN-Ranges:** 1,174,196

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 120 | 29,296 | 12248.5 | +0 | +4 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 330,496 | 108862.5 | +0 | +14 | 827 |
| 3 | AS45102 | Alibaba Cloud | CN | 🔴 105 | 51,050 | 5360.6 | +0 | +18 | 877 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 28,467 | 1653.7 | +0 | +0 | 3183 |
| 5 | AS51167 | Contabo | DE | 🔴 100 | 20,331 | 43303.2 | +0 | +0 | 567 |
| 6 | AS24940 | Hetzner | DE | 🟠 99 | 31,591 | 11238.8 | +0 | +3 | 82 |
| 7 | AS16276 | OVH | FR | 🟠 99 | 55,015 | 12104.5 | +0 | +3 | 600 |
| 8 | AS20473 | Vultr | US | 🟠 98 | 23,853 | 17422.5 | +0 | +1 | 1453 |
| 9 | AS63949 | Linode (Akamai) | US | 🟠 90 | 25,534 | 20129.6 | +0 | +0 | 341 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 2,216 | 14463.2 | +0 | +0 | 312 |
| 11 | AS12876 | Scaleway | FR | 🟠 85 | 14,900 | 26135.2 | +0 | +0 | 22 |
| 12 | AS31898 | Oracle Cloud | US | 🟠 85 | 34,164 | 7202.0 | +0 | +7 | 1971 |
| 13 | AS16509 | Amazon AWS | US | 🟠 85 | 458,646 | 2406.8 | +0 | +18 | 14341 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 4,596 | 5793.2 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 4,803 | 5632.5 | +0 | +4 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟠 71 | 2,647 | 2120.1 | +0 | +2 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,562 | 1813.8 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 64 | 52,911 | 796.9 | +0 | +3 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 2,118 | 519.6 | +0 | +0 | 328 |

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
*Generiert: 2026-06-29 06:58 UTC*