# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-05-23 05:45 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 5,244,529  
**Davon in bekannten ASN-Ranges:** 945,835

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS132203 | Tencent Cloud | CN | 🔴 119 | 26,014 | 10876.3 | +0 | +3 | 1050 |
| 2 | AS14061 | DigitalOcean | US | 🔴 110 | 270,954 | 89249.9 | +0 | +25 | 827 |
| 3 | AS51167 | Contabo | DE | 🔴 106 | 15,800 | 33652.5 | +0 | +2 | 567 |
| 4 | AS12389 | Rostelecom | RU | 🔴 100 | 21,498 | 1248.8 | +0 | +0 | 3183 |
| 5 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 40,872 | 4291.8 | +0 | +0 | 877 |
| 6 | AS20473 | Vultr | US | 🟠 95 | 20,624 | 15064.0 | +0 | +0 | 1453 |
| 7 | AS12876 | Scaleway | FR | 🟠 95 | 10,282 | 18035.0 | +0 | +5 | 22 |
| 8 | AS63949 | Linode (Akamai) | US | 🟠 90 | 18,586 | 14652.2 | +0 | +0 | 341 |
| 9 | AS16276 | OVH | FR | 🟠 90 | 46,258 | 10177.7 | +0 | +0 | 600 |
| 10 | AS22612 | Namecheap | US | 🟠 90 | 1,831 | 11950.5 | +0 | +0 | 312 |
| 11 | AS31898 | Oracle Cloud | US | 🟠 85 | 28,766 | 6064.1 | +0 | +6 | 1971 |
| 12 | AS16509 | Amazon AWS | US | 🟠 85 | 357,228 | 1874.6 | +0 | +17 | 14341 |
| 13 | AS24940 | Hetzner | DE | 🟠 78 | 27,378 | 9740.0 | +0 | +1 | 82 |
| 14 | AS47583 | Hostinger | LT | 🟠 75 | 3,678 | 4636.1 | +0 | +0 | 860 |
| 15 | AS8560 | IONOS | DE | 🟠 75 | 3,669 | 4302.6 | +0 | +5 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 2,294 | 1837.4 | +0 | +0 | 184 |
| 17 | AS46606 | Bluehost (Unified Layer) | US | 🟡 65 | 1,212 | 1407.4 | +0 | +0 | 285 |
| 18 | AS8075 | Microsoft Azure | US | 🟡 55 | 47,402 | 714.0 | +0 | +0 | 931 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,489 | 365.3 | +0 | +0 | 328 |

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
*Generiert: 2026-05-23 05:45 UTC*