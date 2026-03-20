# ASN Reputation Scorer – Report
**Aktualisiert:** 2026-03-20 04:20 UTC  
**Methode:** ScaniteX CIDR-Prefixlisten (kein API-Key, 100% BL-Coverage)  
**Blacklist-IPs gesamt:** 3,714,931  
**Davon in bekannten ASN-Ranges:** 746,624

---

## ASN-Übersicht (nach Score sortiert)

| Rang | ASN | Organisation | Land | Score | BL-Hits | Dichte/1M | DROP | ET | Prefixes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | AS14061 | DigitalOcean | US | 🔴 110 | 204,975 | 67517.0 | +0 | +256 | 827 |
| 2 | AS132203 | Tencent Cloud | CN | 🔴 104 | 22,879 | 9565.6 | +0 | +3 | 1050 |
| 3 | AS51167 | Contabo | DE | 🔴 103 | 11,774 | 25077.5 | +0 | +1 | 567 |
| 4 | AS45102 | Alibaba Cloud | CN | 🟠 95 | 31,996 | 3359.8 | +0 | +0 | 877 |
| 5 | AS20473 | Vultr | US | 🟠 95 | 17,194 | 12558.7 | +0 | +0 | 1453 |
| 6 | AS22612 | Namecheap | US | 🟠 90 | 1,613 | 10527.6 | +0 | +0 | 312 |
| 7 | AS12389 | Rostelecom | RU | 🟠 85 | 13,960 | 811.0 | +0 | +0 | 3183 |
| 8 | AS31898 | Oracle Cloud | US | 🟠 85 | 24,755 | 5218.5 | +0 | +7 | 1971 |
| 9 | AS16509 | Amazon AWS | US | 🟠 85 | 291,004 | 1527.1 | +0 | +18 | 14341 |
| 10 | AS16276 | OVH | FR | 🟠 84 | 38,677 | 8509.8 | +0 | +3 | 600 |
| 11 | AS24940 | Hetzner | DE | 🟠 81 | 22,649 | 8057.6 | +0 | +2 | 82 |
| 12 | AS12876 | Scaleway | FR | 🟠 80 | 8,131 | 14262.1 | +0 | +0 | 22 |
| 13 | AS47583 | Hostinger | LT | 🟠 78 | 2,816 | 3549.5 | +0 | +1 | 860 |
| 14 | AS63949 | Linode (Akamai) | US | 🟠 75 | 10,372 | 8176.7 | +0 | +0 | 341 |
| 15 | AS8560 | IONOS | DE | 🟠 74 | 3,171 | 3718.6 | +0 | +3 | 462 |
| 16 | AS26496 | GoDaddy | US | 🟡 65 | 1,939 | 1553.0 | +0 | +0 | 184 |
| 17 | AS8075 | Microsoft Azure | US | 🟡 61 | 36,631 | 551.7 | +0 | +2 | 931 |
| 18 | AS46606 | Bluehost (Unified Layer) | US | 🟡 60 | 895 | 1039.3 | +0 | +0 | 285 |
| 19 | AS36351 | IBM Cloud | US | 🟡 50 | 1,193 | 292.6 | +0 | +0 | 328 |

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
*Generiert: 2026-03-20 04:20 UTC*