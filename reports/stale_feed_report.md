# NETSHIELD – Stale-Feed-Report
**Aktualisiert:** 2026-08-20 04:12 CEST (Europe/Berlin)
**Schwelle:** IP-Menge ≥ 14 Tage unveraendert

Erkennt Feeds, die zwar antworten und IPs liefern, deren Inhalt sich aber lange nicht mehr aendert. Solche Feeds bestehen den Status-/has_ips-Check, halten ihre IPs aber kuenstlich auf voller Aktualitaet und entgehen so dem Score-Decay → Risiko veralteter Dauer-Blocks. Flag ist **advisory**, kein Auto-Remove.

## ⚠️ 3 moeglicherweise eingefrorene(r) Feed(s)

| Feed | Tage unveraendert | Seit | IPs (Sample) | Typ | URL |
|---|---|---|---|---|---|
| `ashleykleynhans_abuseipdb` | 15 | 2026-08-04 15:19 UTC | ~31614 | normal | https://raw.githubusercontent.com/ashleykleynhans/ipset/refs/heads/main/ipv4.csv |
| `black_mirror` | 15 | 2026-08-04 15:19 UTC | ~1437011 | normal | https://github.com/T145/black-mirror/releases/download/latest/BLOCK_IPV4.txt |
| `blacksnowdot_packets` | 15 | 2026-08-04 15:19 UTC | ~30907 | normal | https://raw.githubusercontent.com/BlacKSnowDot0/packetsdatabase-db/refs/heads/main/ip_list.txt |

Hinweis: Kleine kuratierte Listen aendern sich legitim selten – ein Flag hier ist nicht automatisch ein Defekt. Bei DataPlane-Feeds (taegliches Honeypot-Signal) ist ein eingefrorener Stand dagegen ein echtes Alarmsignal. Der Fingerprint basiert auf dem 2-MB-Sample (wie sample_ips); bei sehr grossen Feeds ist er eine Praefix-Heuristik.

*Generiert: 2026-08-20 04:12 CEST (Europe/Berlin)*