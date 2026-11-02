# NETSHIELD – Stale-Feed-Report
**Aktualisiert:** 2026-11-02 08:00 CET (Europe/Berlin)
**Schwelle:** IP-Menge ≥ 14 Tage unveraendert

Erkennt Feeds, die zwar antworten und IPs liefern, deren Inhalt sich aber lange nicht mehr aendert. Solche Feeds bestehen den Status-/has_ips-Check, halten ihre IPs aber kuenstlich auf voller Aktualitaet und entgehen so dem Score-Decay → Risiko veralteter Dauer-Blocks. Flag ist **advisory**, kein Auto-Remove.

## ⚠️ 2 moeglicherweise eingefrorene(r) Feed(s)

| Feed | Tage unveraendert | Seit | IPs (Sample) | Typ | URL |
|---|---|---|---|---|---|
| `ultimate_hosts_ips0` | 30 | 2026-10-03 07:56 CEST (Europe/Berlin) | ~144537 | normal | https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/refs/heads/master/ips/ips0.list |
| `fadouse_worm` | 17 | 2026-10-16 07:18 CEST (Europe/Berlin) | ~156 | normal | https://raw.githubusercontent.com/Fadouse/clash-threat-intel/main/clash/generated/worm.txt |

Hinweis: Kleine kuratierte Listen aendern sich legitim selten – ein Flag hier ist nicht automatisch ein Defekt. Bei DataPlane-Feeds (taegliches Honeypot-Signal) ist ein eingefrorener Stand dagegen ein echtes Alarmsignal. Der Fingerprint basiert auf dem 2-MB-Sample (wie sample_ips); bei sehr grossen Feeds ist er eine Praefix-Heuristik.

*Generiert: 2026-11-02 08:00 CET (Europe/Berlin)*