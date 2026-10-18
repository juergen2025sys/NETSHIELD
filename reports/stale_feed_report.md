# NETSHIELD – Stale-Feed-Report
**Aktualisiert:** 2026-10-18 07:17 CEST (Europe/Berlin)
**Schwelle:** IP-Menge ≥ 14 Tage unveraendert

Erkennt Feeds, die zwar antworten und IPs liefern, deren Inhalt sich aber lange nicht mehr aendert. Solche Feeds bestehen den Status-/has_ips-Check, halten ihre IPs aber kuenstlich auf voller Aktualitaet und entgehen so dem Score-Decay → Risiko veralteter Dauer-Blocks. Flag ist **advisory**, kein Auto-Remove.

## ⚠️ 2 moeglicherweise eingefrorene(r) Feed(s)

| Feed | Tage unveraendert | Seit | IPs (Sample) | Typ | URL |
|---|---|---|---|---|---|
| `black_mirror` | 15 | 2026-10-02 08:29 CEST (Europe/Berlin) | ~1577401 | normal | https://github.com/T145/black-mirror/releases/download/latest/BLOCK_IPV4.txt |
| `ultimate_hosts_ips0` | 14 | 2026-10-03 07:56 CEST (Europe/Berlin) | ~144537 | normal | https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/refs/heads/master/ips/ips0.list |

Hinweis: Kleine kuratierte Listen aendern sich legitim selten – ein Flag hier ist nicht automatisch ein Defekt. Bei DataPlane-Feeds (taegliches Honeypot-Signal) ist ein eingefrorener Stand dagegen ein echtes Alarmsignal. Der Fingerprint basiert auf dem 2-MB-Sample (wie sample_ips); bei sehr grossen Feeds ist er eine Praefix-Heuristik.

*Generiert: 2026-10-18 07:17 CEST (Europe/Berlin)*