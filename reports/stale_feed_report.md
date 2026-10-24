# NETSHIELD – Stale-Feed-Report
**Aktualisiert:** 2026-10-24 07:15 CEST (Europe/Berlin)
**Schwelle:** IP-Menge ≥ 14 Tage unveraendert

Erkennt Feeds, die zwar antworten und IPs liefern, deren Inhalt sich aber lange nicht mehr aendert. Solche Feeds bestehen den Status-/has_ips-Check, halten ihre IPs aber kuenstlich auf voller Aktualitaet und entgehen so dem Score-Decay → Risiko veralteter Dauer-Blocks. Flag ist **advisory**, kein Auto-Remove.

## ⚠️ 3 moeglicherweise eingefrorene(r) Feed(s)

| Feed | Tage unveraendert | Seit | IPs (Sample) | Typ | URL |
|---|---|---|---|---|---|
| `black_mirror` | 21 | 2026-10-02 08:29 CEST (Europe/Berlin) | ~1577401 | normal | https://github.com/T145/black-mirror/releases/download/latest/BLOCK_IPV4.txt |
| `ultimate_hosts_ips0` | 20 | 2026-10-03 07:56 CEST (Europe/Berlin) | ~144537 | normal | https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/refs/heads/master/ips/ips0.list |
| `amitambekar_threats_aa` | 17 | 2026-10-06 09:02 CEST (Europe/Berlin) | ~40404 | normal | https://raw.githubusercontent.com/amitambekar510/Malicious-IP-Threat-List/main/Malicious-IP-Threat-List_aa |

Hinweis: Kleine kuratierte Listen aendern sich legitim selten – ein Flag hier ist nicht automatisch ein Defekt. Bei DataPlane-Feeds (taegliches Honeypot-Signal) ist ein eingefrorener Stand dagegen ein echtes Alarmsignal. Der Fingerprint basiert auf dem 2-MB-Sample (wie sample_ips); bei sehr grossen Feeds ist er eine Praefix-Heuristik.

*Generiert: 2026-10-24 07:15 CEST (Europe/Berlin)*