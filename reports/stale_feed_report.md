# NETSHIELD – Stale-Feed-Report
**Aktualisiert:** 2026-11-25 10:25 CET (Europe/Berlin)
**Schwelle:** IP-Menge ≥ 14 Tage unveraendert

Erkennt Feeds, die zwar antworten und IPs liefern, deren Inhalt sich aber lange nicht mehr aendert. Solche Feeds bestehen den Status-/has_ips-Check, halten ihre IPs aber kuenstlich auf voller Aktualitaet und entgehen so dem Score-Decay → Risiko veralteter Dauer-Blocks. Flag ist **advisory**, kein Auto-Remove.

## ⚠️ 3 moeglicherweise eingefrorene(r) Feed(s)

| Feed | Tage unveraendert | Seit | IPs (Sample) | Typ | URL |
|---|---|---|---|---|---|
| `ffraud_confirmed` | 21 | 2026-11-04 08:06 CET (Europe/Berlin) | ~964367 | normal | https://raw.githubusercontent.com/FFraud-com/ip-fraud-database/main/threat-ips/confirmed-abusive.csv |
| `firehol_webserver` | 15 | 2026-11-10 08:55 CET (Europe/Berlin) | ~845 | normal | https://iplists.firehol.org/files/firehol_webserver.netset |
| `myip_ms` | 15 | 2026-11-10 08:55 CET (Europe/Berlin) | ~1099 | normal | https://myip.ms/files/blacklist/general/latest_blacklist.txt |

Hinweis: Kleine kuratierte Listen aendern sich legitim selten – ein Flag hier ist nicht automatisch ein Defekt. Bei DataPlane-Feeds (taegliches Honeypot-Signal) ist ein eingefrorener Stand dagegen ein echtes Alarmsignal. Der Fingerprint basiert auf dem 2-MB-Sample (wie sample_ips); bei sehr grossen Feeds ist er eine Praefix-Heuristik.

*Generiert: 2026-11-25 10:25 CET (Europe/Berlin)*