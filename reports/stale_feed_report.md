# NETSHIELD – Stale-Feed-Report
**Aktualisiert:** 2026-06-29 05:24 UTC
**Schwelle:** IP-Menge ≥ 14 Tage unveraendert

Erkennt Feeds, die zwar antworten und IPs liefern, deren Inhalt sich aber lange nicht mehr aendert. Solche Feeds bestehen den Status-/has_ips-Check, halten ihre IPs aber kuenstlich auf voller Aktualitaet und entgehen so dem Score-Decay → Risiko veralteter Dauer-Blocks. Flag ist **advisory**, kein Auto-Remove.

## ⚠️ 16 moeglicherweise eingefrorene(r) Feed(s)

| Feed | Tage unveraendert | Seit | IPs (Sample) | Typ | URL |
|---|---|---|---|---|---|
| `amitambekar_threats` | 15 | 2026-06-13 15:54 UTC | ~139988 | normal | https://raw.githubusercontent.com/amitambekar510/Malicious-IP-Threat-List/refs/heads/main/Malicious-IP-Threat-List.txt |
| `bbcan177` | 15 | 2026-06-13 15:54 UTC | ~1258 | normal | https://gist.githubusercontent.com/BBcan177/d7105c242f17f4498f81/raw |
| `binaryedge_scanners` | 15 | 2026-06-13 15:54 UTC | ~16857 | normal | https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt |
| `blacksnowdot_packets` | 15 | 2026-06-13 15:54 UTC | ~24497 | normal | https://raw.githubusercontent.com/BlacKSnowDot0/packetsdatabase-db/refs/heads/main/ip_list.txt |
| `cloudzy` | 15 | 2026-06-13 15:54 UTC | ~3578 | normal | https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/cloudzy.txt |
| `et_block` | 15 | 2026-06-13 15:54 UTC | ~5 | normal | https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt |
| `fadouse_worm` | 15 | 2026-06-13 15:54 UTC | ~117 | normal | https://raw.githubusercontent.com/Fadouse/clash-threat-intel/main/clash/generated/worm.txt |
| `feodo_aggressive` | 15 | 2026-06-13 15:54 UTC | ~7607 | normal | https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt |
| `feodo_recommended` | 15 | 2026-06-13 15:54 UTC | ~5 | normal | https://feodotracker.abuse.ch/downloads/ipblocklist.txt |
| `firehol_level1` | 15 | 2026-06-13 15:54 UTC | ~1 | normal | https://iplists.firehol.org/files/firehol_level1.netset |
| `l7_ddos` | 15 | 2026-06-13 15:54 UTC | ~1138 | normal | https://raw.githubusercontent.com/Tizian-Maxime-Weigt/L7-HTTP-DDoS-Flood-IP-Signature-IP-List/refs/heads/main/ddos-signatures.txt |
| `littlejake_all_blacklist` | 15 | 2026-06-13 15:54 UTC | ~13543 | normal | https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/all_blacklist.txt |
| `nixbear_malicious` | 15 | 2026-06-13 15:54 UTC | ~8136 | normal | https://raw.githubusercontent.com/nixbear/malicious_ips/refs/heads/main/malicious_ips.txt |
| `stopforumspam_toxic` | 15 | 2026-06-13 15:54 UTC | ~4 | normal | https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt |
| `subnet_blocklist_new` | 15 | 2026-06-13 15:54 UTC | ~37 | normal | https://raw.githubusercontent.com/coyote-nl/blocklist/refs/heads/main/subnet-blocklist-new |
| `kevinmarx` | 14 | 2026-06-14 05:25 UTC | ~49 | normal | https://kevinmarx.org/malicious-ip-list.txt |

Hinweis: Kleine kuratierte Listen aendern sich legitim selten – ein Flag hier ist nicht automatisch ein Defekt. Bei DataPlane-Feeds (taegliches Honeypot-Signal) ist ein eingefrorener Stand dagegen ein echtes Alarmsignal. Der Fingerprint basiert auf dem 2-MB-Sample (wie sample_ips); bei sehr grossen Feeds ist er eine Praefix-Heuristik.

*Generiert: 2026-06-29 05:24 UTC*