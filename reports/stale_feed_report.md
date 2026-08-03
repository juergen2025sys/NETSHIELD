# NETSHIELD – Stale-Feed-Report
**Aktualisiert:** 2026-08-03 04:24 UTC
**Schwelle:** IP-Menge ≥ 14 Tage unveraendert

Erkennt Feeds, die zwar antworten und IPs liefern, deren Inhalt sich aber lange nicht mehr aendert. Solche Feeds bestehen den Status-/has_ips-Check, halten ihre IPs aber kuenstlich auf voller Aktualitaet und entgehen so dem Score-Decay → Risiko veralteter Dauer-Blocks. Flag ist **advisory**, kein Auto-Remove.

## ⚠️ 20 moeglicherweise eingefrorene(r) Feed(s)

| Feed | Tage unveraendert | Seit | IPs (Sample) | Typ | URL |
|---|---|---|---|---|---|
| `amitambekar_threats` | 50 | 2026-06-13 15:54 UTC | ~139988 | normal | https://raw.githubusercontent.com/amitambekar510/Malicious-IP-Threat-List/refs/heads/main/Malicious-IP-Threat-List.txt |
| `bbcan177` | 50 | 2026-06-13 15:54 UTC | ~1258 | normal | https://gist.githubusercontent.com/BBcan177/d7105c242f17f4498f81/raw |
| `binaryedge_scanners` | 50 | 2026-06-13 15:54 UTC | ~16857 | normal | https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt |
| `blacksnowdot_packets` | 50 | 2026-06-13 15:54 UTC | ~24497 | normal | https://raw.githubusercontent.com/BlacKSnowDot0/packetsdatabase-db/refs/heads/main/ip_list.txt |
| `cloudzy` | 50 | 2026-06-13 15:54 UTC | ~3578 | normal | https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/cloudzy.txt |
| `et_block` | 50 | 2026-06-13 15:54 UTC | ~5 | normal | https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt |
| `feodo_aggressive` | 50 | 2026-06-13 15:54 UTC | ~7607 | normal | https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt |
| `feodo_recommended` | 50 | 2026-06-13 15:54 UTC | ~5 | normal | https://feodotracker.abuse.ch/downloads/ipblocklist.txt |
| `firehol_level1` | 50 | 2026-06-13 15:54 UTC | ~1 | normal | https://iplists.firehol.org/files/firehol_level1.netset |
| `l7_ddos` | 50 | 2026-06-13 15:54 UTC | ~1138 | normal | https://raw.githubusercontent.com/Tizian-Maxime-Weigt/L7-HTTP-DDoS-Flood-IP-Signature-IP-List/refs/heads/main/ddos-signatures.txt |
| `littlejake_all_blacklist` | 50 | 2026-06-13 15:54 UTC | ~13543 | normal | https://cdn.jsdelivr.net/gh/LittleJake/ip-blacklist/all_blacklist.txt |
| `nixbear_malicious` | 50 | 2026-06-13 15:54 UTC | ~8136 | normal | https://raw.githubusercontent.com/nixbear/malicious_ips/refs/heads/main/malicious_ips.txt |
| `stopforumspam_toxic` | 50 | 2026-06-13 15:54 UTC | ~4 | normal | https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt |
| `subnet_blocklist_new` | 50 | 2026-06-13 15:54 UTC | ~37 | normal | https://raw.githubusercontent.com/coyote-nl/blocklist/refs/heads/main/subnet-blocklist-new |
| `cyna_malicious` | 45 | 2026-06-18 05:49 UTC | ~4823 | normal | https://raw.githubusercontent.com/cybersecurity-cyna/Malicious_IP/refs/heads/main/ip-list.txt |
| `florent_banned` | 41 | 2026-06-22 06:22 UTC | ~10563 | normal | https://raw.githubusercontent.com/florentvinai/bad-ips-on-my-vps/refs/heads/main/banned_ips.txt |
| `ashleykleynhans_abuseipdb` | 31 | 2026-07-02 04:53 UTC | ~10305 | normal | https://raw.githubusercontent.com/ashleykleynhans/ipset/refs/heads/main/ipv4.csv |
| `firehol_cybercrime` | 24 | 2026-07-09 04:43 UTC | ~373 | normal | https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/cybercrime.ipset |
| `firehol_webclient` | 24 | 2026-07-09 04:43 UTC | ~373 | normal | https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset |
| `neblink_known_scanners` | 17 | 2026-07-17 03:55 UTC | ~4969 | normal | https://blocklist.neblink.net/KnownScanners.txt |

Hinweis: Kleine kuratierte Listen aendern sich legitim selten – ein Flag hier ist nicht automatisch ein Defekt. Bei DataPlane-Feeds (taegliches Honeypot-Signal) ist ein eingefrorener Stand dagegen ein echtes Alarmsignal. Der Fingerprint basiert auf dem 2-MB-Sample (wie sample_ips); bei sehr grossen Feeds ist er eine Praefix-Heuristik.

*Generiert: 2026-08-03 04:24 UTC*