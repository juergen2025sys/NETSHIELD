# NETSHIELD – Dead-Feed-Report
**Aktualisiert:** 2026-09-26 07:43 CEST (Europe/Berlin)
**Schwelle:** 3 Fehl-Laeufe in Folge (Daily-Cron → 3 Tage)

## ❌ 3 tote Feed(s) – manueller Fix noetig

| Feed | Fehl-Laeufe | Seit | Letzter Status | URL |
|---|---|---|---|---|
| `abuseipdb_tmiland` | 16 | 2026-09-11 07:28 CEST (Europe/Berlin) | <urlopen error timed out> | https://abuseipdb.tmiland.com/abuseipdb.txt |
| `fortigate_azure` | 6 | 2026-09-21 07:44 CEST (Europe/Berlin) | 404 | https://raw.githubusercontent.com/IT3ngineer/FortigateBlockList/refs/heads/main/AzureBlockListIPs.txt |
| `edanwong` | 4 | 2026-09-23 07:24 CEST (Europe/Berlin) | 404 | https://raw.githubusercontent.com/EdanWong/ip_list/refs/heads/main/my_ips.txt |

Hinweis: GitHub-raw-Feeds werden bei einem 404 zusaetzlich vom Move-Resolver automatisch im Repo gesucht. Steht ein Feed hier, ist die Datei dort entweder weg oder die Quelle ist keine GitHub-raw-URL (Webseite) – dann hilft nur eine neue URL.

*Generiert: 2026-09-26 07:43 CEST (Europe/Berlin)*