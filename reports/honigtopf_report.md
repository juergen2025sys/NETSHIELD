# Honigtopf – Report
**Aktualisiert:** 2026-09-26 01:30 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ✅ gültig (HTTP 200) |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-26 01:30 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,007** |
| Bad Hosts – SIP | **174** |
| Bad Hosts – SSH | **3,057** |
| Bad Hosts – RDP | **814** |
| Bad Hosts – MSSQL | **479** |
| Bad Hosts – HTTP | **3,603** |
| Bad Hosts – VNC | **342** |
| Bad Hosts – SNMP | **351** |
| Bad Hosts – TFTP | **207** |
| Bad Hosts – ProConOs | **142** |
| Bad Hosts – Telnet | **2,882** |
| Bad Hosts – PostgreSQL | **427** |
| Bad Hosts – MySQL | **618** |
| Bad Hosts – FTP | **497** |
| Bad Hosts – Kubernetes | **681** |
| Bad Hosts – Elasticsearch | **558** |
| Bad Hosts – Redis | **445** |
| Bad Hosts – CouchDB | **212** |
| Bad Hosts – ClickhouseHTTP | **230** |
| Bad Hosts – Oracle | **264** |
| Bad Hosts – Modbus | **181** |
| Bad Hosts – Memcached | **190** |
| Bad Hosts – MQTT | **186** |
| Bad Hosts – RAW | **120** |
| Bad Hosts – LDAP | **201** |
| Bad Hosts – IPP | **85** |
| Bad Hosts – LPD | **55** |
| Bad Hosts – HashCountRandom | **33** |
| Bad Hosts – MOTD | **19** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-25)**: **10,766** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-26 | **13** |
| 2026-09-25 | **10,766** |
| 2026-09-24 | **228** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,473** |
| Kandidaten dieses Abrufs | **13,473** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+595** |
| Entfernt | **-593** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-26 01:30 CEST (Berlin)*