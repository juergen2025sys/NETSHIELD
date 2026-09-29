# Honigtopf – Report
**Aktualisiert:** 2026-09-29 03:55 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ unklar (410) – im Pool belassen |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 03:55 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **8,443** |
| Bad Hosts – SIP | **151** |
| Bad Hosts – SSH | **2,645** |
| Bad Hosts – RDP | **623** |
| Bad Hosts – MSSQL | **465** |
| Bad Hosts – SNMP | **263** |
| Bad Hosts – VNC | **269** |
| Bad Hosts – HTTP | **2,413** |
| Bad Hosts – ProConOs | **153** |
| Bad Hosts – Telnet | **2,220** |
| Bad Hosts – TFTP | **149** |
| Bad Hosts – PostgreSQL | **425** |
| Bad Hosts – MySQL | **302** |
| Bad Hosts – Kubernetes | **616** |
| Bad Hosts – Elasticsearch | **497** |
| Bad Hosts – FTP | **230** |
| Bad Hosts – Redis | **283** |
| Bad Hosts – CouchDB | **185** |
| Bad Hosts – LDAP | **173** |
| Bad Hosts – ClickhouseHTTP | **254** |
| Bad Hosts – Oracle | **201** |
| Bad Hosts – Modbus | **165** |
| Bad Hosts – MQTT | **192** |
| Bad Hosts – RAW | **129** |
| Bad Hosts – Memcached | **150** |
| Bad Hosts – HashCountRandom | **67** |
| Bad Hosts – IPP | **106** |
| Bad Hosts – MOTD | **57** |
| Bad Hosts – LPD | **44** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-29)**: **1,578** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-29 | **1,578** |
| 2026-09-28 | **6,865** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **10,658** |
| Kandidaten dieses Abrufs | **10,658** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+671** |
| Entfernt | **-108** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 03:55 CEST (Berlin)*