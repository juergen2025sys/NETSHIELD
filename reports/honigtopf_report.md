# Honigtopf – Report
**Aktualisiert:** 2026-10-05 23:47 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 23:47 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,320** |
| Bad Hosts – SSH | **3,939** |
| Bad Hosts – SIP | **177** |
| Bad Hosts – SNMP | **426** |
| Bad Hosts – RDP | **816** |
| Bad Hosts – MSSQL | **471** |
| Bad Hosts – HTTP | **3,395** |
| Bad Hosts – MySQL | **599** |
| Bad Hosts – Telnet | **2,658** |
| Bad Hosts – VNC | **346** |
| Bad Hosts – ProConOs | **119** |
| Bad Hosts – TFTP | **204** |
| Bad Hosts – Memcached | **186** |
| Bad Hosts – PostgreSQL | **476** |
| Bad Hosts – Kubernetes | **768** |
| Bad Hosts – Redis | **418** |
| Bad Hosts – FTP | **517** |
| Bad Hosts – Elasticsearch | **668** |
| Bad Hosts – ClickhouseHTTP | **372** |
| Bad Hosts – CouchDB | **356** |
| Bad Hosts – LDAP | **215** |
| Bad Hosts – Oracle | **284** |
| Bad Hosts – Modbus | **208** |
| Bad Hosts – MQTT | **207** |
| Bad Hosts – RAW | **110** |
| Bad Hosts – IPP | **84** |
| Bad Hosts – HashCountRandom | **85** |
| Bad Hosts – LPD | **58** |
| Bad Hosts – MOTD | **73** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **10,650** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **10,650** |
| 2026-10-04 | **670** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,990** |
| Kandidaten dieses Abrufs | **13,990** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+164** |
| Entfernt | **-185** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 23:47 CEST (Berlin)*