# Honigtopf – Report
**Aktualisiert:** 2026-10-05 23:17 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 23:17 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,332** |
| Bad Hosts – SSH | **3,943** |
| Bad Hosts – SIP | **174** |
| Bad Hosts – SNMP | **422** |
| Bad Hosts – RDP | **820** |
| Bad Hosts – MSSQL | **475** |
| Bad Hosts – HTTP | **3,398** |
| Bad Hosts – MySQL | **591** |
| Bad Hosts – Telnet | **2,654** |
| Bad Hosts – VNC | **349** |
| Bad Hosts – ProConOs | **122** |
| Bad Hosts – TFTP | **203** |
| Bad Hosts – Kubernetes | **776** |
| Bad Hosts – PostgreSQL | **493** |
| Bad Hosts – Memcached | **187** |
| Bad Hosts – FTP | **515** |
| Bad Hosts – Redis | **420** |
| Bad Hosts – Elasticsearch | **664** |
| Bad Hosts – ClickhouseHTTP | **372** |
| Bad Hosts – CouchDB | **357** |
| Bad Hosts – LDAP | **229** |
| Bad Hosts – Oracle | **282** |
| Bad Hosts – Modbus | **206** |
| Bad Hosts – MQTT | **205** |
| Bad Hosts – RAW | **110** |
| Bad Hosts – IPP | **85** |
| Bad Hosts – HashCountRandom | **82** |
| Bad Hosts – LPD | **56** |
| Bad Hosts – MOTD | **72** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **10,512** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **10,512** |
| 2026-10-04 | **820** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,011** |
| Kandidaten dieses Abrufs | **14,011** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+882** |
| Entfernt | **-919** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 23:17 CEST (Berlin)*