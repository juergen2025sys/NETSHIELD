# Honigtopf – Report
**Aktualisiert:** 2026-10-03 10:16 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-03 10:16 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,285** |
| Bad Hosts – SIP | **154** |
| Bad Hosts – VNC | **314** |
| Bad Hosts – SSH | **2,846** |
| Bad Hosts – MSSQL | **496** |
| Bad Hosts – SNMP | **409** |
| Bad Hosts – RDP | **825** |
| Bad Hosts – HTTP | **4,294** |
| Bad Hosts – MySQL | **624** |
| Bad Hosts – Telnet | **2,989** |
| Bad Hosts – ProConOs | **157** |
| Bad Hosts – TFTP | **204** |
| Bad Hosts – PostgreSQL | **550** |
| Bad Hosts – CouchDB | **329** |
| Bad Hosts – Kubernetes | **694** |
| Bad Hosts – Redis | **493** |
| Bad Hosts – FTP | **511** |
| Bad Hosts – Elasticsearch | **563** |
| Bad Hosts – Oracle | **304** |
| Bad Hosts – ClickhouseHTTP | **307** |
| Bad Hosts – Modbus | **210** |
| Bad Hosts – RAW | **129** |
| Bad Hosts – LDAP | **230** |
| Bad Hosts – Memcached | **218** |
| Bad Hosts – MQTT | **181** |
| Bad Hosts – IPP | **104** |
| Bad Hosts – LPD | **60** |
| Bad Hosts – HashCountRandom | **94** |
| Bad Hosts – MOTD | **32** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Echo | **6** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-03)**: **4,429** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-03 | **4,429** |
| 2026-10-02 | **6,856** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,276** |
| Kandidaten dieses Abrufs | **14,276** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+658** |
| Entfernt | **-1,363** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-03 10:16 CEST (Berlin)*