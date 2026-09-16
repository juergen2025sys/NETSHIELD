# Honigtopf – Report
**Aktualisiert:** 2026-09-16 02:28 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-16 02:28 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **47,581** |
| Bad Hosts – SIP | **189** |
| Bad Hosts – RDP | **1,260** |
| Bad Hosts – SSH | **4,077** |
| Bad Hosts – MSSQL | **576** |
| Bad Hosts – HTTP | **5,024** |
| Bad Hosts – FTP | **33,647** |
| Bad Hosts – VNC | **1,639** |
| Bad Hosts – SNMP | **506** |
| Bad Hosts – TFTP | **217** |
| Bad Hosts – ProConOs | **227** |
| Bad Hosts – Telnet | **3,380** |
| Bad Hosts – MySQL | **751** |
| Bad Hosts – PostgreSQL | **606** |
| Bad Hosts – Kubernetes | **749** |
| Bad Hosts – Redis | **478** |
| Bad Hosts – CouchDB | **257** |
| Bad Hosts – Elasticsearch | **507** |
| Bad Hosts – ClickhouseHTTP | **369** |
| Bad Hosts – Oracle | **326** |
| Bad Hosts – Memcached | **229** |
| Bad Hosts – Modbus | **228** |
| Bad Hosts – LDAP | **234** |
| Bad Hosts – HashCountRandom | **282** |
| Bad Hosts – MQTT | **269** |
| Bad Hosts – RAW | **183** |
| Bad Hosts – IPP | **143** |
| Bad Hosts – LPD | **93** |
| Bad Hosts – MOTD | **67** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-16)**: **804** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-16 | **804** |
| 2026-09-15 | **46,777** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **51,071** |
| Kandidaten dieses Abrufs | **51,071** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+698** |
| Entfernt | **-1,463** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-16 02:28 CEST (Berlin)*