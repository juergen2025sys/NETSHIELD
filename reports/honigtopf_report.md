# Honigtopf – Report
**Aktualisiert:** 2026-09-21 02:19 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-21 02:19 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **13,904** |
| Bad Hosts – RDP | **1,075** |
| Bad Hosts – SSH | **4,683** |
| Bad Hosts – MSSQL | **618** |
| Bad Hosts – SIP | **208** |
| Bad Hosts – SNMP | **400** |
| Bad Hosts – VNC | **1,511** |
| Bad Hosts – HTTP | **2,392** |
| Bad Hosts – Telnet | **2,923** |
| Bad Hosts – MySQL | **382** |
| Bad Hosts – TFTP | **268** |
| Bad Hosts – ProConOs | **112** |
| Bad Hosts – FTP | **1,787** |
| Bad Hosts – PostgreSQL | **488** |
| Bad Hosts – Kubernetes | **642** |
| Bad Hosts – Redis | **310** |
| Bad Hosts – Elasticsearch | **373** |
| Bad Hosts – Memcached | **236** |
| Bad Hosts – Oracle | **284** |
| Bad Hosts – ClickhouseHTTP | **215** |
| Bad Hosts – CouchDB | **188** |
| Bad Hosts – LDAP | **240** |
| Bad Hosts – RAW | **166** |
| Bad Hosts – Modbus | **198** |
| Bad Hosts – MQTT | **204** |
| Bad Hosts – IPP | **93** |
| Bad Hosts – HashCountRandom | **64** |
| Bad Hosts – LPD | **66** |
| Bad Hosts – MOTD | **56** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-21)**: **487** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-21 | **487** |
| 2026-09-20 | **13,417** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **16,509** |
| Kandidaten dieses Abrufs | **16,509** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+667** |
| Entfernt | **-1,679** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-21 02:19 CEST (Berlin)*