# Honigtopf – Report
**Aktualisiert:** 2026-09-18 19:51 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 19:51 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **39,150** |
| Bad Hosts – SIP | **182** |
| Bad Hosts – MSSQL | **911** |
| Bad Hosts – VNC | **1,622** |
| Bad Hosts – SSH | **3,830** |
| Bad Hosts – RDP | **1,075** |
| Bad Hosts – SNMP | **432** |
| Bad Hosts – HTTP | **4,488** |
| Bad Hosts – TFTP | **240** |
| Bad Hosts – FTP | **26,072** |
| Bad Hosts – Telnet | **2,945** |
| Bad Hosts – ProConOs | **164** |
| Bad Hosts – PostgreSQL | **530** |
| Bad Hosts – MySQL | **657** |
| Bad Hosts – Kubernetes | **715** |
| Bad Hosts – Redis | **413** |
| Bad Hosts – Elasticsearch | **430** |
| Bad Hosts – CouchDB | **244** |
| Bad Hosts – Oracle | **271** |
| Bad Hosts – ClickhouseHTTP | **239** |
| Bad Hosts – Modbus | **159** |
| Bad Hosts – RAW | **266** |
| Bad Hosts – LDAP | **235** |
| Bad Hosts – Memcached | **232** |
| Bad Hosts – MQTT | **231** |
| Bad Hosts – HashCountRandom | **226** |
| Bad Hosts – IPP | **93** |
| Bad Hosts – LPD | **77** |
| Bad Hosts – MOTD | **54** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **29,813** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **29,813** |
| 2026-09-17 | **9,337** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **42,478** |
| Kandidaten dieses Abrufs | **42,478** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,551** |
| Entfernt | **-5,352** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 19:51 CEST (Berlin)*