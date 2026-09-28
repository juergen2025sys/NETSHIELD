# Honigtopf – Report
**Aktualisiert:** 2026-09-28 09:14 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-28 09:14 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **9,603** |
| Bad Hosts – SIP | **140** |
| Bad Hosts – SSH | **3,373** |
| Bad Hosts – RDP | **780** |
| Bad Hosts – MSSQL | **477** |
| Bad Hosts – SNMP | **297** |
| Bad Hosts – VNC | **352** |
| Bad Hosts – HTTP | **1,934** |
| Bad Hosts – PostgreSQL | **394** |
| Bad Hosts – TFTP | **151** |
| Bad Hosts – Telnet | **2,773** |
| Bad Hosts – ProConOs | **122** |
| Bad Hosts – FTP | **242** |
| Bad Hosts – MySQL | **293** |
| Bad Hosts – Kubernetes | **747** |
| Bad Hosts – Elasticsearch | **552** |
| Bad Hosts – CouchDB | **238** |
| Bad Hosts – Redis | **371** |
| Bad Hosts – Oracle | **188** |
| Bad Hosts – ClickhouseHTTP | **240** |
| Bad Hosts – Modbus | **148** |
| Bad Hosts – LDAP | **229** |
| Bad Hosts – IPP | **91** |
| Bad Hosts – HashCountRandom | **26** |
| Bad Hosts – RAW | **136** |
| Bad Hosts – MQTT | **173** |
| Bad Hosts – Memcached | **183** |
| Bad Hosts – LPD | **51** |
| Bad Hosts – MOTD | **22** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-28)**: **3,002** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-28 | **3,002** |
| 2026-09-27 | **6,601** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **11,735** |
| Kandidaten dieses Abrufs | **11,735** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,273** |
| Entfernt | **-3,195** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-28 09:14 CEST (Berlin)*