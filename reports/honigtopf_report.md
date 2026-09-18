# Honigtopf – Report
**Aktualisiert:** 2026-09-18 16:30 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 16:30 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **39,724** |
| Bad Hosts – SIP | **171** |
| Bad Hosts – MSSQL | **898** |
| Bad Hosts – VNC | **1,612** |
| Bad Hosts – SSH | **3,829** |
| Bad Hosts – RDP | **1,140** |
| Bad Hosts – SNMP | **447** |
| Bad Hosts – HTTP | **4,452** |
| Bad Hosts – TFTP | **243** |
| Bad Hosts – FTP | **26,570** |
| Bad Hosts – Telnet | **2,999** |
| Bad Hosts – ProConOs | **165** |
| Bad Hosts – PostgreSQL | **543** |
| Bad Hosts – MySQL | **670** |
| Bad Hosts – Kubernetes | **743** |
| Bad Hosts – Redis | **406** |
| Bad Hosts – Elasticsearch | **406** |
| Bad Hosts – CouchDB | **249** |
| Bad Hosts – Oracle | **295** |
| Bad Hosts – ClickhouseHTTP | **273** |
| Bad Hosts – RAW | **286** |
| Bad Hosts – LDAP | **242** |
| Bad Hosts – Modbus | **164** |
| Bad Hosts – Memcached | **239** |
| Bad Hosts – MQTT | **241** |
| Bad Hosts – IPP | **91** |
| Bad Hosts – HashCountRandom | **182** |
| Bad Hosts – LPD | **85** |
| Bad Hosts – MOTD | **56** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **23,496** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **23,496** |
| 2026-09-17 | **16,228** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **43,268** |
| Kandidaten dieses Abrufs | **43,268** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+3,087** |
| Entfernt | **-3,200** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 16:30 CEST (Berlin)*