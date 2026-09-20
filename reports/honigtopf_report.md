# Honigtopf – Report
**Aktualisiert:** 2026-09-20 19:30 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-20 19:30 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **21,611** |
| Bad Hosts – RDP | **1,014** |
| Bad Hosts – MSSQL | **668** |
| Bad Hosts – SSH | **4,727** |
| Bad Hosts – SIP | **211** |
| Bad Hosts – SNMP | **431** |
| Bad Hosts – VNC | **1,689** |
| Bad Hosts – HTTP | **3,810** |
| Bad Hosts – FTP | **7,910** |
| Bad Hosts – TFTP | **293** |
| Bad Hosts – MySQL | **441** |
| Bad Hosts – Telnet | **2,869** |
| Bad Hosts – ProConOs | **124** |
| Bad Hosts – PostgreSQL | **521** |
| Bad Hosts – Kubernetes | **697** |
| Bad Hosts – Elasticsearch | **485** |
| Bad Hosts – Redis | **320** |
| Bad Hosts – CouchDB | **186** |
| Bad Hosts – Memcached | **255** |
| Bad Hosts – Oracle | **278** |
| Bad Hosts – MQTT | **220** |
| Bad Hosts – LDAP | **239** |
| Bad Hosts – ClickhouseHTTP | **213** |
| Bad Hosts – Modbus | **201** |
| Bad Hosts – RAW | **167** |
| Bad Hosts – HashCountRandom | **60** |
| Bad Hosts – IPP | **83** |
| Bad Hosts – LPD | **70** |
| Bad Hosts – MOTD | **58** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-20)**: **11,746** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-20 | **11,746** |
| 2026-09-19 | **9,865** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **24,349** |
| Kandidaten dieses Abrufs | **24,349** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+431** |
| Entfernt | **-6,194** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-20 19:30 CEST (Berlin)*