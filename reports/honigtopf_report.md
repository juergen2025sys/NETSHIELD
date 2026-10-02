# Honigtopf – Report
**Aktualisiert:** 2026-10-02 17:00 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 17:00 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,602** |
| Bad Hosts – SIP | **162** |
| Bad Hosts – SSH | **3,004** |
| Bad Hosts – SNMP | **385** |
| Bad Hosts – MSSQL | **530** |
| Bad Hosts – VNC | **455** |
| Bad Hosts – HTTP | **3,438** |
| Bad Hosts – RDP | **822** |
| Bad Hosts – MySQL | **612** |
| Bad Hosts – ProConOs | **227** |
| Bad Hosts – Telnet | **3,005** |
| Bad Hosts – FTP | **572** |
| Bad Hosts – TFTP | **195** |
| Bad Hosts – PostgreSQL | **389** |
| Bad Hosts – Kubernetes | **855** |
| Bad Hosts – CouchDB | **311** |
| Bad Hosts – Redis | **382** |
| Bad Hosts – Elasticsearch | **525** |
| Bad Hosts – ClickhouseHTTP | **272** |
| Bad Hosts – Oracle | **257** |
| Bad Hosts – Modbus | **227** |
| Bad Hosts – MQTT | **230** |
| Bad Hosts – Memcached | **230** |
| Bad Hosts – LDAP | **186** |
| Bad Hosts – RAW | **120** |
| Bad Hosts – IPP | **109** |
| Bad Hosts – HashCountRandom | **132** |
| Bad Hosts – LPD | **93** |
| Bad Hosts – MOTD | **44** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **7,265** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **7,265** |
| 2026-10-01 | **3,337** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,455** |
| Kandidaten dieses Abrufs | **13,455** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+305** |
| Entfernt | **-392** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 17:00 CEST (Berlin)*