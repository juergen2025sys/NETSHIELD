# Honigtopf – Report
**Aktualisiert:** 2026-10-06 09:30 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 09:30 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,455** |
| Bad Hosts – SSH | **3,727** |
| Bad Hosts – SIP | **164** |
| Bad Hosts – SNMP | **417** |
| Bad Hosts – MSSQL | **511** |
| Bad Hosts – RDP | **891** |
| Bad Hosts – HTTP | **3,681** |
| Bad Hosts – VNC | **380** |
| Bad Hosts – TFTP | **219** |
| Bad Hosts – Telnet | **2,629** |
| Bad Hosts – MySQL | **588** |
| Bad Hosts – Memcached | **210** |
| Bad Hosts – ProConOs | **132** |
| Bad Hosts – Kubernetes | **819** |
| Bad Hosts – Redis | **449** |
| Bad Hosts – PostgreSQL | **547** |
| Bad Hosts – FTP | **555** |
| Bad Hosts – CouchDB | **392** |
| Bad Hosts – Elasticsearch | **697** |
| Bad Hosts – ClickhouseHTTP | **361** |
| Bad Hosts – Oracle | **262** |
| Bad Hosts – LDAP | **253** |
| Bad Hosts – Modbus | **209** |
| Bad Hosts – MQTT | **234** |
| Bad Hosts – IPP | **119** |
| Bad Hosts – RAW | **127** |
| Bad Hosts – HashCountRandom | **120** |
| Bad Hosts – LPD | **82** |
| Bad Hosts – MOTD | **78** |
| Bad Hosts – Echo | **6** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **4,796** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **4,796** |
| 2026-10-05 | **6,659** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,263** |
| Kandidaten dieses Abrufs | **14,263** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+211** |
| Entfernt | **-172** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 09:30 CEST (Berlin)*