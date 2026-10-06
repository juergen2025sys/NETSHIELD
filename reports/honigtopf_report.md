# Honigtopf – Report
**Aktualisiert:** 2026-10-06 11:04 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 11:04 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,410** |
| Bad Hosts – SIP | **165** |
| Bad Hosts – SSH | **3,728** |
| Bad Hosts – SNMP | **418** |
| Bad Hosts – MSSQL | **512** |
| Bad Hosts – RDP | **865** |
| Bad Hosts – HTTP | **3,652** |
| Bad Hosts – TFTP | **215** |
| Bad Hosts – VNC | **394** |
| Bad Hosts – Telnet | **2,603** |
| Bad Hosts – MySQL | **598** |
| Bad Hosts – Memcached | **235** |
| Bad Hosts – ProConOs | **141** |
| Bad Hosts – Kubernetes | **864** |
| Bad Hosts – Redis | **460** |
| Bad Hosts – PostgreSQL | **508** |
| Bad Hosts – FTP | **578** |
| Bad Hosts – CouchDB | **374** |
| Bad Hosts – ClickhouseHTTP | **371** |
| Bad Hosts – Elasticsearch | **679** |
| Bad Hosts – Oracle | **259** |
| Bad Hosts – Modbus | **196** |
| Bad Hosts – MQTT | **234** |
| Bad Hosts – LDAP | **251** |
| Bad Hosts – RAW | **124** |
| Bad Hosts – IPP | **114** |
| Bad Hosts – HashCountRandom | **122** |
| Bad Hosts – LPD | **79** |
| Bad Hosts – MOTD | **75** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **5,637** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **5,637** |
| 2026-10-05 | **5,773** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,160** |
| Kandidaten dieses Abrufs | **14,160** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+344** |
| Entfernt | **-430** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 11:04 CEST (Berlin)*