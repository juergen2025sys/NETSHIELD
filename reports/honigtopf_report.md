# Honigtopf – Report
**Aktualisiert:** 2026-10-06 10:09 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 10:09 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,456** |
| Bad Hosts – SIP | **163** |
| Bad Hosts – SSH | **3,747** |
| Bad Hosts – SNMP | **414** |
| Bad Hosts – MSSQL | **512** |
| Bad Hosts – RDP | **892** |
| Bad Hosts – HTTP | **3,681** |
| Bad Hosts – TFTP | **215** |
| Bad Hosts – VNC | **392** |
| Bad Hosts – Telnet | **2,612** |
| Bad Hosts – MySQL | **596** |
| Bad Hosts – Memcached | **228** |
| Bad Hosts – ProConOs | **134** |
| Bad Hosts – Kubernetes | **820** |
| Bad Hosts – Redis | **454** |
| Bad Hosts – PostgreSQL | **519** |
| Bad Hosts – FTP | **582** |
| Bad Hosts – CouchDB | **384** |
| Bad Hosts – ClickhouseHTTP | **369** |
| Bad Hosts – Elasticsearch | **688** |
| Bad Hosts – Oracle | **252** |
| Bad Hosts – Modbus | **208** |
| Bad Hosts – LDAP | **253** |
| Bad Hosts – MQTT | **228** |
| Bad Hosts – IPP | **116** |
| Bad Hosts – RAW | **125** |
| Bad Hosts – HashCountRandom | **120** |
| Bad Hosts – LPD | **80** |
| Bad Hosts – MOTD | **75** |
| Bad Hosts – Echo | **6** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **5,169** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **5,169** |
| 2026-10-05 | **6,287** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,246** |
| Kandidaten dieses Abrufs | **14,246** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+279** |
| Entfernt | **-296** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 10:09 CEST (Berlin)*