# Honigtopf – Report
**Aktualisiert:** 2026-10-06 04:02 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 04:02 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,334** |
| Bad Hosts – SSH | **3,817** |
| Bad Hosts – SIP | **177** |
| Bad Hosts – SNMP | **431** |
| Bad Hosts – RDP | **833** |
| Bad Hosts – MSSQL | **520** |
| Bad Hosts – HTTP | **3,539** |
| Bad Hosts – MySQL | **587** |
| Bad Hosts – Telnet | **2,650** |
| Bad Hosts – VNC | **346** |
| Bad Hosts – Memcached | **189** |
| Bad Hosts – ProConOs | **115** |
| Bad Hosts – TFTP | **203** |
| Bad Hosts – Kubernetes | **717** |
| Bad Hosts – PostgreSQL | **561** |
| Bad Hosts – Redis | **451** |
| Bad Hosts – FTP | **537** |
| Bad Hosts – Elasticsearch | **667** |
| Bad Hosts – ClickhouseHTTP | **367** |
| Bad Hosts – CouchDB | **366** |
| Bad Hosts – LDAP | **244** |
| Bad Hosts – Oracle | **283** |
| Bad Hosts – Modbus | **202** |
| Bad Hosts – MQTT | **228** |
| Bad Hosts – RAW | **128** |
| Bad Hosts – IPP | **104** |
| Bad Hosts – HashCountRandom | **84** |
| Bad Hosts – LPD | **72** |
| Bad Hosts – MOTD | **71** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **1,694** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **1,694** |
| 2026-10-05 | **9,640** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,079** |
| Kandidaten dieses Abrufs | **14,079** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+462** |
| Entfernt | **-492** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 04:02 CEST (Berlin)*