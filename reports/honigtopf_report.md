# Honigtopf – Report
**Aktualisiert:** 2026-09-29 10:26 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 10:26 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,366** |
| Bad Hosts – SIP | **165** |
| Bad Hosts – MSSQL | **489** |
| Bad Hosts – SSH | **2,797** |
| Bad Hosts – RDP | **720** |
| Bad Hosts – SNMP | **294** |
| Bad Hosts – HTTP | **4,690** |
| Bad Hosts – VNC | **292** |
| Bad Hosts – ProConOs | **143** |
| Bad Hosts – Telnet | **2,507** |
| Bad Hosts – PostgreSQL | **425** |
| Bad Hosts – TFTP | **189** |
| Bad Hosts – MySQL | **370** |
| Bad Hosts – Kubernetes | **685** |
| Bad Hosts – Elasticsearch | **557** |
| Bad Hosts – FTP | **326** |
| Bad Hosts – Redis | **335** |
| Bad Hosts – CouchDB | **266** |
| Bad Hosts – ClickhouseHTTP | **280** |
| Bad Hosts – LDAP | **186** |
| Bad Hosts – Oracle | **232** |
| Bad Hosts – RAW | **143** |
| Bad Hosts – Modbus | **170** |
| Bad Hosts – MQTT | **189** |
| Bad Hosts – Memcached | **186** |
| Bad Hosts – IPP | **106** |
| Bad Hosts – HashCountRandom | **72** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – LPD | **44** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-29)**: **6,818** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-29 | **6,818** |
| 2026-09-28 | **4,548** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,636** |
| Kandidaten dieses Abrufs | **13,636** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+647** |
| Entfernt | **-473** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 10:26 CEST (Berlin)*