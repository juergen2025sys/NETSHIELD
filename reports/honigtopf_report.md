# Honigtopf – Report
**Aktualisiert:** 2026-10-04 11:16 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 11:16 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,625** |
| Bad Hosts – SIP | **189** |
| Bad Hosts – MSSQL | **454** |
| Bad Hosts – SSH | **3,838** |
| Bad Hosts – SNMP | **409** |
| Bad Hosts – RDP | **722** |
| Bad Hosts – HTTP | **3,010** |
| Bad Hosts – VNC | **266** |
| Bad Hosts – ProConOs | **167** |
| Bad Hosts – MySQL | **573** |
| Bad Hosts – Telnet | **2,632** |
| Bad Hosts – TFTP | **186** |
| Bad Hosts – Redis | **409** |
| Bad Hosts – PostgreSQL | **437** |
| Bad Hosts – CouchDB | **333** |
| Bad Hosts – Kubernetes | **679** |
| Bad Hosts – Elasticsearch | **638** |
| Bad Hosts – FTP | **444** |
| Bad Hosts – ClickhouseHTTP | **321** |
| Bad Hosts – Oracle | **306** |
| Bad Hosts – Memcached | **208** |
| Bad Hosts – Modbus | **161** |
| Bad Hosts – LDAP | **173** |
| Bad Hosts – MQTT | **198** |
| Bad Hosts – RAW | **122** |
| Bad Hosts – IPP | **103** |
| Bad Hosts – LPD | **83** |
| Bad Hosts – HashCountRandom | **56** |
| Bad Hosts – MOTD | **68** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **5,086** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **5,086** |
| 2026-10-03 | **5,539** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,317** |
| Kandidaten dieses Abrufs | **13,317** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+403** |
| Entfernt | **-1,316** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 11:16 CEST (Berlin)*