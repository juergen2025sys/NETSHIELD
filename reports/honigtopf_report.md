# Honigtopf – Report
**Aktualisiert:** 2026-10-04 19:09 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 19:09 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,439** |
| Bad Hosts – SIP | **189** |
| Bad Hosts – SSH | **3,929** |
| Bad Hosts – SNMP | **417** |
| Bad Hosts – MSSQL | **437** |
| Bad Hosts – RDP | **679** |
| Bad Hosts – HTTP | **2,662** |
| Bad Hosts – VNC | **319** |
| Bad Hosts – Telnet | **2,689** |
| Bad Hosts – ProConOs | **164** |
| Bad Hosts – MySQL | **476** |
| Bad Hosts – TFTP | **186** |
| Bad Hosts – Redis | **433** |
| Bad Hosts – FTP | **408** |
| Bad Hosts – PostgreSQL | **500** |
| Bad Hosts – CouchDB | **323** |
| Bad Hosts – Kubernetes | **654** |
| Bad Hosts – Elasticsearch | **532** |
| Bad Hosts – ClickhouseHTTP | **364** |
| Bad Hosts – Oracle | **290** |
| Bad Hosts – Memcached | **232** |
| Bad Hosts – Modbus | **202** |
| Bad Hosts – MQTT | **219** |
| Bad Hosts – LDAP | **170** |
| Bad Hosts – IPP | **90** |
| Bad Hosts – RAW | **128** |
| Bad Hosts – LPD | **78** |
| Bad Hosts – MOTD | **68** |
| Bad Hosts – HashCountRandom | **36** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **8,036** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **8,036** |
| 2026-10-03 | **2,403** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,086** |
| Kandidaten dieses Abrufs | **13,086** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+809** |
| Entfernt | **-1,618** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 19:09 CEST (Berlin)*