# Honigtopf – Report
**Aktualisiert:** 2026-10-01 21:28 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-01 21:28 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,545** |
| Bad Hosts – SIP | **168** |
| Bad Hosts – SSH | **3,441** |
| Bad Hosts – RDP | **669** |
| Bad Hosts – MSSQL | **469** |
| Bad Hosts – HTTP | **3,132** |
| Bad Hosts – SNMP | **395** |
| Bad Hosts – VNC | **302** |
| Bad Hosts – MySQL | **626** |
| Bad Hosts – FTP | **520** |
| Bad Hosts – Telnet | **2,992** |
| Bad Hosts – ProConOs | **132** |
| Bad Hosts – TFTP | **193** |
| Bad Hosts – PostgreSQL | **344** |
| Bad Hosts – Kubernetes | **595** |
| Bad Hosts – Redis | **374** |
| Bad Hosts – Elasticsearch | **586** |
| Bad Hosts – CouchDB | **258** |
| Bad Hosts – ClickhouseHTTP | **269** |
| Bad Hosts – Oracle | **255** |
| Bad Hosts – Modbus | **190** |
| Bad Hosts – Memcached | **176** |
| Bad Hosts – LDAP | **174** |
| Bad Hosts – MQTT | **178** |
| Bad Hosts – IPP | **100** |
| Bad Hosts – RAW | **82** |
| Bad Hosts – LPD | **70** |
| Bad Hosts – HashCountRandom | **114** |
| Bad Hosts – MOTD | **68** |
| Bad Hosts – Echo | **6** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-01)**: **8,806** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-01 | **8,806** |
| 2026-09-30 | **1,739** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,274** |
| Kandidaten dieses Abrufs | **13,274** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+107** |
| Entfernt | **-109** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-01 21:28 CEST (Berlin)*