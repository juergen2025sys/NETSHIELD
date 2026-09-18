# Honigtopf – Report
**Aktualisiert:** 2026-09-18 22:53 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 22:53 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **38,499** |
| Bad Hosts – SIP | **180** |
| Bad Hosts – MSSQL | **909** |
| Bad Hosts – SSH | **3,831** |
| Bad Hosts – VNC | **1,607** |
| Bad Hosts – RDP | **1,062** |
| Bad Hosts – SNMP | **439** |
| Bad Hosts – HTTP | **4,480** |
| Bad Hosts – TFTP | **238** |
| Bad Hosts – FTP | **25,609** |
| Bad Hosts – Telnet | **2,919** |
| Bad Hosts – PostgreSQL | **539** |
| Bad Hosts – ProConOs | **158** |
| Bad Hosts – MySQL | **616** |
| Bad Hosts – Kubernetes | **693** |
| Bad Hosts – Redis | **439** |
| Bad Hosts – Elasticsearch | **414** |
| Bad Hosts – CouchDB | **252** |
| Bad Hosts – ClickhouseHTTP | **252** |
| Bad Hosts – Oracle | **238** |
| Bad Hosts – Modbus | **171** |
| Bad Hosts – RAW | **258** |
| Bad Hosts – LDAP | **239** |
| Bad Hosts – MQTT | **218** |
| Bad Hosts – Memcached | **218** |
| Bad Hosts – IPP | **104** |
| Bad Hosts – HashCountRandom | **197** |
| Bad Hosts – LPD | **85** |
| Bad Hosts – MOTD | **55** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **34,969** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **34,969** |
| 2026-09-17 | **3,530** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **41,928** |
| Kandidaten dieses Abrufs | **41,928** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,972** |
| Entfernt | **-2,334** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 22:53 CEST (Berlin)*