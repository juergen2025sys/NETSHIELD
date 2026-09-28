# Honigtopf – Report
**Aktualisiert:** 2026-09-28 23:56 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-28 23:56 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **8,207** |
| Bad Hosts – SIP | **138** |
| Bad Hosts – RDP | **644** |
| Bad Hosts – SSH | **2,742** |
| Bad Hosts – MSSQL | **481** |
| Bad Hosts – VNC | **253** |
| Bad Hosts – SNMP | **274** |
| Bad Hosts – HTTP | **1,835** |
| Bad Hosts – ProConOs | **153** |
| Bad Hosts – Telnet | **2,320** |
| Bad Hosts – TFTP | **137** |
| Bad Hosts – PostgreSQL | **365** |
| Bad Hosts – MySQL | **296** |
| Bad Hosts – Kubernetes | **653** |
| Bad Hosts – FTP | **207** |
| Bad Hosts – Elasticsearch | **466** |
| Bad Hosts – Redis | **281** |
| Bad Hosts – CouchDB | **183** |
| Bad Hosts – LDAP | **208** |
| Bad Hosts – ClickhouseHTTP | **282** |
| Bad Hosts – Oracle | **216** |
| Bad Hosts – RAW | **142** |
| Bad Hosts – MQTT | **201** |
| Bad Hosts – Modbus | **166** |
| Bad Hosts – Memcached | **151** |
| Bad Hosts – IPP | **109** |
| Bad Hosts – HashCountRandom | **59** |
| Bad Hosts – LPD | **61** |
| Bad Hosts – MOTD | **57** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-28)**: **7,565** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-28 | **7,565** |
| 2026-09-27 | **642** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **10,275** |
| Kandidaten dieses Abrufs | **10,275** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,006** |
| Entfernt | **-1,308** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-28 23:56 CEST (Berlin)*