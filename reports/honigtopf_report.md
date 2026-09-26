# Honigtopf – Report
**Aktualisiert:** 2026-09-26 08:37 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-26 08:37 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,035** |
| Bad Hosts – SIP | **142** |
| Bad Hosts – SSH | **3,003** |
| Bad Hosts – RDP | **875** |
| Bad Hosts – MSSQL | **448** |
| Bad Hosts – HTTP | **3,643** |
| Bad Hosts – SNMP | **396** |
| Bad Hosts – TFTP | **175** |
| Bad Hosts – VNC | **380** |
| Bad Hosts – ProConOs | **200** |
| Bad Hosts – Telnet | **2,947** |
| Bad Hosts – PostgreSQL | **548** |
| Bad Hosts – MySQL | **595** |
| Bad Hosts – FTP | **503** |
| Bad Hosts – Kubernetes | **700** |
| Bad Hosts – Elasticsearch | **501** |
| Bad Hosts – Redis | **467** |
| Bad Hosts – CouchDB | **223** |
| Bad Hosts – ClickhouseHTTP | **241** |
| Bad Hosts – Oracle | **323** |
| Bad Hosts – Modbus | **197** |
| Bad Hosts – Memcached | **206** |
| Bad Hosts – MQTT | **240** |
| Bad Hosts – RAW | **156** |
| Bad Hosts – LDAP | **226** |
| Bad Hosts – IPP | **88** |
| Bad Hosts – LPD | **57** |
| Bad Hosts – HashCountRandom | **36** |
| Bad Hosts – MOTD | **38** |
| Bad Hosts – Echo | **6** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-26)**: **3,654** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-26 | **3,654** |
| 2026-09-25 | **7,381** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,569** |
| Kandidaten dieses Abrufs | **13,569** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+433** |
| Entfernt | **-422** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-26 08:37 CEST (Berlin)*