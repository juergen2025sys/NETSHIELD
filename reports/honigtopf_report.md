# Honigtopf – Report
**Aktualisiert:** 2026-09-26 16:32 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-26 16:32 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,652** |
| Bad Hosts – SIP | **167** |
| Bad Hosts – SSH | **3,099** |
| Bad Hosts – RDP | **984** |
| Bad Hosts – MSSQL | **444** |
| Bad Hosts – HTTP | **2,981** |
| Bad Hosts – SNMP | **381** |
| Bad Hosts – TFTP | **185** |
| Bad Hosts – VNC | **394** |
| Bad Hosts – ProConOs | **210** |
| Bad Hosts – Telnet | **3,065** |
| Bad Hosts – PostgreSQL | **602** |
| Bad Hosts – MySQL | **616** |
| Bad Hosts – FTP | **503** |
| Bad Hosts – Kubernetes | **733** |
| Bad Hosts – Redis | **466** |
| Bad Hosts – Elasticsearch | **506** |
| Bad Hosts – ClickhouseHTTP | **261** |
| Bad Hosts – CouchDB | **212** |
| Bad Hosts – Oracle | **322** |
| Bad Hosts – Modbus | **213** |
| Bad Hosts – Memcached | **223** |
| Bad Hosts – RAW | **173** |
| Bad Hosts – MQTT | **228** |
| Bad Hosts – IPP | **82** |
| Bad Hosts – LDAP | **214** |
| Bad Hosts – LPD | **46** |
| Bad Hosts – HashCountRandom | **34** |
| Bad Hosts – MOTD | **52** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-26)**: **7,335** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-26 | **7,335** |
| 2026-09-25 | **3,317** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,286** |
| Kandidaten dieses Abrufs | **13,286** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+633** |
| Entfernt | **-981** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-26 16:32 CEST (Berlin)*