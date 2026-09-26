# Honigtopf – Report
**Aktualisiert:** 2026-09-27 01:21 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-27 01:21 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,690** |
| Bad Hosts – SIP | **163** |
| Bad Hosts – SSH | **3,056** |
| Bad Hosts – RDP | **1,015** |
| Bad Hosts – MSSQL | **446** |
| Bad Hosts – SNMP | **364** |
| Bad Hosts – HTTP | **3,203** |
| Bad Hosts – TFTP | **173** |
| Bad Hosts – PostgreSQL | **607** |
| Bad Hosts – ProConOs | **206** |
| Bad Hosts – Telnet | **2,988** |
| Bad Hosts – MySQL | **647** |
| Bad Hosts – VNC | **394** |
| Bad Hosts – Kubernetes | **727** |
| Bad Hosts – FTP | **516** |
| Bad Hosts – Redis | **441** |
| Bad Hosts – Elasticsearch | **486** |
| Bad Hosts – CouchDB | **262** |
| Bad Hosts – Oracle | **285** |
| Bad Hosts – ClickhouseHTTP | **229** |
| Bad Hosts – RAW | **184** |
| Bad Hosts – Memcached | **238** |
| Bad Hosts – Modbus | **224** |
| Bad Hosts – IPP | **142** |
| Bad Hosts – MQTT | **208** |
| Bad Hosts – LDAP | **209** |
| Bad Hosts – LPD | **71** |
| Bad Hosts – MOTD | **83** |
| Bad Hosts – HashCountRandom | **51** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-26)**: **10,501** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-27 | **6** |
| 2026-09-26 | **10,501** |
| 2026-09-25 | **183** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,388** |
| Kandidaten dieses Abrufs | **13,388** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+217** |
| Entfernt | **-226** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-27 01:21 CEST (Berlin)*