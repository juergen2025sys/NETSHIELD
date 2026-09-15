# Honigtopf – Report
**Aktualisiert:** 2026-09-16 00:17 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-16 00:17 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **47,701** |
| Bad Hosts – SIP | **193** |
| Bad Hosts – RDP | **1,256** |
| Bad Hosts – SSH | **3,985** |
| Bad Hosts – MSSQL | **598** |
| Bad Hosts – HTTP | **5,046** |
| Bad Hosts – VNC | **1,618** |
| Bad Hosts – FTP | **33,776** |
| Bad Hosts – SNMP | **500** |
| Bad Hosts – TFTP | **220** |
| Bad Hosts – ProConOs | **231** |
| Bad Hosts – Telnet | **3,371** |
| Bad Hosts – MySQL | **756** |
| Bad Hosts – PostgreSQL | **588** |
| Bad Hosts – Kubernetes | **744** |
| Bad Hosts – Redis | **458** |
| Bad Hosts – CouchDB | **254** |
| Bad Hosts – Elasticsearch | **501** |
| Bad Hosts – ClickhouseHTTP | **334** |
| Bad Hosts – Oracle | **315** |
| Bad Hosts – Modbus | **229** |
| Bad Hosts – Memcached | **247** |
| Bad Hosts – LDAP | **227** |
| Bad Hosts – MQTT | **273** |
| Bad Hosts – HashCountRandom | **238** |
| Bad Hosts – RAW | **184** |
| Bad Hosts – IPP | **142** |
| Bad Hosts – LPD | **86** |
| Bad Hosts – MOTD | **67** |
| Bad Hosts – WebLogic | **3** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-15)**: **45,700** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-15 | **45,700** |
| 2026-09-14 | **2,001** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **51,328** |
| Kandidaten dieses Abrufs | **51,328** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+935** |
| Entfernt | **-1,127** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-16 00:17 CEST (Berlin)*