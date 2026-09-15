# Honigtopf – Report
**Aktualisiert:** 2026-09-16 01:01 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-16 01:01 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **47,693** |
| Bad Hosts – SIP | **192** |
| Bad Hosts – RDP | **1,233** |
| Bad Hosts – SSH | **4,024** |
| Bad Hosts – MSSQL | **582** |
| Bad Hosts – HTTP | **5,088** |
| Bad Hosts – FTP | **33,749** |
| Bad Hosts – VNC | **1,627** |
| Bad Hosts – SNMP | **500** |
| Bad Hosts – TFTP | **220** |
| Bad Hosts – ProConOs | **229** |
| Bad Hosts – Telnet | **3,363** |
| Bad Hosts – MySQL | **744** |
| Bad Hosts – PostgreSQL | **585** |
| Bad Hosts – Kubernetes | **738** |
| Bad Hosts – Redis | **459** |
| Bad Hosts – CouchDB | **259** |
| Bad Hosts – Elasticsearch | **503** |
| Bad Hosts – ClickhouseHTTP | **337** |
| Bad Hosts – Oracle | **313** |
| Bad Hosts – Memcached | **244** |
| Bad Hosts – Modbus | **226** |
| Bad Hosts – LDAP | **232** |
| Bad Hosts – MQTT | **277** |
| Bad Hosts – HashCountRandom | **240** |
| Bad Hosts – RAW | **181** |
| Bad Hosts – IPP | **140** |
| Bad Hosts – LPD | **87** |
| Bad Hosts – MOTD | **67** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-15)**: **46,517** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-16 | **2** |
| 2026-09-15 | **46,517** |
| 2026-09-14 | **1,174** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **51,235** |
| Kandidaten dieses Abrufs | **51,235** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+794** |
| Entfernt | **-887** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-16 01:01 CEST (Berlin)*