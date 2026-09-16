# Honigtopf – Report
**Aktualisiert:** 2026-09-16 03:22 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-16 03:22 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **47,503** |
| Bad Hosts – SIP | **182** |
| Bad Hosts – RDP | **1,253** |
| Bad Hosts – SSH | **4,074** |
| Bad Hosts – MSSQL | **569** |
| Bad Hosts – HTTP | **4,983** |
| Bad Hosts – FTP | **33,574** |
| Bad Hosts – VNC | **1,643** |
| Bad Hosts – SNMP | **525** |
| Bad Hosts – TFTP | **225** |
| Bad Hosts – ProConOs | **229** |
| Bad Hosts – Telnet | **3,386** |
| Bad Hosts – MySQL | **756** |
| Bad Hosts – PostgreSQL | **631** |
| Bad Hosts – Kubernetes | **754** |
| Bad Hosts – Redis | **503** |
| Bad Hosts – CouchDB | **260** |
| Bad Hosts – Elasticsearch | **517** |
| Bad Hosts – ClickhouseHTTP | **368** |
| Bad Hosts – Oracle | **329** |
| Bad Hosts – Memcached | **234** |
| Bad Hosts – Modbus | **228** |
| Bad Hosts – LDAP | **238** |
| Bad Hosts – RAW | **211** |
| Bad Hosts – MQTT | **269** |
| Bad Hosts – HashCountRandom | **252** |
| Bad Hosts – IPP | **135** |
| Bad Hosts – LPD | **77** |
| Bad Hosts – MOTD | **67** |
| Bad Hosts – WebLogic | **4** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-16)**: **2,068** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-16 | **2,068** |
| 2026-09-15 | **45,435** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **50,971** |
| Kandidaten dieses Abrufs | **50,971** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+808** |
| Entfernt | **-908** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-16 03:22 CEST (Berlin)*