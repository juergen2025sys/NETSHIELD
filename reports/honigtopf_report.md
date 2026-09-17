# Honigtopf – Report
**Aktualisiert:** 2026-09-17 22:15 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-17 22:15 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **42,144** |
| Bad Hosts – VNC | **1,500** |
| Bad Hosts – SIP | **175** |
| Bad Hosts – SSH | **3,852** |
| Bad Hosts – MSSQL | **956** |
| Bad Hosts – RDP | **989** |
| Bad Hosts – SNMP | **543** |
| Bad Hosts – HTTP | **4,489** |
| Bad Hosts – CouchDB | **214** |
| Bad Hosts – FTP | **28,918** |
| Bad Hosts – TFTP | **213** |
| Bad Hosts – ProConOs | **163** |
| Bad Hosts – Telnet | **3,043** |
| Bad Hosts – MySQL | **608** |
| Bad Hosts – PostgreSQL | **511** |
| Bad Hosts – Kubernetes | **767** |
| Bad Hosts – Redis | **457** |
| Bad Hosts – Elasticsearch | **613** |
| Bad Hosts – Oracle | **290** |
| Bad Hosts – ClickhouseHTTP | **282** |
| Bad Hosts – Modbus | **243** |
| Bad Hosts – LDAP | **228** |
| Bad Hosts – IPP | **138** |
| Bad Hosts – Memcached | **250** |
| Bad Hosts – RAW | **211** |
| Bad Hosts – MQTT | **212** |
| Bad Hosts – HashCountRandom | **241** |
| Bad Hosts – LPD | **49** |
| Bad Hosts – MOTD | **57** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-17)**: **37,096** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-17 | **37,096** |
| 2026-09-16 | **5,048** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **45,641** |
| Kandidaten dieses Abrufs | **45,641** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,977** |
| Entfernt | **-2,038** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-17 22:15 CEST (Berlin)*