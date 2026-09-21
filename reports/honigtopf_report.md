# Honigtopf – Report
**Aktualisiert:** 2026-09-21 12:48 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-21 12:48 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,867** |
| Bad Hosts – RDP | **1,084** |
| Bad Hosts – SSH | **4,547** |
| Bad Hosts – SIP | **190** |
| Bad Hosts – MSSQL | **526** |
| Bad Hosts – SNMP | **342** |
| Bad Hosts – HTTP | **2,559** |
| Bad Hosts – VNC | **1,021** |
| Bad Hosts – Telnet | **2,948** |
| Bad Hosts – ProConOs | **139** |
| Bad Hosts – TFTP | **174** |
| Bad Hosts – MySQL | **441** |
| Bad Hosts – PostgreSQL | **509** |
| Bad Hosts – FTP | **383** |
| Bad Hosts – Kubernetes | **696** |
| Bad Hosts – Redis | **282** |
| Bad Hosts – Elasticsearch | **417** |
| Bad Hosts – ClickhouseHTTP | **193** |
| Bad Hosts – Oracle | **254** |
| Bad Hosts – RAW | **196** |
| Bad Hosts – LDAP | **219** |
| Bad Hosts – CouchDB | **217** |
| Bad Hosts – Modbus | **144** |
| Bad Hosts – Memcached | **169** |
| Bad Hosts – IPP | **110** |
| Bad Hosts – MQTT | **170** |
| Bad Hosts – LPD | **91** |
| Bad Hosts – HashCountRandom | **74** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – MOTD | **46** |
| Bad Hosts – Echo | **6** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-21)**: **6,208** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-21 | **6,208** |
| 2026-09-20 | **5,659** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,338** |
| Kandidaten dieses Abrufs | **14,338** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,880** |
| Entfernt | **-2,144** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-21 12:48 CEST (Berlin)*