# Honigtopf – Report
**Aktualisiert:** 2026-09-27 00:11 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-27 00:11 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,677** |
| Bad Hosts – SIP | **168** |
| Bad Hosts – SSH | **3,077** |
| Bad Hosts – RDP | **1,012** |
| Bad Hosts – MSSQL | **447** |
| Bad Hosts – SNMP | **356** |
| Bad Hosts – HTTP | **3,148** |
| Bad Hosts – TFTP | **174** |
| Bad Hosts – PostgreSQL | **623** |
| Bad Hosts – ProConOs | **201** |
| Bad Hosts – Telnet | **3,001** |
| Bad Hosts – MySQL | **679** |
| Bad Hosts – VNC | **398** |
| Bad Hosts – Kubernetes | **731** |
| Bad Hosts – FTP | **518** |
| Bad Hosts – Redis | **450** |
| Bad Hosts – Elasticsearch | **480** |
| Bad Hosts – CouchDB | **231** |
| Bad Hosts – Oracle | **292** |
| Bad Hosts – ClickhouseHTTP | **229** |
| Bad Hosts – RAW | **185** |
| Bad Hosts – Memcached | **241** |
| Bad Hosts – Modbus | **211** |
| Bad Hosts – MQTT | **211** |
| Bad Hosts – IPP | **133** |
| Bad Hosts – LDAP | **217** |
| Bad Hosts – LPD | **68** |
| Bad Hosts – MOTD | **83** |
| Bad Hosts – HashCountRandom | **55** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-26)**: **10,123** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-26 | **10,123** |
| 2026-09-25 | **554** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,423** |
| Kandidaten dieses Abrufs | **13,423** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+286** |
| Entfernt | **-183** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-27 00:11 CEST (Berlin)*