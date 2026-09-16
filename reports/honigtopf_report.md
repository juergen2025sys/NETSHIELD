# Honigtopf – Report
**Aktualisiert:** 2026-09-16 17:09 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-16 17:09 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **45,766** |
| Bad Hosts – SIP | **214** |
| Bad Hosts – RDP | **1,281** |
| Bad Hosts – MSSQL | **590** |
| Bad Hosts – SSH | **3,617** |
| Bad Hosts – HTTP | **4,619** |
| Bad Hosts – FTP | **32,536** |
| Bad Hosts – VNC | **1,609** |
| Bad Hosts – TFTP | **316** |
| Bad Hosts – SNMP | **498** |
| Bad Hosts – Telnet | **3,371** |
| Bad Hosts – ProConOs | **145** |
| Bad Hosts – MySQL | **752** |
| Bad Hosts – PostgreSQL | **630** |
| Bad Hosts – Kubernetes | **914** |
| Bad Hosts – Redis | **445** |
| Bad Hosts – Elasticsearch | **533** |
| Bad Hosts – CouchDB | **271** |
| Bad Hosts – ClickhouseHTTP | **316** |
| Bad Hosts – Oracle | **267** |
| Bad Hosts – Memcached | **245** |
| Bad Hosts – Modbus | **250** |
| Bad Hosts – LDAP | **257** |
| Bad Hosts – RAW | **199** |
| Bad Hosts – IPP | **136** |
| Bad Hosts – MQTT | **215** |
| Bad Hosts – HashCountRandom | **200** |
| Bad Hosts – LPD | **83** |
| Bad Hosts – MOTD | **59** |
| Bad Hosts – WebLogic | **3** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-16)**: **29,244** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-16 | **29,244** |
| 2026-09-15 | **16,522** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **49,526** |
| Kandidaten dieses Abrufs | **49,526** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+749** |
| Entfernt | **-1,071** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-16 17:09 CEST (Berlin)*