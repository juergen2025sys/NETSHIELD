# Honigtopf – Report
**Aktualisiert:** 2026-09-16 07:12 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-16 07:12 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **47,233** |
| Bad Hosts – SIP | **189** |
| Bad Hosts – RDP | **1,279** |
| Bad Hosts – SSH | **4,083** |
| Bad Hosts – MSSQL | **567** |
| Bad Hosts – HTTP | **5,012** |
| Bad Hosts – FTP | **33,219** |
| Bad Hosts – VNC | **1,649** |
| Bad Hosts – TFTP | **211** |
| Bad Hosts – ProConOs | **228** |
| Bad Hosts – SNMP | **548** |
| Bad Hosts – Telnet | **3,360** |
| Bad Hosts – MySQL | **744** |
| Bad Hosts – Kubernetes | **886** |
| Bad Hosts – PostgreSQL | **588** |
| Bad Hosts – Redis | **573** |
| Bad Hosts – CouchDB | **276** |
| Bad Hosts – Elasticsearch | **538** |
| Bad Hosts – ClickhouseHTTP | **347** |
| Bad Hosts – Oracle | **343** |
| Bad Hosts – Modbus | **232** |
| Bad Hosts – Memcached | **221** |
| Bad Hosts – LDAP | **239** |
| Bad Hosts – RAW | **172** |
| Bad Hosts – MQTT | **250** |
| Bad Hosts – HashCountRandom | **212** |
| Bad Hosts – IPP | **147** |
| Bad Hosts – LPD | **80** |
| Bad Hosts – MOTD | **63** |
| Bad Hosts – WebLogic | **6** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-16)**: **7,188** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-16 | **7,188** |
| 2026-09-15 | **40,045** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **51,009** |
| Kandidaten dieses Abrufs | **51,009** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+4,560** |
| Entfernt | **-4,522** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-16 07:12 CEST (Berlin)*