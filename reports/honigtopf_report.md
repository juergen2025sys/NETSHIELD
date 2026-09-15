# Honigtopf – Report
**Aktualisiert:** 2026-09-15 22:11 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-15 22:11 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **48,018** |
| Bad Hosts – SIP | **196** |
| Bad Hosts – RDP | **1,116** |
| Bad Hosts – SSH | **3,941** |
| Bad Hosts – MSSQL | **604** |
| Bad Hosts – VNC | **1,656** |
| Bad Hosts – HTTP | **5,020** |
| Bad Hosts – FTP | **34,185** |
| Bad Hosts – SNMP | **503** |
| Bad Hosts – TFTP | **232** |
| Bad Hosts – ProConOs | **227** |
| Bad Hosts – MySQL | **750** |
| Bad Hosts – Telnet | **3,390** |
| Bad Hosts – PostgreSQL | **589** |
| Bad Hosts – Kubernetes | **726** |
| Bad Hosts – Redis | **442** |
| Bad Hosts – CouchDB | **277** |
| Bad Hosts – Elasticsearch | **523** |
| Bad Hosts – ClickhouseHTTP | **346** |
| Bad Hosts – Oracle | **318** |
| Bad Hosts – Modbus | **219** |
| Bad Hosts – Memcached | **229** |
| Bad Hosts – LDAP | **229** |
| Bad Hosts – MQTT | **270** |
| Bad Hosts – HashCountRandom | **239** |
| Bad Hosts – RAW | **190** |
| Bad Hosts – IPP | **151** |
| Bad Hosts – LPD | **78** |
| Bad Hosts – MOTD | **71** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – WebLogic | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-15)**: **42,504** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-15 | **42,504** |
| 2026-09-14 | **5,514** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **51,611** |
| Kandidaten dieses Abrufs | **51,611** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,176** |
| Entfernt | **-2,468** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-15 22:11 CEST (Berlin)*