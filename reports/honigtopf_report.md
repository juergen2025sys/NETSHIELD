# Honigtopf – Report
**Aktualisiert:** 2026-09-19 07:05 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-19 07:05 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **38,394** |
| Bad Hosts – SIP | **189** |
| Bad Hosts – MSSQL | **860** |
| Bad Hosts – SSH | **3,981** |
| Bad Hosts – VNC | **1,573** |
| Bad Hosts – RDP | **889** |
| Bad Hosts – SNMP | **446** |
| Bad Hosts – HTTP | **4,689** |
| Bad Hosts – TFTP | **207** |
| Bad Hosts – FTP | **25,112** |
| Bad Hosts – PostgreSQL | **531** |
| Bad Hosts – Telnet | **2,927** |
| Bad Hosts – ProConOs | **160** |
| Bad Hosts – MySQL | **609** |
| Bad Hosts – Kubernetes | **800** |
| Bad Hosts – Redis | **446** |
| Bad Hosts – Elasticsearch | **453** |
| Bad Hosts – CouchDB | **247** |
| Bad Hosts – Modbus | **239** |
| Bad Hosts – ClickhouseHTTP | **262** |
| Bad Hosts – IPP | **175** |
| Bad Hosts – Oracle | **222** |
| Bad Hosts – RAW | **267** |
| Bad Hosts – Memcached | **237** |
| Bad Hosts – LDAP | **256** |
| Bad Hosts – LPD | **114** |
| Bad Hosts – MQTT | **212** |
| Bad Hosts – HashCountRandom | **168** |
| Bad Hosts – MOTD | **52** |
| Bad Hosts – WebLogic | **1** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-19)**: **6,447** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-19 | **6,447** |
| 2026-09-18 | **31,947** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **41,723** |
| Kandidaten dieses Abrufs | **41,723** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,364** |
| Entfernt | **-2,341** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-19 07:05 CEST (Berlin)*