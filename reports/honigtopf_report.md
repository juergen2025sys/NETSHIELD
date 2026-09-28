# Honigtopf – Report
**Aktualisiert:** 2026-09-29 00:28 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ unklar (410) – im Pool belassen |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 00:28 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **8,164** |
| Bad Hosts – SIP | **142** |
| Bad Hosts – RDP | **642** |
| Bad Hosts – SSH | **2,719** |
| Bad Hosts – MSSQL | **475** |
| Bad Hosts – VNC | **252** |
| Bad Hosts – SNMP | **275** |
| Bad Hosts – HTTP | **1,843** |
| Bad Hosts – ProConOs | **152** |
| Bad Hosts – Telnet | **2,298** |
| Bad Hosts – TFTP | **134** |
| Bad Hosts – PostgreSQL | **419** |
| Bad Hosts – MySQL | **294** |
| Bad Hosts – Kubernetes | **653** |
| Bad Hosts – FTP | **207** |
| Bad Hosts – Elasticsearch | **469** |
| Bad Hosts – Redis | **274** |
| Bad Hosts – CouchDB | **180** |
| Bad Hosts – ClickhouseHTTP | **282** |
| Bad Hosts – LDAP | **193** |
| Bad Hosts – Oracle | **222** |
| Bad Hosts – RAW | **138** |
| Bad Hosts – MQTT | **197** |
| Bad Hosts – Modbus | **166** |
| Bad Hosts – Memcached | **154** |
| Bad Hosts – IPP | **110** |
| Bad Hosts – HashCountRandom | **59** |
| Bad Hosts – LPD | **59** |
| Bad Hosts – MOTD | **57** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-28)**: **7,673** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-28 | **7,673** |
| 2026-09-27 | **491** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **10,293** |
| Kandidaten dieses Abrufs | **10,293** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+178** |
| Entfernt | **-160** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 00:28 CEST (Berlin)*