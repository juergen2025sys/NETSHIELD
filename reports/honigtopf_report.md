# Honigtopf – Report
**Aktualisiert:** 2026-09-24 02:48 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-24 02:48 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,488** |
| Bad Hosts – SIP | **160** |
| Bad Hosts – RDP | **1,152** |
| Bad Hosts – SSH | **4,009** |
| Bad Hosts – MSSQL | **640** |
| Bad Hosts – HTTP | **3,214** |
| Bad Hosts – VNC | **374** |
| Bad Hosts – SNMP | **349** |
| Bad Hosts – TFTP | **173** |
| Bad Hosts – Telnet | **2,925** |
| Bad Hosts – MySQL | **671** |
| Bad Hosts – ProConOs | **199** |
| Bad Hosts – PostgreSQL | **503** |
| Bad Hosts – FTP | **660** |
| Bad Hosts – Kubernetes | **876** |
| Bad Hosts – CouchDB | **1,139** |
| Bad Hosts – Redis | **453** |
| Bad Hosts – Elasticsearch | **677** |
| Bad Hosts – Oracle | **289** |
| Bad Hosts – ClickhouseHTTP | **313** |
| Bad Hosts – Modbus | **299** |
| Bad Hosts – Memcached | **283** |
| Bad Hosts – LDAP | **276** |
| Bad Hosts – RAW | **217** |
| Bad Hosts – MQTT | **239** |
| Bad Hosts – HashCountRandom | **98** |
| Bad Hosts – IPP | **98** |
| Bad Hosts – LPD | **93** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-24)**: **916** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-24 | **916** |
| 2026-09-23 | **11,572** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,257** |
| Kandidaten dieses Abrufs | **15,257** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+110** |
| Entfernt | **-157** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-24 02:48 CEST (Berlin)*