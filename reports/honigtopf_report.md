# Honigtopf – Report
**Aktualisiert:** 2026-09-29 17:43 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 17:43 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,938** |
| Bad Hosts – SIP | **159** |
| Bad Hosts – MSSQL | **518** |
| Bad Hosts – SSH | **2,844** |
| Bad Hosts – RDP | **932** |
| Bad Hosts – SNMP | **332** |
| Bad Hosts – HTTP | **5,043** |
| Bad Hosts – ProConOs | **159** |
| Bad Hosts – VNC | **283** |
| Bad Hosts – Telnet | **2,646** |
| Bad Hosts – PostgreSQL | **504** |
| Bad Hosts – MySQL | **516** |
| Bad Hosts – TFTP | **189** |
| Bad Hosts – Kubernetes | **652** |
| Bad Hosts – Elasticsearch | **570** |
| Bad Hosts – FTP | **392** |
| Bad Hosts – Redis | **347** |
| Bad Hosts – CouchDB | **349** |
| Bad Hosts – ClickhouseHTTP | **266** |
| Bad Hosts – LDAP | **188** |
| Bad Hosts – Oracle | **256** |
| Bad Hosts – Modbus | **213** |
| Bad Hosts – RAW | **136** |
| Bad Hosts – Memcached | **214** |
| Bad Hosts – MQTT | **165** |
| Bad Hosts – IPP | **88** |
| Bad Hosts – HashCountRandom | **96** |
| Bad Hosts – LPD | **42** |
| Bad Hosts – MOTD | **58** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-29)**: **9,978** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-29 | **9,978** |
| 2026-09-28 | **1,960** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,580** |
| Kandidaten dieses Abrufs | **14,580** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+280** |
| Entfernt | **-160** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 17:43 CEST (Berlin)*