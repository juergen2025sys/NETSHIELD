# Honigtopf – Report
**Aktualisiert:** 2026-09-16 12:15 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-16 12:15 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **46,572** |
| Bad Hosts – RDP | **1,296** |
| Bad Hosts – SIP | **196** |
| Bad Hosts – MSSQL | **611** |
| Bad Hosts – SSH | **3,830** |
| Bad Hosts – HTTP | **4,719** |
| Bad Hosts – FTP | **33,009** |
| Bad Hosts – VNC | **1,628** |
| Bad Hosts – TFTP | **283** |
| Bad Hosts – SNMP | **533** |
| Bad Hosts – ProConOs | **196** |
| Bad Hosts – Telnet | **3,339** |
| Bad Hosts – MySQL | **744** |
| Bad Hosts – PostgreSQL | **648** |
| Bad Hosts – Kubernetes | **820** |
| Bad Hosts – Redis | **509** |
| Bad Hosts – CouchDB | **304** |
| Bad Hosts – Elasticsearch | **541** |
| Bad Hosts – ClickhouseHTTP | **318** |
| Bad Hosts – Oracle | **288** |
| Bad Hosts – Memcached | **234** |
| Bad Hosts – Modbus | **249** |
| Bad Hosts – LDAP | **265** |
| Bad Hosts – RAW | **187** |
| Bad Hosts – IPP | **135** |
| Bad Hosts – MQTT | **233** |
| Bad Hosts – HashCountRandom | **182** |
| Bad Hosts – LPD | **83** |
| Bad Hosts – MOTD | **70** |
| Bad Hosts – WebLogic | **9** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-16)**: **18,373** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-16 | **18,373** |
| 2026-09-15 | **28,199** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **50,619** |
| Kandidaten dieses Abrufs | **50,619** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+593** |
| Entfernt | **-574** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-16 12:15 CEST (Berlin)*