# Honigtopf – Report
**Aktualisiert:** 2026-09-23 03:45 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 03:45 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,263** |
| Bad Hosts – SIP | **247** |
| Bad Hosts – RDP | **950** |
| Bad Hosts – SSH | **3,953** |
| Bad Hosts – MSSQL | **545** |
| Bad Hosts – SNMP | **399** |
| Bad Hosts – HTTP | **2,927** |
| Bad Hosts – VNC | **357** |
| Bad Hosts – Telnet | **2,825** |
| Bad Hosts – TFTP | **200** |
| Bad Hosts – MySQL | **663** |
| Bad Hosts – ProConOs | **148** |
| Bad Hosts – FTP | **581** |
| Bad Hosts – PostgreSQL | **550** |
| Bad Hosts – Kubernetes | **694** |
| Bad Hosts – Redis | **474** |
| Bad Hosts – Elasticsearch | **579** |
| Bad Hosts – CouchDB | **248** |
| Bad Hosts – ClickhouseHTTP | **273** |
| Bad Hosts – Oracle | **288** |
| Bad Hosts – MQTT | **245** |
| Bad Hosts – LDAP | **338** |
| Bad Hosts – RAW | **258** |
| Bad Hosts – Modbus | **219** |
| Bad Hosts – Memcached | **256** |
| Bad Hosts – IPP | **152** |
| Bad Hosts – LPD | **119** |
| Bad Hosts – HashCountRandom | **101** |
| Bad Hosts – MOTD | **62** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-23)**: **1,473** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-23 | **1,473** |
| 2026-09-22 | **9,790** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,296** |
| Kandidaten dieses Abrufs | **14,296** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+474** |
| Entfernt | **-695** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 03:45 CEST (Berlin)*