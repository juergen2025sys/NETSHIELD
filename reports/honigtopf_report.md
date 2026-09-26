# Honigtopf – Report
**Aktualisiert:** 2026-09-26 07:25 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-26 07:25 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,001** |
| Bad Hosts – SIP | **148** |
| Bad Hosts – SSH | **3,005** |
| Bad Hosts – RDP | **862** |
| Bad Hosts – MSSQL | **477** |
| Bad Hosts – HTTP | **3,584** |
| Bad Hosts – VNC | **374** |
| Bad Hosts – SNMP | **406** |
| Bad Hosts – TFTP | **172** |
| Bad Hosts – ProConOs | **187** |
| Bad Hosts – Telnet | **2,931** |
| Bad Hosts – PostgreSQL | **552** |
| Bad Hosts – MySQL | **595** |
| Bad Hosts – FTP | **496** |
| Bad Hosts – Kubernetes | **707** |
| Bad Hosts – Redis | **474** |
| Bad Hosts – Elasticsearch | **527** |
| Bad Hosts – CouchDB | **248** |
| Bad Hosts – ClickhouseHTTP | **242** |
| Bad Hosts – Oracle | **319** |
| Bad Hosts – Modbus | **212** |
| Bad Hosts – Memcached | **209** |
| Bad Hosts – MQTT | **243** |
| Bad Hosts – RAW | **129** |
| Bad Hosts – LDAP | **227** |
| Bad Hosts – IPP | **92** |
| Bad Hosts – LPD | **61** |
| Bad Hosts – HashCountRandom | **36** |
| Bad Hosts – MOTD | **37** |
| Bad Hosts – Echo | **6** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-26)**: **3,164** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-26 | **3,164** |
| 2026-09-25 | **7,837** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,558** |
| Kandidaten dieses Abrufs | **13,558** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,925** |
| Entfernt | **-1,824** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-26 07:25 CEST (Berlin)*