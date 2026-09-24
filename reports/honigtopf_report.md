# Honigtopf – Report
**Aktualisiert:** 2026-09-24 08:44 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-24 08:44 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,660** |
| Bad Hosts – SIP | **174** |
| Bad Hosts – RDP | **1,165** |
| Bad Hosts – SSH | **3,919** |
| Bad Hosts – MSSQL | **637** |
| Bad Hosts – VNC | **402** |
| Bad Hosts – HTTP | **3,339** |
| Bad Hosts – SNMP | **335** |
| Bad Hosts – TFTP | **188** |
| Bad Hosts – Telnet | **2,953** |
| Bad Hosts – ProConOs | **220** |
| Bad Hosts – MySQL | **707** |
| Bad Hosts – PostgreSQL | **434** |
| Bad Hosts – FTP | **616** |
| Bad Hosts – Kubernetes | **956** |
| Bad Hosts – CouchDB | **1,120** |
| Bad Hosts – Elasticsearch | **685** |
| Bad Hosts – Redis | **456** |
| Bad Hosts – ClickhouseHTTP | **300** |
| Bad Hosts – Oracle | **267** |
| Bad Hosts – RAW | **248** |
| Bad Hosts – Modbus | **319** |
| Bad Hosts – Memcached | **301** |
| Bad Hosts – LDAP | **273** |
| Bad Hosts – MQTT | **245** |
| Bad Hosts – HashCountRandom | **84** |
| Bad Hosts – IPP | **104** |
| Bad Hosts – LPD | **61** |
| Bad Hosts – MOTD | **63** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-24)**: **4,481** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-24 | **4,481** |
| 2026-09-23 | **8,179** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,543** |
| Kandidaten dieses Abrufs | **15,543** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+195** |
| Entfernt | **-118** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-24 08:44 CEST (Berlin)*