# Honigtopf – Report
**Aktualisiert:** 2026-09-24 19:31 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-24 19:31 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,535** |
| Bad Hosts – SIP | **170** |
| Bad Hosts – RDP | **1,033** |
| Bad Hosts – SSH | **3,827** |
| Bad Hosts – MSSQL | **569** |
| Bad Hosts – VNC | **526** |
| Bad Hosts – HTTP | **3,335** |
| Bad Hosts – SNMP | **384** |
| Bad Hosts – ProConOs | **237** |
| Bad Hosts – TFTP | **173** |
| Bad Hosts – Telnet | **3,045** |
| Bad Hosts – MySQL | **687** |
| Bad Hosts – PostgreSQL | **408** |
| Bad Hosts – Elasticsearch | **574** |
| Bad Hosts – FTP | **640** |
| Bad Hosts – Kubernetes | **1,003** |
| Bad Hosts – CouchDB | **1,051** |
| Bad Hosts – Redis | **443** |
| Bad Hosts – ClickhouseHTTP | **336** |
| Bad Hosts – RAW | **257** |
| Bad Hosts – Oracle | **260** |
| Bad Hosts – Modbus | **248** |
| Bad Hosts – Memcached | **322** |
| Bad Hosts – LDAP | **237** |
| Bad Hosts – MQTT | **253** |
| Bad Hosts – IPP | **143** |
| Bad Hosts – LPD | **76** |
| Bad Hosts – MOTD | **82** |
| Bad Hosts – HashCountRandom | **44** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-24)**: **9,447** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-24 | **9,447** |
| 2026-09-23 | **3,088** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,450** |
| Kandidaten dieses Abrufs | **15,450** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+413** |
| Entfernt | **-359** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-24 19:31 CEST (Berlin)*