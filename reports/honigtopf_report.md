# Honigtopf – Report
**Aktualisiert:** 2026-09-26 20:00 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-26 20:00 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,775** |
| Bad Hosts – SIP | **165** |
| Bad Hosts – SSH | **3,031** |
| Bad Hosts – RDP | **1,073** |
| Bad Hosts – MSSQL | **460** |
| Bad Hosts – SNMP | **382** |
| Bad Hosts – HTTP | **3,104** |
| Bad Hosts – TFTP | **182** |
| Bad Hosts – VNC | **393** |
| Bad Hosts – ProConOs | **212** |
| Bad Hosts – PostgreSQL | **628** |
| Bad Hosts – Telnet | **3,061** |
| Bad Hosts – MySQL | **609** |
| Bad Hosts – Kubernetes | **705** |
| Bad Hosts – FTP | **554** |
| Bad Hosts – Redis | **475** |
| Bad Hosts – Elasticsearch | **502** |
| Bad Hosts – CouchDB | **205** |
| Bad Hosts – Oracle | **298** |
| Bad Hosts – ClickhouseHTTP | **229** |
| Bad Hosts – Modbus | **221** |
| Bad Hosts – Memcached | **243** |
| Bad Hosts – MQTT | **225** |
| Bad Hosts – RAW | **174** |
| Bad Hosts – LDAP | **229** |
| Bad Hosts – IPP | **102** |
| Bad Hosts – HashCountRandom | **36** |
| Bad Hosts – LPD | **42** |
| Bad Hosts – MOTD | **53** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-26)**: **8,694** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-26 | **8,694** |
| 2026-09-25 | **2,081** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,589** |
| Kandidaten dieses Abrufs | **13,589** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+623** |
| Entfernt | **-495** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-26 20:00 CEST (Berlin)*