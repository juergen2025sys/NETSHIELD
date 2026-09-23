# Honigtopf – Report
**Aktualisiert:** 2026-09-23 23:49 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 23:49 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,429** |
| Bad Hosts – SIP | **147** |
| Bad Hosts – RDP | **1,136** |
| Bad Hosts – SSH | **4,017** |
| Bad Hosts – MSSQL | **640** |
| Bad Hosts – SNMP | **361** |
| Bad Hosts – HTTP | **3,198** |
| Bad Hosts – VNC | **391** |
| Bad Hosts – TFTP | **180** |
| Bad Hosts – Telnet | **2,839** |
| Bad Hosts – ProConOs | **226** |
| Bad Hosts – MySQL | **687** |
| Bad Hosts – FTP | **640** |
| Bad Hosts – PostgreSQL | **569** |
| Bad Hosts – Kubernetes | **879** |
| Bad Hosts – CouchDB | **1,145** |
| Bad Hosts – Redis | **474** |
| Bad Hosts – Elasticsearch | **630** |
| Bad Hosts – Oracle | **289** |
| Bad Hosts – ClickhouseHTTP | **297** |
| Bad Hosts – Modbus | **275** |
| Bad Hosts – Memcached | **279** |
| Bad Hosts – LDAP | **314** |
| Bad Hosts – RAW | **254** |
| Bad Hosts – MQTT | **241** |
| Bad Hosts – IPP | **102** |
| Bad Hosts – HashCountRandom | **100** |
| Bad Hosts – LPD | **94** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-23)**: **11,733** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-23 | **11,733** |
| 2026-09-22 | **696** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,325** |
| Kandidaten dieses Abrufs | **15,325** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,081** |
| Entfernt | **-1,074** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 23:49 CEST (Berlin)*