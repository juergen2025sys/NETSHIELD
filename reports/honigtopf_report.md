# Honigtopf – Report
**Aktualisiert:** 2026-09-16 12:00 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-16 12:00 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **46,605** |
| Bad Hosts – RDP | **1,301** |
| Bad Hosts – SIP | **198** |
| Bad Hosts – MSSQL | **609** |
| Bad Hosts – SSH | **3,855** |
| Bad Hosts – HTTP | **4,707** |
| Bad Hosts – FTP | **32,985** |
| Bad Hosts – VNC | **1,631** |
| Bad Hosts – TFTP | **284** |
| Bad Hosts – SNMP | **533** |
| Bad Hosts – ProConOs | **194** |
| Bad Hosts – Telnet | **3,352** |
| Bad Hosts – MySQL | **735** |
| Bad Hosts – PostgreSQL | **658** |
| Bad Hosts – Kubernetes | **833** |
| Bad Hosts – Redis | **508** |
| Bad Hosts – CouchDB | **305** |
| Bad Hosts – Elasticsearch | **542** |
| Bad Hosts – ClickhouseHTTP | **322** |
| Bad Hosts – Oracle | **287** |
| Bad Hosts – Memcached | **239** |
| Bad Hosts – Modbus | **255** |
| Bad Hosts – LDAP | **261** |
| Bad Hosts – RAW | **188** |
| Bad Hosts – IPP | **135** |
| Bad Hosts – MQTT | **234** |
| Bad Hosts – HashCountRandom | **182** |
| Bad Hosts – LPD | **82** |
| Bad Hosts – MOTD | **70** |
| Bad Hosts – WebLogic | **9** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-16)**: **17,794** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-16 | **17,794** |
| 2026-09-15 | **28,811** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **50,600** |
| Kandidaten dieses Abrufs | **50,600** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+5,076** |
| Entfernt | **-10,177** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-16 12:00 CEST (Berlin)*