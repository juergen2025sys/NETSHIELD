# Honigtopf – Report
**Aktualisiert:** 2026-10-01 21:05 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-01 21:05 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,539** |
| Bad Hosts – SIP | **165** |
| Bad Hosts – SSH | **3,476** |
| Bad Hosts – RDP | **667** |
| Bad Hosts – MSSQL | **469** |
| Bad Hosts – HTTP | **3,101** |
| Bad Hosts – SNMP | **400** |
| Bad Hosts – VNC | **300** |
| Bad Hosts – MySQL | **625** |
| Bad Hosts – FTP | **520** |
| Bad Hosts – Telnet | **2,979** |
| Bad Hosts – ProConOs | **127** |
| Bad Hosts – TFTP | **194** |
| Bad Hosts – PostgreSQL | **347** |
| Bad Hosts – Kubernetes | **587** |
| Bad Hosts – Redis | **375** |
| Bad Hosts – Elasticsearch | **592** |
| Bad Hosts – CouchDB | **256** |
| Bad Hosts – ClickhouseHTTP | **264** |
| Bad Hosts – Oracle | **256** |
| Bad Hosts – Modbus | **186** |
| Bad Hosts – Memcached | **172** |
| Bad Hosts – LDAP | **172** |
| Bad Hosts – MQTT | **181** |
| Bad Hosts – IPP | **100** |
| Bad Hosts – RAW | **81** |
| Bad Hosts – LPD | **72** |
| Bad Hosts – HashCountRandom | **114** |
| Bad Hosts – MOTD | **68** |
| Bad Hosts – Echo | **6** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-01)**: **8,696** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-01 | **8,696** |
| 2026-09-30 | **1,843** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,213** |
| Kandidaten dieses Abrufs | **13,213** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,104** |
| Entfernt | **-1,453** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-01 21:05 CEST (Berlin)*