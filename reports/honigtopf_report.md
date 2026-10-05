# Honigtopf – Report
**Aktualisiert:** 2026-10-05 07:57 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 07:57 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,807** |
| Bad Hosts – SIP | **174** |
| Bad Hosts – SSH | **4,206** |
| Bad Hosts – SNMP | **380** |
| Bad Hosts – MSSQL | **467** |
| Bad Hosts – RDP | **736** |
| Bad Hosts – HTTP | **2,649** |
| Bad Hosts – Telnet | **2,773** |
| Bad Hosts – ProConOs | **148** |
| Bad Hosts – MySQL | **421** |
| Bad Hosts – VNC | **334** |
| Bad Hosts – TFTP | **190** |
| Bad Hosts – FTP | **398** |
| Bad Hosts – Redis | **429** |
| Bad Hosts – Kubernetes | **765** |
| Bad Hosts – PostgreSQL | **553** |
| Bad Hosts – CouchDB | **370** |
| Bad Hosts – Elasticsearch | **613** |
| Bad Hosts – ClickhouseHTTP | **369** |
| Bad Hosts – LDAP | **197** |
| Bad Hosts – Oracle | **274** |
| Bad Hosts – Memcached | **233** |
| Bad Hosts – Modbus | **199** |
| Bad Hosts – MQTT | **193** |
| Bad Hosts – RAW | **105** |
| Bad Hosts – IPP | **90** |
| Bad Hosts – LPD | **83** |
| Bad Hosts – HashCountRandom | **44** |
| Bad Hosts – MOTD | **67** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **4,141** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **4,141** |
| 2026-10-04 | **6,666** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,405** |
| Kandidaten dieses Abrufs | **13,405** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,696** |
| Entfernt | **-1,458** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 07:57 CEST (Berlin)*