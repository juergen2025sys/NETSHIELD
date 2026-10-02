# Honigtopf – Report
**Aktualisiert:** 2026-10-02 22:58 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 22:58 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,377** |
| Bad Hosts – SIP | **157** |
| Bad Hosts – SSH | **2,929** |
| Bad Hosts – VNC | **419** |
| Bad Hosts – SNMP | **376** |
| Bad Hosts – MSSQL | **507** |
| Bad Hosts – HTTP | **4,256** |
| Bad Hosts – RDP | **786** |
| Bad Hosts – MySQL | **599** |
| Bad Hosts – Telnet | **3,023** |
| Bad Hosts – ProConOs | **179** |
| Bad Hosts – FTP | **539** |
| Bad Hosts – TFTP | **190** |
| Bad Hosts – PostgreSQL | **443** |
| Bad Hosts – Kubernetes | **802** |
| Bad Hosts – CouchDB | **333** |
| Bad Hosts – Redis | **423** |
| Bad Hosts – Elasticsearch | **476** |
| Bad Hosts – ClickhouseHTTP | **337** |
| Bad Hosts – Oracle | **275** |
| Bad Hosts – Modbus | **189** |
| Bad Hosts – MQTT | **214** |
| Bad Hosts – Memcached | **271** |
| Bad Hosts – LDAP | **193** |
| Bad Hosts – RAW | **122** |
| Bad Hosts – IPP | **121** |
| Bad Hosts – HashCountRandom | **92** |
| Bad Hosts – LPD | **72** |
| Bad Hosts – MOTD | **36** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **10,374** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **10,374** |
| 2026-10-01 | **1,003** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,292** |
| Kandidaten dieses Abrufs | **14,292** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+315** |
| Entfernt | **-292** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 22:58 CEST (Berlin)*