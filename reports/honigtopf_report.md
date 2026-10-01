# Honigtopf – Report
**Aktualisiert:** 2026-10-01 22:37 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-01 22:37 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,501** |
| Bad Hosts – SIP | **166** |
| Bad Hosts – SSH | **3,310** |
| Bad Hosts – RDP | **658** |
| Bad Hosts – MSSQL | **477** |
| Bad Hosts – HTTP | **3,152** |
| Bad Hosts – SNMP | **393** |
| Bad Hosts – VNC | **310** |
| Bad Hosts – MySQL | **639** |
| Bad Hosts – FTP | **518** |
| Bad Hosts – ProConOs | **125** |
| Bad Hosts – Telnet | **3,022** |
| Bad Hosts – TFTP | **193** |
| Bad Hosts – PostgreSQL | **349** |
| Bad Hosts – Kubernetes | **605** |
| Bad Hosts – Elasticsearch | **587** |
| Bad Hosts – Redis | **385** |
| Bad Hosts – CouchDB | **255** |
| Bad Hosts – ClickhouseHTTP | **247** |
| Bad Hosts – Oracle | **255** |
| Bad Hosts – Modbus | **189** |
| Bad Hosts – Memcached | **174** |
| Bad Hosts – MQTT | **197** |
| Bad Hosts – LDAP | **170** |
| Bad Hosts – IPP | **99** |
| Bad Hosts – RAW | **80** |
| Bad Hosts – HashCountRandom | **123** |
| Bad Hosts – LPD | **64** |
| Bad Hosts – MOTD | **69** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-01)**: **9,246** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-01 | **9,246** |
| 2026-09-30 | **1,255** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,152** |
| Kandidaten dieses Abrufs | **13,152** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+426** |
| Entfernt | **-548** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-01 22:37 CEST (Berlin)*