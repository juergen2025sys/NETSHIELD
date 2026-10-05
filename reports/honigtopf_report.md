# Honigtopf – Report
**Aktualisiert:** 2026-10-05 11:34 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 11:34 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,864** |
| Bad Hosts – SIP | **175** |
| Bad Hosts – SSH | **4,123** |
| Bad Hosts – RDP | **726** |
| Bad Hosts – MSSQL | **485** |
| Bad Hosts – SNMP | **385** |
| Bad Hosts – HTTP | **2,775** |
| Bad Hosts – Telnet | **2,762** |
| Bad Hosts – MySQL | **477** |
| Bad Hosts – VNC | **319** |
| Bad Hosts – ProConOs | **127** |
| Bad Hosts – TFTP | **199** |
| Bad Hosts – FTP | **412** |
| Bad Hosts – Redis | **398** |
| Bad Hosts – Kubernetes | **745** |
| Bad Hosts – PostgreSQL | **537** |
| Bad Hosts – CouchDB | **373** |
| Bad Hosts – Elasticsearch | **583** |
| Bad Hosts – ClickhouseHTTP | **348** |
| Bad Hosts – LDAP | **198** |
| Bad Hosts – Oracle | **282** |
| Bad Hosts – Memcached | **227** |
| Bad Hosts – Modbus | **220** |
| Bad Hosts – MQTT | **196** |
| Bad Hosts – RAW | **112** |
| Bad Hosts – IPP | **87** |
| Bad Hosts – HashCountRandom | **44** |
| Bad Hosts – LPD | **75** |
| Bad Hosts – MOTD | **61** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **5,834** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **5,834** |
| 2026-10-04 | **5,030** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,399** |
| Kandidaten dieses Abrufs | **13,399** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+865** |
| Entfernt | **-1,382** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 11:34 CEST (Berlin)*