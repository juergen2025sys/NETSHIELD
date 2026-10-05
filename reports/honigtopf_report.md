# Honigtopf – Report
**Aktualisiert:** 2026-10-05 11:35 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 11:35 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,864** |
| Bad Hosts – SIP | **175** |
| Bad Hosts – SSH | **4,123** |
| Bad Hosts – RDP | **727** |
| Bad Hosts – MSSQL | **486** |
| Bad Hosts – SNMP | **385** |
| Bad Hosts – HTTP | **2,774** |
| Bad Hosts – Telnet | **2,760** |
| Bad Hosts – MySQL | **480** |
| Bad Hosts – VNC | **321** |
| Bad Hosts – ProConOs | **127** |
| Bad Hosts – TFTP | **200** |
| Bad Hosts – FTP | **412** |
| Bad Hosts – Redis | **396** |
| Bad Hosts – Kubernetes | **744** |
| Bad Hosts – PostgreSQL | **531** |
| Bad Hosts – CouchDB | **380** |
| Bad Hosts – Elasticsearch | **583** |
| Bad Hosts – ClickhouseHTTP | **347** |
| Bad Hosts – LDAP | **198** |
| Bad Hosts – Oracle | **280** |
| Bad Hosts – Memcached | **226** |
| Bad Hosts – Modbus | **220** |
| Bad Hosts – MQTT | **196** |
| Bad Hosts – RAW | **112** |
| Bad Hosts – IPP | **87** |
| Bad Hosts – HashCountRandom | **44** |
| Bad Hosts – LPD | **75** |
| Bad Hosts – MOTD | **62** |
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
| Gesamt Honigtopf-IPs | **13,406** |
| Kandidaten dieses Abrufs | **13,406** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+11** |
| Entfernt | **-4** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 11:35 CEST (Berlin)*