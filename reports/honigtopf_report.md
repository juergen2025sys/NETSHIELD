# Honigtopf – Report
**Aktualisiert:** 2026-10-05 04:25 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 04:25 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,507** |
| Bad Hosts – SIP | **171** |
| Bad Hosts – SSH | **4,112** |
| Bad Hosts – SNMP | **398** |
| Bad Hosts – MSSQL | **422** |
| Bad Hosts – RDP | **698** |
| Bad Hosts – HTTP | **2,505** |
| Bad Hosts – Telnet | **2,747** |
| Bad Hosts – VNC | **361** |
| Bad Hosts – ProConOs | **140** |
| Bad Hosts – TFTP | **191** |
| Bad Hosts – FTP | **353** |
| Bad Hosts – MySQL | **412** |
| Bad Hosts – Redis | **405** |
| Bad Hosts – Kubernetes | **744** |
| Bad Hosts – PostgreSQL | **562** |
| Bad Hosts – CouchDB | **374** |
| Bad Hosts – ClickhouseHTTP | **378** |
| Bad Hosts – Elasticsearch | **537** |
| Bad Hosts – Oracle | **284** |
| Bad Hosts – LDAP | **189** |
| Bad Hosts – Memcached | **223** |
| Bad Hosts – Modbus | **205** |
| Bad Hosts – MQTT | **199** |
| Bad Hosts – RAW | **106** |
| Bad Hosts – IPP | **95** |
| Bad Hosts – LPD | **71** |
| Bad Hosts – HashCountRandom | **36** |
| Bad Hosts – MOTD | **64** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **1,914** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **1,914** |
| 2026-10-04 | **8,593** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,149** |
| Kandidaten dieses Abrufs | **13,149** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+641** |
| Entfernt | **-782** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 04:25 CEST (Berlin)*