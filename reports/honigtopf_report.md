# Honigtopf – Report
**Aktualisiert:** 2026-10-02 04:19 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 04:19 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,282** |
| Bad Hosts – SIP | **173** |
| Bad Hosts – SSH | **2,917** |
| Bad Hosts – RDP | **716** |
| Bad Hosts – MSSQL | **492** |
| Bad Hosts – HTTP | **3,226** |
| Bad Hosts – SNMP | **377** |
| Bad Hosts – MySQL | **707** |
| Bad Hosts – VNC | **355** |
| Bad Hosts – ProConOs | **136** |
| Bad Hosts – Telnet | **2,973** |
| Bad Hosts – FTP | **537** |
| Bad Hosts – TFTP | **195** |
| Bad Hosts – PostgreSQL | **373** |
| Bad Hosts – Kubernetes | **670** |
| Bad Hosts – Redis | **374** |
| Bad Hosts – Elasticsearch | **554** |
| Bad Hosts – CouchDB | **260** |
| Bad Hosts – Oracle | **254** |
| Bad Hosts – Modbus | **192** |
| Bad Hosts – ClickhouseHTTP | **224** |
| Bad Hosts – Memcached | **216** |
| Bad Hosts – MQTT | **210** |
| Bad Hosts – LDAP | **159** |
| Bad Hosts – IPP | **90** |
| Bad Hosts – RAW | **93** |
| Bad Hosts – HashCountRandom | **151** |
| Bad Hosts – LPD | **71** |
| Bad Hosts – MOTD | **69** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **1,593** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **1,593** |
| 2026-10-01 | **8,689** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **12,918** |
| Kandidaten dieses Abrufs | **12,918** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+591** |
| Entfernt | **-1,199** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 04:19 CEST (Berlin)*