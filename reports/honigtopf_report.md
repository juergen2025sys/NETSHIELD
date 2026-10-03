# Honigtopf – Report
**Aktualisiert:** 2026-10-03 15:29 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-03 15:29 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,362** |
| Bad Hosts – SIP | **163** |
| Bad Hosts – SSH | **3,043** |
| Bad Hosts – MSSQL | **508** |
| Bad Hosts – VNC | **279** |
| Bad Hosts – RDP | **803** |
| Bad Hosts – SNMP | **375** |
| Bad Hosts – HTTP | **4,099** |
| Bad Hosts – MySQL | **611** |
| Bad Hosts – Telnet | **2,964** |
| Bad Hosts – ProConOs | **127** |
| Bad Hosts – TFTP | **203** |
| Bad Hosts – CouchDB | **353** |
| Bad Hosts – Redis | **494** |
| Bad Hosts – Kubernetes | **686** |
| Bad Hosts – PostgreSQL | **490** |
| Bad Hosts – FTP | **491** |
| Bad Hosts – Elasticsearch | **690** |
| Bad Hosts – Oracle | **274** |
| Bad Hosts – ClickhouseHTTP | **326** |
| Bad Hosts – Modbus | **192** |
| Bad Hosts – Memcached | **223** |
| Bad Hosts – RAW | **137** |
| Bad Hosts – LDAP | **228** |
| Bad Hosts – MQTT | **165** |
| Bad Hosts – IPP | **110** |
| Bad Hosts – LPD | **65** |
| Bad Hosts – HashCountRandom | **107** |
| Bad Hosts – MOTD | **51** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-03)**: **6,733** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-03 | **6,733** |
| 2026-10-02 | **4,629** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,325** |
| Kandidaten dieses Abrufs | **14,325** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+390** |
| Entfernt | **-1,261** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-03 15:29 CEST (Berlin)*