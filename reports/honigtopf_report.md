# Honigtopf – Report
**Aktualisiert:** 2026-10-02 04:31 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 04:31 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,318** |
| Bad Hosts – SIP | **173** |
| Bad Hosts – SSH | **2,924** |
| Bad Hosts – RDP | **721** |
| Bad Hosts – MSSQL | **495** |
| Bad Hosts – HTTP | **3,258** |
| Bad Hosts – SNMP | **364** |
| Bad Hosts – MySQL | **715** |
| Bad Hosts – VNC | **340** |
| Bad Hosts – ProConOs | **137** |
| Bad Hosts – Telnet | **2,974** |
| Bad Hosts – FTP | **542** |
| Bad Hosts – TFTP | **196** |
| Bad Hosts – PostgreSQL | **372** |
| Bad Hosts – Kubernetes | **677** |
| Bad Hosts – Redis | **379** |
| Bad Hosts – Elasticsearch | **557** |
| Bad Hosts – CouchDB | **266** |
| Bad Hosts – Oracle | **253** |
| Bad Hosts – Modbus | **193** |
| Bad Hosts – ClickhouseHTTP | **223** |
| Bad Hosts – Memcached | **218** |
| Bad Hosts – MQTT | **211** |
| Bad Hosts – LDAP | **162** |
| Bad Hosts – IPP | **93** |
| Bad Hosts – HashCountRandom | **151** |
| Bad Hosts – RAW | **93** |
| Bad Hosts – LPD | **71** |
| Bad Hosts – MOTD | **69** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **1,794** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **1,794** |
| 2026-10-01 | **8,524** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **12,935** |
| Kandidaten dieses Abrufs | **12,935** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+134** |
| Entfernt | **-117** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 04:31 CEST (Berlin)*