# Honigtopf – Report
**Aktualisiert:** 2026-10-01 17:47 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-01 17:47 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,542** |
| Bad Hosts – SIP | **166** |
| Bad Hosts – SSH | **3,779** |
| Bad Hosts – RDP | **670** |
| Bad Hosts – MSSQL | **427** |
| Bad Hosts – HTTP | **2,895** |
| Bad Hosts – SNMP | **433** |
| Bad Hosts – VNC | **286** |
| Bad Hosts – MySQL | **593** |
| Bad Hosts – FTP | **445** |
| Bad Hosts – Telnet | **2,905** |
| Bad Hosts – ProConOs | **119** |
| Bad Hosts – TFTP | **262** |
| Bad Hosts – PostgreSQL | **386** |
| Bad Hosts – Kubernetes | **518** |
| Bad Hosts – Redis | **379** |
| Bad Hosts – Elasticsearch | **566** |
| Bad Hosts – CouchDB | **273** |
| Bad Hosts – Oracle | **313** |
| Bad Hosts – ClickhouseHTTP | **268** |
| Bad Hosts – Modbus | **156** |
| Bad Hosts – Memcached | **169** |
| Bad Hosts – LDAP | **163** |
| Bad Hosts – MQTT | **166** |
| Bad Hosts – RAW | **88** |
| Bad Hosts – IPP | **110** |
| Bad Hosts – HashCountRandom | **142** |
| Bad Hosts – LPD | **61** |
| Bad Hosts – MOTD | **68** |
| Bad Hosts – Echo | **6** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-01)**: **7,395** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-01 | **7,395** |
| 2026-09-30 | **3,147** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,243** |
| Kandidaten dieses Abrufs | **13,243** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+498** |
| Entfernt | **-943** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-01 17:47 CEST (Berlin)*