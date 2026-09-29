# Honigtopf – Report
**Aktualisiert:** 2026-09-29 17:05 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 17:05 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,894** |
| Bad Hosts – SIP | **159** |
| Bad Hosts – SSH | **2,850** |
| Bad Hosts – MSSQL | **514** |
| Bad Hosts – RDP | **907** |
| Bad Hosts – SNMP | **321** |
| Bad Hosts – HTTP | **4,996** |
| Bad Hosts – ProConOs | **163** |
| Bad Hosts – VNC | **279** |
| Bad Hosts – Telnet | **2,633** |
| Bad Hosts – PostgreSQL | **480** |
| Bad Hosts – MySQL | **495** |
| Bad Hosts – TFTP | **193** |
| Bad Hosts – Kubernetes | **675** |
| Bad Hosts – Elasticsearch | **566** |
| Bad Hosts – FTP | **388** |
| Bad Hosts – Redis | **350** |
| Bad Hosts – CouchDB | **349** |
| Bad Hosts – ClickhouseHTTP | **252** |
| Bad Hosts – LDAP | **175** |
| Bad Hosts – Oracle | **251** |
| Bad Hosts – Modbus | **209** |
| Bad Hosts – RAW | **131** |
| Bad Hosts – Memcached | **211** |
| Bad Hosts – MQTT | **166** |
| Bad Hosts – IPP | **90** |
| Bad Hosts – HashCountRandom | **93** |
| Bad Hosts – LPD | **42** |
| Bad Hosts – MOTD | **57** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-29)**: **9,773** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-29 | **9,773** |
| 2026-09-28 | **2,121** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,443** |
| Kandidaten dieses Abrufs | **14,443** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+24** |
| Entfernt | **-0** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 17:05 CEST (Berlin)*