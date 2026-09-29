# Honigtopf – Report
**Aktualisiert:** 2026-09-29 17:06 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 17:06 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,894** |
| Bad Hosts – SIP | **159** |
| Bad Hosts – SSH | **2,854** |
| Bad Hosts – MSSQL | **515** |
| Bad Hosts – RDP | **908** |
| Bad Hosts – SNMP | **323** |
| Bad Hosts – HTTP | **5,001** |
| Bad Hosts – ProConOs | **163** |
| Bad Hosts – VNC | **279** |
| Bad Hosts – Telnet | **2,633** |
| Bad Hosts – PostgreSQL | **481** |
| Bad Hosts – MySQL | **496** |
| Bad Hosts – TFTP | **192** |
| Bad Hosts – Kubernetes | **673** |
| Bad Hosts – Elasticsearch | **569** |
| Bad Hosts – FTP | **388** |
| Bad Hosts – Redis | **350** |
| Bad Hosts – CouchDB | **349** |
| Bad Hosts – ClickhouseHTTP | **252** |
| Bad Hosts – LDAP | **175** |
| Bad Hosts – Oracle | **251** |
| Bad Hosts – Modbus | **210** |
| Bad Hosts – RAW | **130** |
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
| Gesamt Honigtopf-IPs | **14,460** |
| Kandidaten dieses Abrufs | **14,460** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+43** |
| Entfernt | **-2** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 17:06 CEST (Berlin)*