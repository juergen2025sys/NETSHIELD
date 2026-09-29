# Honigtopf – Report
**Aktualisiert:** 2026-09-29 16:02 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 16:02 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,745** |
| Bad Hosts – SIP | **157** |
| Bad Hosts – SSH | **2,834** |
| Bad Hosts – MSSQL | **520** |
| Bad Hosts – RDP | **859** |
| Bad Hosts – SNMP | **294** |
| Bad Hosts – HTTP | **4,893** |
| Bad Hosts – VNC | **308** |
| Bad Hosts – ProConOs | **163** |
| Bad Hosts – Telnet | **2,607** |
| Bad Hosts – PostgreSQL | **476** |
| Bad Hosts – MySQL | **481** |
| Bad Hosts – TFTP | **192** |
| Bad Hosts – Kubernetes | **651** |
| Bad Hosts – Elasticsearch | **569** |
| Bad Hosts – FTP | **389** |
| Bad Hosts – Redis | **343** |
| Bad Hosts – CouchDB | **324** |
| Bad Hosts – ClickhouseHTTP | **247** |
| Bad Hosts – LDAP | **173** |
| Bad Hosts – Oracle | **249** |
| Bad Hosts – Modbus | **184** |
| Bad Hosts – RAW | **128** |
| Bad Hosts – Memcached | **206** |
| Bad Hosts – MQTT | **173** |
| Bad Hosts – IPP | **91** |
| Bad Hosts – HashCountRandom | **81** |
| Bad Hosts – LPD | **41** |
| Bad Hosts – MOTD | **56** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-29)**: **9,349** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-29 | **9,349** |
| 2026-09-28 | **2,396** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,192** |
| Kandidaten dieses Abrufs | **14,192** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,196** |
| Entfernt | **-1,740** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 16:02 CEST (Berlin)*