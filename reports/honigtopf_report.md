# Honigtopf – Report
**Aktualisiert:** 2026-09-29 10:51 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 10:51 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,414** |
| Bad Hosts – SIP | **159** |
| Bad Hosts – MSSQL | **490** |
| Bad Hosts – SSH | **2,787** |
| Bad Hosts – RDP | **742** |
| Bad Hosts – SNMP | **300** |
| Bad Hosts – HTTP | **4,702** |
| Bad Hosts – VNC | **294** |
| Bad Hosts – ProConOs | **143** |
| Bad Hosts – Telnet | **2,500** |
| Bad Hosts – PostgreSQL | **436** |
| Bad Hosts – TFTP | **191** |
| Bad Hosts – MySQL | **377** |
| Bad Hosts – Kubernetes | **684** |
| Bad Hosts – Elasticsearch | **574** |
| Bad Hosts – FTP | **331** |
| Bad Hosts – Redis | **333** |
| Bad Hosts – CouchDB | **269** |
| Bad Hosts – LDAP | **185** |
| Bad Hosts – ClickhouseHTTP | **272** |
| Bad Hosts – Oracle | **236** |
| Bad Hosts – RAW | **141** |
| Bad Hosts – Modbus | **174** |
| Bad Hosts – MQTT | **172** |
| Bad Hosts – Memcached | **188** |
| Bad Hosts – IPP | **105** |
| Bad Hosts – HashCountRandom | **71** |
| Bad Hosts – LPD | **48** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-29)**: **7,054** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-29 | **7,054** |
| 2026-09-28 | **4,360** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,675** |
| Kandidaten dieses Abrufs | **13,675** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+64** |
| Entfernt | **-78** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 10:51 CEST (Berlin)*