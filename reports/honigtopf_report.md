# Honigtopf – Report
**Aktualisiert:** 2026-09-26 12:13 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ✅ gültig (HTTP 200) |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-26 12:13 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,503** |
| Bad Hosts – SIP | **155** |
| Bad Hosts – SSH | **3,074** |
| Bad Hosts – RDP | **965** |
| Bad Hosts – MSSQL | **470** |
| Bad Hosts – HTTP | **3,031** |
| Bad Hosts – SNMP | **374** |
| Bad Hosts – TFTP | **189** |
| Bad Hosts – VNC | **411** |
| Bad Hosts – ProConOs | **216** |
| Bad Hosts – Telnet | **3,005** |
| Bad Hosts – PostgreSQL | **561** |
| Bad Hosts – MySQL | **612** |
| Bad Hosts – FTP | **537** |
| Bad Hosts – Kubernetes | **724** |
| Bad Hosts – Redis | **472** |
| Bad Hosts – Elasticsearch | **537** |
| Bad Hosts – ClickhouseHTTP | **251** |
| Bad Hosts – CouchDB | **207** |
| Bad Hosts – Oracle | **325** |
| Bad Hosts – Modbus | **202** |
| Bad Hosts – Memcached | **213** |
| Bad Hosts – MQTT | **237** |
| Bad Hosts – RAW | **159** |
| Bad Hosts – IPP | **105** |
| Bad Hosts – LDAP | **205** |
| Bad Hosts – LPD | **68** |
| Bad Hosts – HashCountRandom | **34** |
| Bad Hosts – MOTD | **48** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-26)**: **5,300** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-26 | **5,300** |
| 2026-09-25 | **5,203** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,289** |
| Kandidaten dieses Abrufs | **13,289** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,235** |
| Entfernt | **-1,573** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-26 12:13 CEST (Berlin)*