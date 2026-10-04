# Honigtopf – Report
**Aktualisiert:** 2026-10-04 12:34 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 12:34 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,520** |
| Bad Hosts – SIP | **177** |
| Bad Hosts – SSH | **3,845** |
| Bad Hosts – MSSQL | **450** |
| Bad Hosts – SNMP | **406** |
| Bad Hosts – RDP | **690** |
| Bad Hosts – HTTP | **2,923** |
| Bad Hosts – VNC | **260** |
| Bad Hosts – ProConOs | **150** |
| Bad Hosts – MySQL | **564** |
| Bad Hosts – Telnet | **2,677** |
| Bad Hosts – TFTP | **177** |
| Bad Hosts – Redis | **409** |
| Bad Hosts – PostgreSQL | **466** |
| Bad Hosts – CouchDB | **322** |
| Bad Hosts – Kubernetes | **681** |
| Bad Hosts – FTP | **432** |
| Bad Hosts – Elasticsearch | **591** |
| Bad Hosts – ClickhouseHTTP | **326** |
| Bad Hosts – Oracle | **294** |
| Bad Hosts – Memcached | **207** |
| Bad Hosts – Modbus | **197** |
| Bad Hosts – MQTT | **199** |
| Bad Hosts – LDAP | **172** |
| Bad Hosts – IPP | **100** |
| Bad Hosts – RAW | **111** |
| Bad Hosts – LPD | **76** |
| Bad Hosts – HashCountRandom | **50** |
| Bad Hosts – MOTD | **74** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **5,605** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **5,605** |
| 2026-10-03 | **4,915** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,222** |
| Kandidaten dieses Abrufs | **13,222** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+477** |
| Entfernt | **-572** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 12:34 CEST (Berlin)*