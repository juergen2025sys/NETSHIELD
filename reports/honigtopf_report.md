# Honigtopf – Report
**Aktualisiert:** 2026-10-05 01:30 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 01:30 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,370** |
| Bad Hosts – SIP | **176** |
| Bad Hosts – SSH | **3,909** |
| Bad Hosts – SNMP | **381** |
| Bad Hosts – MSSQL | **453** |
| Bad Hosts – RDP | **700** |
| Bad Hosts – HTTP | **2,539** |
| Bad Hosts – Telnet | **2,723** |
| Bad Hosts – VNC | **351** |
| Bad Hosts – ProConOs | **152** |
| Bad Hosts – TFTP | **189** |
| Bad Hosts – FTP | **350** |
| Bad Hosts – MySQL | **409** |
| Bad Hosts – Redis | **404** |
| Bad Hosts – PostgreSQL | **566** |
| Bad Hosts – Kubernetes | **672** |
| Bad Hosts – CouchDB | **348** |
| Bad Hosts – ClickhouseHTTP | **368** |
| Bad Hosts – Elasticsearch | **527** |
| Bad Hosts – Oracle | **275** |
| Bad Hosts – Memcached | **223** |
| Bad Hosts – Modbus | **200** |
| Bad Hosts – LDAP | **208** |
| Bad Hosts – MQTT | **211** |
| Bad Hosts – IPP | **111** |
| Bad Hosts – RAW | **107** |
| Bad Hosts – LPD | **84** |
| Bad Hosts – HashCountRandom | **36** |
| Bad Hosts – MOTD | **62** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **10,205** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **23** |
| 2026-10-04 | **10,205** |
| 2026-10-03 | **142** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **12,895** |
| Kandidaten dieses Abrufs | **12,895** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+575** |
| Entfernt | **-614** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 01:30 CEST (Berlin)*