# Honigtopf – Report
**Aktualisiert:** 2026-10-04 22:11 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 22:11 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,369** |
| Bad Hosts – SIP | **171** |
| Bad Hosts – SSH | **3,920** |
| Bad Hosts – SNMP | **401** |
| Bad Hosts – MSSQL | **432** |
| Bad Hosts – RDP | **694** |
| Bad Hosts – HTTP | **2,551** |
| Bad Hosts – VNC | **338** |
| Bad Hosts – Telnet | **2,694** |
| Bad Hosts – ProConOs | **143** |
| Bad Hosts – MySQL | **488** |
| Bad Hosts – TFTP | **192** |
| Bad Hosts – Redis | **421** |
| Bad Hosts – FTP | **376** |
| Bad Hosts – PostgreSQL | **542** |
| Bad Hosts – Kubernetes | **684** |
| Bad Hosts – CouchDB | **343** |
| Bad Hosts – Elasticsearch | **544** |
| Bad Hosts – ClickhouseHTTP | **365** |
| Bad Hosts – Oracle | **294** |
| Bad Hosts – Memcached | **225** |
| Bad Hosts – Modbus | **204** |
| Bad Hosts – LDAP | **180** |
| Bad Hosts – MQTT | **211** |
| Bad Hosts – IPP | **108** |
| Bad Hosts – RAW | **123** |
| Bad Hosts – LPD | **84** |
| Bad Hosts – MOTD | **63** |
| Bad Hosts – HashCountRandom | **35** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **9,099** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **9,099** |
| 2026-10-03 | **1,270** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **12,994** |
| Kandidaten dieses Abrufs | **12,994** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+794** |
| Entfernt | **-1,069** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 22:11 CEST (Berlin)*