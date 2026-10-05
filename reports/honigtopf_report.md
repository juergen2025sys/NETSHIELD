# Honigtopf – Report
**Aktualisiert:** 2026-10-05 20:52 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 20:52 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,313** |
| Bad Hosts – SSH | **3,976** |
| Bad Hosts – SIP | **173** |
| Bad Hosts – SNMP | **431** |
| Bad Hosts – MSSQL | **467** |
| Bad Hosts – RDP | **820** |
| Bad Hosts – HTTP | **3,308** |
| Bad Hosts – MySQL | **597** |
| Bad Hosts – Telnet | **2,687** |
| Bad Hosts – VNC | **338** |
| Bad Hosts – ProConOs | **119** |
| Bad Hosts – TFTP | **200** |
| Bad Hosts – FTP | **494** |
| Bad Hosts – Kubernetes | **786** |
| Bad Hosts – Redis | **387** |
| Bad Hosts – PostgreSQL | **530** |
| Bad Hosts – Memcached | **189** |
| Bad Hosts – Elasticsearch | **644** |
| Bad Hosts – ClickhouseHTTP | **362** |
| Bad Hosts – CouchDB | **404** |
| Bad Hosts – LDAP | **209** |
| Bad Hosts – Oracle | **283** |
| Bad Hosts – Modbus | **212** |
| Bad Hosts – MQTT | **207** |
| Bad Hosts – RAW | **108** |
| Bad Hosts – IPP | **94** |
| Bad Hosts – HashCountRandom | **78** |
| Bad Hosts – LPD | **60** |
| Bad Hosts – MOTD | **72** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **9,670** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **9,670** |
| 2026-10-04 | **1,643** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,048** |
| Kandidaten dieses Abrufs | **14,048** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+963** |
| Entfernt | **-823** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 20:52 CEST (Berlin)*