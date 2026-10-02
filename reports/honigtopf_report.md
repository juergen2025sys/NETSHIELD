# Honigtopf – Report
**Aktualisiert:** 2026-10-03 01:54 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-03 01:54 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,327** |
| Bad Hosts – SIP | **166** |
| Bad Hosts – SSH | **2,839** |
| Bad Hosts – VNC | **403** |
| Bad Hosts – SNMP | **390** |
| Bad Hosts – MSSQL | **520** |
| Bad Hosts – HTTP | **4,346** |
| Bad Hosts – RDP | **778** |
| Bad Hosts – MySQL | **599** |
| Bad Hosts – Telnet | **3,022** |
| Bad Hosts – ProConOs | **179** |
| Bad Hosts – FTP | **516** |
| Bad Hosts – TFTP | **204** |
| Bad Hosts – PostgreSQL | **475** |
| Bad Hosts – Kubernetes | **774** |
| Bad Hosts – CouchDB | **325** |
| Bad Hosts – Redis | **463** |
| Bad Hosts – Elasticsearch | **498** |
| Bad Hosts – ClickhouseHTTP | **331** |
| Bad Hosts – Oracle | **276** |
| Bad Hosts – Modbus | **196** |
| Bad Hosts – LDAP | **233** |
| Bad Hosts – MQTT | **211** |
| Bad Hosts – RAW | **126** |
| Bad Hosts – Memcached | **238** |
| Bad Hosts – IPP | **129** |
| Bad Hosts – LPD | **72** |
| Bad Hosts – HashCountRandom | **94** |
| Bad Hosts – MOTD | **35** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **11,248** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-03 | **13** |
| 2026-10-02 | **11,248** |
| 2026-10-01 | **66** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,317** |
| Kandidaten dieses Abrufs | **14,317** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+148** |
| Entfernt | **-77** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-03 01:54 CEST (Berlin)*