# Honigtopf – Report
**Aktualisiert:** 2026-10-05 08:11 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 08:11 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,833** |
| Bad Hosts – SIP | **172** |
| Bad Hosts – SSH | **4,206** |
| Bad Hosts – SNMP | **380** |
| Bad Hosts – MSSQL | **470** |
| Bad Hosts – RDP | **739** |
| Bad Hosts – HTTP | **2,624** |
| Bad Hosts – Telnet | **2,783** |
| Bad Hosts – ProConOs | **147** |
| Bad Hosts – MySQL | **423** |
| Bad Hosts – VNC | **333** |
| Bad Hosts – TFTP | **188** |
| Bad Hosts – FTP | **402** |
| Bad Hosts – Redis | **429** |
| Bad Hosts – Kubernetes | **764** |
| Bad Hosts – PostgreSQL | **554** |
| Bad Hosts – CouchDB | **369** |
| Bad Hosts – Elasticsearch | **616** |
| Bad Hosts – ClickhouseHTTP | **368** |
| Bad Hosts – LDAP | **201** |
| Bad Hosts – Oracle | **273** |
| Bad Hosts – Memcached | **230** |
| Bad Hosts – Modbus | **199** |
| Bad Hosts – MQTT | **195** |
| Bad Hosts – RAW | **104** |
| Bad Hosts – IPP | **90** |
| Bad Hosts – LPD | **81** |
| Bad Hosts – HashCountRandom | **44** |
| Bad Hosts – MOTD | **67** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **4,254** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **4,254** |
| 2026-10-04 | **6,579** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,409** |
| Kandidaten dieses Abrufs | **13,409** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+78** |
| Entfernt | **-74** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 08:11 CEST (Berlin)*