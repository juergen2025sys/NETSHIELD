# Honigtopf – Report
**Aktualisiert:** 2026-10-04 06:13 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 06:13 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,782** |
| Bad Hosts – SIP | **190** |
| Bad Hosts – MSSQL | **497** |
| Bad Hosts – SSH | **3,675** |
| Bad Hosts – SNMP | **410** |
| Bad Hosts – RDP | **752** |
| Bad Hosts – HTTP | **3,171** |
| Bad Hosts – VNC | **236** |
| Bad Hosts – MySQL | **630** |
| Bad Hosts – ProConOs | **146** |
| Bad Hosts – Telnet | **2,717** |
| Bad Hosts – TFTP | **206** |
| Bad Hosts – Redis | **403** |
| Bad Hosts – PostgreSQL | **388** |
| Bad Hosts – CouchDB | **410** |
| Bad Hosts – FTP | **477** |
| Bad Hosts – Elasticsearch | **620** |
| Bad Hosts – Kubernetes | **660** |
| Bad Hosts – Oracle | **328** |
| Bad Hosts – ClickhouseHTTP | **299** |
| Bad Hosts – Memcached | **217** |
| Bad Hosts – Modbus | **177** |
| Bad Hosts – LDAP | **201** |
| Bad Hosts – MQTT | **208** |
| Bad Hosts – RAW | **130** |
| Bad Hosts – IPP | **99** |
| Bad Hosts – LPD | **66** |
| Bad Hosts – HashCountRandom | **58** |
| Bad Hosts – MOTD | **69** |
| Bad Hosts – Random | **1** |
| Bad Hosts – Telnet.IoT | **1** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **2,738** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **2,738** |
| 2026-10-03 | **8,044** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,566** |
| Kandidaten dieses Abrufs | **13,566** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+687** |
| Entfernt | **-651** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 06:13 CEST (Berlin)*