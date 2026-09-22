# Honigtopf – Report
**Aktualisiert:** 2026-09-22 02:03 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-22 02:03 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,077** |
| Bad Hosts – SIP | **195** |
| Bad Hosts – RDP | **1,000** |
| Bad Hosts – SSH | **4,318** |
| Bad Hosts – MSSQL | **506** |
| Bad Hosts – SNMP | **405** |
| Bad Hosts – HTTP | **3,739** |
| Bad Hosts – TFTP | **186** |
| Bad Hosts – VNC | **381** |
| Bad Hosts – Telnet | **2,869** |
| Bad Hosts – MySQL | **564** |
| Bad Hosts – ProConOs | **146** |
| Bad Hosts – PostgreSQL | **542** |
| Bad Hosts – FTP | **568** |
| Bad Hosts – Kubernetes | **687** |
| Bad Hosts – Redis | **377** |
| Bad Hosts – Elasticsearch | **510** |
| Bad Hosts – CouchDB | **295** |
| Bad Hosts – Oracle | **270** |
| Bad Hosts – ClickhouseHTTP | **221** |
| Bad Hosts – LDAP | **227** |
| Bad Hosts – Memcached | **188** |
| Bad Hosts – MQTT | **178** |
| Bad Hosts – Modbus | **161** |
| Bad Hosts – RAW | **182** |
| Bad Hosts – IPP | **104** |
| Bad Hosts – LPD | **94** |
| Bad Hosts – HashCountRandom | **69** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – MOTD | **50** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-22)**: **35** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-22 | **35** |
| 2026-09-21 | **12,042** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,886** |
| Kandidaten dieses Abrufs | **14,886** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+110** |
| Entfernt | **-89** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-22 02:03 CEST (Berlin)*