# Honigtopf – Report
**Aktualisiert:** 2026-09-22 05:01 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-22 05:01 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,092** |
| Bad Hosts – SIP | **213** |
| Bad Hosts – RDP | **1,014** |
| Bad Hosts – SSH | **4,337** |
| Bad Hosts – MSSQL | **500** |
| Bad Hosts – SNMP | **374** |
| Bad Hosts – HTTP | **3,772** |
| Bad Hosts – TFTP | **215** |
| Bad Hosts – MySQL | **595** |
| Bad Hosts – Telnet | **2,822** |
| Bad Hosts – VNC | **379** |
| Bad Hosts – ProConOs | **135** |
| Bad Hosts – PostgreSQL | **546** |
| Bad Hosts – FTP | **614** |
| Bad Hosts – Kubernetes | **679** |
| Bad Hosts – Redis | **382** |
| Bad Hosts – Elasticsearch | **577** |
| Bad Hosts – CouchDB | **271** |
| Bad Hosts – Oracle | **249** |
| Bad Hosts – ClickhouseHTTP | **230** |
| Bad Hosts – MQTT | **184** |
| Bad Hosts – LDAP | **238** |
| Bad Hosts – Memcached | **201** |
| Bad Hosts – Modbus | **156** |
| Bad Hosts – RAW | **178** |
| Bad Hosts – IPP | **102** |
| Bad Hosts – LPD | **72** |
| Bad Hosts – HashCountRandom | **68** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – MOTD | **51** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-22)**: **2,370** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-22 | **2,370** |
| 2026-09-21 | **9,722** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,957** |
| Kandidaten dieses Abrufs | **14,957** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+737** |
| Entfernt | **-901** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-22 05:01 CEST (Berlin)*