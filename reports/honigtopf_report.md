# Honigtopf – Report
**Aktualisiert:** 2026-10-01 15:50 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-01 15:50 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,600** |
| Bad Hosts – SIP | **163** |
| Bad Hosts – SSH | **3,940** |
| Bad Hosts – RDP | **698** |
| Bad Hosts – MSSQL | **459** |
| Bad Hosts – HTTP | **2,792** |
| Bad Hosts – SNMP | **432** |
| Bad Hosts – VNC | **280** |
| Bad Hosts – MySQL | **565** |
| Bad Hosts – Telnet | **2,895** |
| Bad Hosts – FTP | **429** |
| Bad Hosts – ProConOs | **95** |
| Bad Hosts – PostgreSQL | **346** |
| Bad Hosts – TFTP | **256** |
| Bad Hosts – Kubernetes | **497** |
| Bad Hosts – Elasticsearch | **565** |
| Bad Hosts – Redis | **349** |
| Bad Hosts – CouchDB | **272** |
| Bad Hosts – Oracle | **317** |
| Bad Hosts – ClickhouseHTTP | **284** |
| Bad Hosts – Modbus | **158** |
| Bad Hosts – Memcached | **162** |
| Bad Hosts – RAW | **102** |
| Bad Hosts – MQTT | **176** |
| Bad Hosts – LDAP | **158** |
| Bad Hosts – IPP | **102** |
| Bad Hosts – HashCountRandom | **116** |
| Bad Hosts – LPD | **63** |
| Bad Hosts – MOTD | **70** |
| Bad Hosts – Echo | **6** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-01)**: **6,474** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-01 | **6,474** |
| 2026-09-30 | **4,126** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,236** |
| Kandidaten dieses Abrufs | **13,236** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+12** |
| Entfernt | **-2** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-01 15:50 CEST (Berlin)*