# Honigtopf – Report
**Aktualisiert:** 2026-10-05 18:19 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-05 18:19 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,223** |
| Bad Hosts – SSH | **4,007** |
| Bad Hosts – SIP | **174** |
| Bad Hosts – SNMP | **423** |
| Bad Hosts – MSSQL | **472** |
| Bad Hosts – RDP | **821** |
| Bad Hosts – HTTP | **3,197** |
| Bad Hosts – Telnet | **2,660** |
| Bad Hosts – MySQL | **572** |
| Bad Hosts – VNC | **353** |
| Bad Hosts – ProConOs | **121** |
| Bad Hosts – TFTP | **189** |
| Bad Hosts – FTP | **477** |
| Bad Hosts – Redis | **394** |
| Bad Hosts – Kubernetes | **732** |
| Bad Hosts – PostgreSQL | **505** |
| Bad Hosts – Memcached | **213** |
| Bad Hosts – Elasticsearch | **658** |
| Bad Hosts – ClickhouseHTTP | **370** |
| Bad Hosts – CouchDB | **381** |
| Bad Hosts – LDAP | **192** |
| Bad Hosts – Oracle | **280** |
| Bad Hosts – Modbus | **191** |
| Bad Hosts – MQTT | **205** |
| Bad Hosts – RAW | **100** |
| Bad Hosts – IPP | **97** |
| Bad Hosts – HashCountRandom | **63** |
| Bad Hosts – LPD | **61** |
| Bad Hosts – MOTD | **65** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-05)**: **8,703** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-05 | **8,703** |
| 2026-10-04 | **2,520** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,914** |
| Kandidaten dieses Abrufs | **13,914** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+164** |
| Entfernt | **-513** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-05 18:19 CEST (Berlin)*