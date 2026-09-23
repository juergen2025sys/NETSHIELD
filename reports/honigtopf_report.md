# Honigtopf – Report
**Aktualisiert:** 2026-09-23 20:40 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 20:40 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,597** |
| Bad Hosts – SIP | **162** |
| Bad Hosts – RDP | **1,115** |
| Bad Hosts – SSH | **4,033** |
| Bad Hosts – MSSQL | **624** |
| Bad Hosts – SNMP | **399** |
| Bad Hosts – HTTP | **3,073** |
| Bad Hosts – VNC | **385** |
| Bad Hosts – TFTP | **184** |
| Bad Hosts – Telnet | **2,833** |
| Bad Hosts – ProConOs | **205** |
| Bad Hosts – MySQL | **678** |
| Bad Hosts – FTP | **584** |
| Bad Hosts – PostgreSQL | **494** |
| Bad Hosts – Kubernetes | **813** |
| Bad Hosts – Redis | **497** |
| Bad Hosts – CouchDB | **354** |
| Bad Hosts – Elasticsearch | **600** |
| Bad Hosts – Oracle | **316** |
| Bad Hosts – ClickhouseHTTP | **232** |
| Bad Hosts – Memcached | **259** |
| Bad Hosts – Modbus | **257** |
| Bad Hosts – RAW | **226** |
| Bad Hosts – LDAP | **310** |
| Bad Hosts – MQTT | **243** |
| Bad Hosts – IPP | **100** |
| Bad Hosts – HashCountRandom | **77** |
| Bad Hosts – LPD | **84** |
| Bad Hosts – MOTD | **65** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-23)**: **9,834** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-23 | **9,834** |
| 2026-09-22 | **1,763** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,485** |
| Kandidaten dieses Abrufs | **14,485** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+653** |
| Entfernt | **-1,516** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 20:40 CEST (Berlin)*