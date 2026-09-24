# Honigtopf – Report
**Aktualisiert:** 2026-09-24 03:38 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-24 03:38 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,452** |
| Bad Hosts – SIP | **162** |
| Bad Hosts – RDP | **1,133** |
| Bad Hosts – SSH | **4,016** |
| Bad Hosts – MSSQL | **625** |
| Bad Hosts – HTTP | **3,149** |
| Bad Hosts – VNC | **381** |
| Bad Hosts – SNMP | **337** |
| Bad Hosts – TFTP | **188** |
| Bad Hosts – Telnet | **2,965** |
| Bad Hosts – MySQL | **670** |
| Bad Hosts – PostgreSQL | **503** |
| Bad Hosts – ProConOs | **196** |
| Bad Hosts – FTP | **622** |
| Bad Hosts – Kubernetes | **873** |
| Bad Hosts – CouchDB | **1,134** |
| Bad Hosts – Redis | **449** |
| Bad Hosts – Elasticsearch | **651** |
| Bad Hosts – Oracle | **289** |
| Bad Hosts – ClickhouseHTTP | **306** |
| Bad Hosts – RAW | **228** |
| Bad Hosts – Modbus | **297** |
| Bad Hosts – Memcached | **292** |
| Bad Hosts – LDAP | **276** |
| Bad Hosts – MQTT | **234** |
| Bad Hosts – HashCountRandom | **97** |
| Bad Hosts – IPP | **81** |
| Bad Hosts – LPD | **73** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-24)**: **1,405** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-24 | **1,405** |
| 2026-09-23 | **11,047** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,252** |
| Kandidaten dieses Abrufs | **15,252** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+347** |
| Entfernt | **-352** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-24 03:38 CEST (Berlin)*