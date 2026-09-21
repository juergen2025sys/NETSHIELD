# Honigtopf – Report
**Aktualisiert:** 2026-09-21 08:37 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-21 08:37 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,017** |
| Bad Hosts – RDP | **1,060** |
| Bad Hosts – SSH | **4,524** |
| Bad Hosts – SIP | **197** |
| Bad Hosts – MSSQL | **590** |
| Bad Hosts – SNMP | **368** |
| Bad Hosts – HTTP | **2,448** |
| Bad Hosts – VNC | **1,294** |
| Bad Hosts – Telnet | **2,971** |
| Bad Hosts – ProConOs | **142** |
| Bad Hosts – TFTP | **274** |
| Bad Hosts – PostgreSQL | **540** |
| Bad Hosts – FTP | **362** |
| Bad Hosts – MySQL | **428** |
| Bad Hosts – Kubernetes | **680** |
| Bad Hosts – Redis | **304** |
| Bad Hosts – Elasticsearch | **371** |
| Bad Hosts – ClickhouseHTTP | **212** |
| Bad Hosts – Oracle | **272** |
| Bad Hosts – Memcached | **171** |
| Bad Hosts – RAW | **206** |
| Bad Hosts – LDAP | **228** |
| Bad Hosts – Modbus | **150** |
| Bad Hosts – CouchDB | **198** |
| Bad Hosts – MQTT | **196** |
| Bad Hosts – IPP | **114** |
| Bad Hosts – LPD | **77** |
| Bad Hosts – HashCountRandom | **41** |
| Bad Hosts – MOTD | **54** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-21)**: **3,925** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-21 | **3,925** |
| 2026-09-20 | **8,092** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,602** |
| Kandidaten dieses Abrufs | **14,602** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+580** |
| Entfernt | **-566** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-21 08:37 CEST (Berlin)*