# Honigtopf – Report
**Aktualisiert:** 2026-09-18 09:56 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 09:56 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **41,124** |
| Bad Hosts – SIP | **172** |
| Bad Hosts – VNC | **1,555** |
| Bad Hosts – MSSQL | **938** |
| Bad Hosts – SSH | **3,860** |
| Bad Hosts – RDP | **1,162** |
| Bad Hosts – SNMP | **478** |
| Bad Hosts – HTTP | **4,381** |
| Bad Hosts – FTP | **27,849** |
| Bad Hosts – TFTP | **241** |
| Bad Hosts – ProConOs | **163** |
| Bad Hosts – Telnet | **3,083** |
| Bad Hosts – PostgreSQL | **576** |
| Bad Hosts – MySQL | **720** |
| Bad Hosts – Kubernetes | **777** |
| Bad Hosts – Redis | **422** |
| Bad Hosts – Elasticsearch | **441** |
| Bad Hosts – CouchDB | **259** |
| Bad Hosts – Oracle | **281** |
| Bad Hosts – ClickhouseHTTP | **247** |
| Bad Hosts – Modbus | **242** |
| Bad Hosts – Memcached | **256** |
| Bad Hosts – LDAP | **208** |
| Bad Hosts – MQTT | **254** |
| Bad Hosts – RAW | **168** |
| Bad Hosts – IPP | **106** |
| Bad Hosts – HashCountRandom | **224** |
| Bad Hosts – LPD | **41** |
| Bad Hosts – MOTD | **65** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **11,303** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **11,303** |
| 2026-09-17 | **29,821** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **44,526** |
| Kandidaten dieses Abrufs | **44,526** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,715** |
| Entfernt | **-2,964** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 09:56 CEST (Berlin)*