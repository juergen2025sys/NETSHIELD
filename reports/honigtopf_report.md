# Honigtopf – Report
**Aktualisiert:** 2026-09-16 16:47 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-16 16:47 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **45,839** |
| Bad Hosts – SIP | **210** |
| Bad Hosts – RDP | **1,279** |
| Bad Hosts – MSSQL | **595** |
| Bad Hosts – SSH | **3,613** |
| Bad Hosts – HTTP | **4,595** |
| Bad Hosts – FTP | **32,580** |
| Bad Hosts – VNC | **1,612** |
| Bad Hosts – TFTP | **315** |
| Bad Hosts – SNMP | **494** |
| Bad Hosts – Telnet | **3,372** |
| Bad Hosts – ProConOs | **147** |
| Bad Hosts – MySQL | **758** |
| Bad Hosts – PostgreSQL | **632** |
| Bad Hosts – Kubernetes | **936** |
| Bad Hosts – Redis | **446** |
| Bad Hosts – Elasticsearch | **535** |
| Bad Hosts – CouchDB | **269** |
| Bad Hosts – ClickhouseHTTP | **316** |
| Bad Hosts – Oracle | **267** |
| Bad Hosts – Memcached | **244** |
| Bad Hosts – Modbus | **251** |
| Bad Hosts – LDAP | **254** |
| Bad Hosts – RAW | **205** |
| Bad Hosts – MQTT | **221** |
| Bad Hosts – IPP | **122** |
| Bad Hosts – HashCountRandom | **171** |
| Bad Hosts – LPD | **83** |
| Bad Hosts – MOTD | **61** |
| Bad Hosts – WebLogic | **3** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-16)**: **28,200** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-16 | **28,200** |
| 2026-09-15 | **17,639** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **49,848** |
| Kandidaten dieses Abrufs | **49,848** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,694** |
| Entfernt | **-9,839** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-16 16:47 CEST (Berlin)*