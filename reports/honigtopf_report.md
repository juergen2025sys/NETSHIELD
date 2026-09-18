# Honigtopf – Report
**Aktualisiert:** 2026-09-18 03:15 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 03:15 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **41,916** |
| Bad Hosts – VNC | **1,540** |
| Bad Hosts – SIP | **178** |
| Bad Hosts – MSSQL | **959** |
| Bad Hosts – SSH | **3,841** |
| Bad Hosts – RDP | **1,028** |
| Bad Hosts – SNMP | **492** |
| Bad Hosts – HTTP | **4,470** |
| Bad Hosts – FTP | **28,594** |
| Bad Hosts – TFTP | **253** |
| Bad Hosts – ProConOs | **166** |
| Bad Hosts – Telnet | **3,097** |
| Bad Hosts – MySQL | **708** |
| Bad Hosts – PostgreSQL | **518** |
| Bad Hosts – Kubernetes | **768** |
| Bad Hosts – Redis | **444** |
| Bad Hosts – Elasticsearch | **536** |
| Bad Hosts – Oracle | **298** |
| Bad Hosts – CouchDB | **260** |
| Bad Hosts – ClickhouseHTTP | **262** |
| Bad Hosts – Modbus | **248** |
| Bad Hosts – RAW | **219** |
| Bad Hosts – LDAP | **210** |
| Bad Hosts – IPP | **125** |
| Bad Hosts – Memcached | **247** |
| Bad Hosts – MQTT | **231** |
| Bad Hosts – HashCountRandom | **267** |
| Bad Hosts – LPD | **44** |
| Bad Hosts – MOTD | **56** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **1,692** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **1,692** |
| 2026-09-17 | **40,224** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **45,103** |
| Kandidaten dieses Abrufs | **45,103** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,190** |
| Entfernt | **-1,086** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 03:15 CEST (Berlin)*