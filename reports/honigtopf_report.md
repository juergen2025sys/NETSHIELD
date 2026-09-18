# Honigtopf – Report
**Aktualisiert:** 2026-09-18 13:35 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 13:35 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **40,384** |
| Bad Hosts – SIP | **177** |
| Bad Hosts – MSSQL | **926** |
| Bad Hosts – VNC | **1,551** |
| Bad Hosts – SSH | **3,896** |
| Bad Hosts – RDP | **1,161** |
| Bad Hosts – SNMP | **433** |
| Bad Hosts – HTTP | **4,547** |
| Bad Hosts – TFTP | **232** |
| Bad Hosts – FTP | **27,074** |
| Bad Hosts – ProConOs | **174** |
| Bad Hosts – Telnet | **3,057** |
| Bad Hosts – PostgreSQL | **582** |
| Bad Hosts – MySQL | **677** |
| Bad Hosts – Kubernetes | **784** |
| Bad Hosts – Redis | **395** |
| Bad Hosts – Elasticsearch | **432** |
| Bad Hosts – CouchDB | **255** |
| Bad Hosts – Oracle | **300** |
| Bad Hosts – ClickhouseHTTP | **264** |
| Bad Hosts – Modbus | **200** |
| Bad Hosts – Memcached | **257** |
| Bad Hosts – RAW | **225** |
| Bad Hosts – LDAP | **213** |
| Bad Hosts – MQTT | **264** |
| Bad Hosts – IPP | **104** |
| Bad Hosts – HashCountRandom | **197** |
| Bad Hosts – LPD | **62** |
| Bad Hosts – MOTD | **64** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **18,582** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **18,582** |
| 2026-09-17 | **21,802** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **43,683** |
| Kandidaten dieses Abrufs | **43,683** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+542** |
| Entfernt | **-971** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 13:35 CEST (Berlin)*