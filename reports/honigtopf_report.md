# Honigtopf – Report
**Aktualisiert:** 2026-09-18 21:38 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 21:38 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **38,823** |
| Bad Hosts – SIP | **179** |
| Bad Hosts – MSSQL | **920** |
| Bad Hosts – VNC | **1,622** |
| Bad Hosts – SSH | **3,809** |
| Bad Hosts – RDP | **1,080** |
| Bad Hosts – SNMP | **442** |
| Bad Hosts – HTTP | **4,544** |
| Bad Hosts – TFTP | **240** |
| Bad Hosts – FTP | **25,777** |
| Bad Hosts – Telnet | **2,935** |
| Bad Hosts – PostgreSQL | **541** |
| Bad Hosts – ProConOs | **161** |
| Bad Hosts – MySQL | **638** |
| Bad Hosts – Kubernetes | **708** |
| Bad Hosts – Redis | **440** |
| Bad Hosts – Elasticsearch | **399** |
| Bad Hosts – CouchDB | **248** |
| Bad Hosts – ClickhouseHTTP | **266** |
| Bad Hosts – Oracle | **263** |
| Bad Hosts – Modbus | **170** |
| Bad Hosts – RAW | **261** |
| Bad Hosts – LDAP | **236** |
| Bad Hosts – MQTT | **238** |
| Bad Hosts – Memcached | **235** |
| Bad Hosts – HashCountRandom | **198** |
| Bad Hosts – IPP | **102** |
| Bad Hosts – LPD | **82** |
| Bad Hosts – MOTD | **54** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **32,972** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **32,972** |
| 2026-09-17 | **5,851** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **42,290** |
| Kandidaten dieses Abrufs | **42,290** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,173** |
| Entfernt | **-1,977** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 21:38 CEST (Berlin)*