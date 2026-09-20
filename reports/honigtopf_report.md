# Honigtopf – Report
**Aktualisiert:** 2026-09-20 07:20 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-20 07:20 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **36,699** |
| Bad Hosts – SIP | **193** |
| Bad Hosts – RDP | **875** |
| Bad Hosts – SSH | **4,316** |
| Bad Hosts – MSSQL | **764** |
| Bad Hosts – VNC | **1,553** |
| Bad Hosts – SNMP | **442** |
| Bad Hosts – HTTP | **5,121** |
| Bad Hosts – FTP | **22,440** |
| Bad Hosts – TFTP | **197** |
| Bad Hosts – Telnet | **2,934** |
| Bad Hosts – ProConOs | **165** |
| Bad Hosts – MySQL | **614** |
| Bad Hosts – PostgreSQL | **562** |
| Bad Hosts – Kubernetes | **674** |
| Bad Hosts – Oracle | **261** |
| Bad Hosts – Redis | **400** |
| Bad Hosts – Elasticsearch | **541** |
| Bad Hosts – MQTT | **300** |
| Bad Hosts – Memcached | **263** |
| Bad Hosts – CouchDB | **245** |
| Bad Hosts – Modbus | **225** |
| Bad Hosts – ClickhouseHTTP | **210** |
| Bad Hosts – LDAP | **263** |
| Bad Hosts – HashCountRandom | **147** |
| Bad Hosts – RAW | **175** |
| Bad Hosts – IPP | **103** |
| Bad Hosts – LPD | **51** |
| Bad Hosts – MOTD | **79** |
| Bad Hosts – WebLogic | **3** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-20)**: **5,534** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-20 | **5,534** |
| 2026-09-19 | **31,165** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **39,617** |
| Kandidaten dieses Abrufs | **39,617** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,838** |
| Entfernt | **-5,774** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-20 07:20 CEST (Berlin)*