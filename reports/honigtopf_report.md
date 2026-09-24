# Honigtopf – Report
**Aktualisiert:** 2026-09-24 14:01 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-24 14:01 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,780** |
| Bad Hosts – SIP | **169** |
| Bad Hosts – RDP | **1,147** |
| Bad Hosts – SSH | **3,865** |
| Bad Hosts – MSSQL | **641** |
| Bad Hosts – VNC | **553** |
| Bad Hosts – HTTP | **3,442** |
| Bad Hosts – TFTP | **174** |
| Bad Hosts – Telnet | **3,043** |
| Bad Hosts – SNMP | **383** |
| Bad Hosts – ProConOs | **215** |
| Bad Hosts – MySQL | **676** |
| Bad Hosts – PostgreSQL | **400** |
| Bad Hosts – Elasticsearch | **577** |
| Bad Hosts – FTP | **579** |
| Bad Hosts – Kubernetes | **1,081** |
| Bad Hosts – CouchDB | **1,100** |
| Bad Hosts – Redis | **492** |
| Bad Hosts – ClickhouseHTTP | **356** |
| Bad Hosts – Oracle | **274** |
| Bad Hosts – RAW | **249** |
| Bad Hosts – Modbus | **315** |
| Bad Hosts – Memcached | **312** |
| Bad Hosts – LDAP | **286** |
| Bad Hosts – MQTT | **285** |
| Bad Hosts – IPP | **103** |
| Bad Hosts – HashCountRandom | **71** |
| Bad Hosts – LPD | **55** |
| Bad Hosts – MOTD | **63** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-24)**: **7,226** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-24 | **7,226** |
| 2026-09-23 | **5,554** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,638** |
| Kandidaten dieses Abrufs | **15,638** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+968** |
| Entfernt | **-2,174** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-24 14:01 CEST (Berlin)*