# Honigtopf – Report
**Aktualisiert:** 2026-09-20 23:40 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-20 23:40 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **16,159** |
| Bad Hosts – RDP | **1,048** |
| Bad Hosts – SSH | **4,689** |
| Bad Hosts – MSSQL | **617** |
| Bad Hosts – SIP | **204** |
| Bad Hosts – SNMP | **390** |
| Bad Hosts – VNC | **1,598** |
| Bad Hosts – HTTP | **3,282** |
| Bad Hosts – Telnet | **2,907** |
| Bad Hosts – MySQL | **467** |
| Bad Hosts – TFTP | **271** |
| Bad Hosts – FTP | **2,960** |
| Bad Hosts – ProConOs | **105** |
| Bad Hosts – PostgreSQL | **512** |
| Bad Hosts – Kubernetes | **647** |
| Bad Hosts – Redis | **320** |
| Bad Hosts – Elasticsearch | **403** |
| Bad Hosts – CouchDB | **203** |
| Bad Hosts – Memcached | **248** |
| Bad Hosts – Oracle | **287** |
| Bad Hosts – ClickhouseHTTP | **215** |
| Bad Hosts – LDAP | **220** |
| Bad Hosts – RAW | **172** |
| Bad Hosts – Modbus | **202** |
| Bad Hosts – MQTT | **198** |
| Bad Hosts – HashCountRandom | **59** |
| Bad Hosts – IPP | **88** |
| Bad Hosts – LPD | **67** |
| Bad Hosts – MOTD | **57** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-20)**: **13,215** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-20 | **13,215** |
| 2026-09-19 | **2,944** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **18,874** |
| Kandidaten dieses Abrufs | **18,874** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+795** |
| Entfernt | **-3,624** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-20 23:40 CEST (Berlin)*