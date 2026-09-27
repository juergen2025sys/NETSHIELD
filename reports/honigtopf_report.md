# Honigtopf – Report
**Aktualisiert:** 2026-09-27 15:16 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-27 15:16 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,525** |
| Bad Hosts – SIP | **162** |
| Bad Hosts – SSH | **3,104** |
| Bad Hosts – RDP | **932** |
| Bad Hosts – MSSQL | **462** |
| Bad Hosts – SNMP | **340** |
| Bad Hosts – HTTP | **3,021** |
| Bad Hosts – TFTP | **183** |
| Bad Hosts – PostgreSQL | **519** |
| Bad Hosts – ProConOs | **126** |
| Bad Hosts – Telnet | **2,956** |
| Bad Hosts – VNC | **422** |
| Bad Hosts – MySQL | **530** |
| Bad Hosts – Kubernetes | **802** |
| Bad Hosts – Redis | **434** |
| Bad Hosts – FTP | **448** |
| Bad Hosts – Elasticsearch | **452** |
| Bad Hosts – CouchDB | **273** |
| Bad Hosts – Oracle | **197** |
| Bad Hosts – ClickhouseHTTP | **223** |
| Bad Hosts – Memcached | **254** |
| Bad Hosts – RAW | **151** |
| Bad Hosts – Modbus | **202** |
| Bad Hosts – IPP | **142** |
| Bad Hosts – MQTT | **157** |
| Bad Hosts – LDAP | **194** |
| Bad Hosts – HashCountRandom | **46** |
| Bad Hosts – LPD | **64** |
| Bad Hosts – MOTD | **58** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-27)**: **6,634** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-27 | **6,634** |
| 2026-09-26 | **3,891** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,038** |
| Kandidaten dieses Abrufs | **13,038** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+546** |
| Entfernt | **-599** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-27 15:16 CEST (Berlin)*