# Honigtopf – Report
**Aktualisiert:** 2026-09-25 22:29 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-25 22:29 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,062** |
| Bad Hosts – SIP | **151** |
| Bad Hosts – SSH | **3,238** |
| Bad Hosts – RDP | **810** |
| Bad Hosts – MSSQL | **488** |
| Bad Hosts – HTTP | **3,577** |
| Bad Hosts – VNC | **334** |
| Bad Hosts – TFTP | **194** |
| Bad Hosts – ProConOs | **137** |
| Bad Hosts – SNMP | **355** |
| Bad Hosts – Telnet | **2,868** |
| Bad Hosts – PostgreSQL | **425** |
| Bad Hosts – MySQL | **599** |
| Bad Hosts – FTP | **520** |
| Bad Hosts – Kubernetes | **644** |
| Bad Hosts – Elasticsearch | **539** |
| Bad Hosts – Redis | **440** |
| Bad Hosts – CouchDB | **216** |
| Bad Hosts – ClickhouseHTTP | **238** |
| Bad Hosts – Oracle | **258** |
| Bad Hosts – Memcached | **197** |
| Bad Hosts – Modbus | **170** |
| Bad Hosts – MQTT | **192** |
| Bad Hosts – LDAP | **203** |
| Bad Hosts – RAW | **120** |
| Bad Hosts – IPP | **83** |
| Bad Hosts – LPD | **50** |
| Bad Hosts – HashCountRandom | **26** |
| Bad Hosts – MOTD | **16** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-25)**: **9,819** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-25 | **9,819** |
| 2026-09-24 | **1,243** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,518** |
| Kandidaten dieses Abrufs | **13,518** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+538** |
| Entfernt | **-597** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-25 22:29 CEST (Berlin)*