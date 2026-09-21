# Honigtopf – Report
**Aktualisiert:** 2026-09-21 07:20 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-21 07:20 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,042** |
| Bad Hosts – RDP | **1,058** |
| Bad Hosts – SSH | **4,510** |
| Bad Hosts – SIP | **196** |
| Bad Hosts – MSSQL | **586** |
| Bad Hosts – SNMP | **391** |
| Bad Hosts – HTTP | **2,351** |
| Bad Hosts – VNC | **1,362** |
| Bad Hosts – Telnet | **2,964** |
| Bad Hosts – ProConOs | **145** |
| Bad Hosts – TFTP | **267** |
| Bad Hosts – PostgreSQL | **534** |
| Bad Hosts – FTP | **358** |
| Bad Hosts – MySQL | **418** |
| Bad Hosts – Kubernetes | **688** |
| Bad Hosts – Redis | **306** |
| Bad Hosts – Elasticsearch | **340** |
| Bad Hosts – CouchDB | **185** |
| Bad Hosts – Oracle | **277** |
| Bad Hosts – ClickhouseHTTP | **208** |
| Bad Hosts – Memcached | **171** |
| Bad Hosts – RAW | **203** |
| Bad Hosts – LDAP | **225** |
| Bad Hosts – Modbus | **151** |
| Bad Hosts – MQTT | **196** |
| Bad Hosts – IPP | **100** |
| Bad Hosts – LPD | **74** |
| Bad Hosts – HashCountRandom | **39** |
| Bad Hosts – MOTD | **55** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-21)**: **3,283** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-21 | **3,283** |
| 2026-09-20 | **8,759** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,588** |
| Kandidaten dieses Abrufs | **14,588** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+63** |
| Entfernt | **-87** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-21 07:20 CEST (Berlin)*