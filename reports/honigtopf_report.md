# Honigtopf – Report
**Aktualisiert:** 2026-09-24 00:17 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-24 00:17 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,452** |
| Bad Hosts – SIP | **147** |
| Bad Hosts – RDP | **1,151** |
| Bad Hosts – SSH | **3,995** |
| Bad Hosts – MSSQL | **636** |
| Bad Hosts – SNMP | **354** |
| Bad Hosts – HTTP | **3,224** |
| Bad Hosts – VNC | **381** |
| Bad Hosts – TFTP | **180** |
| Bad Hosts – Telnet | **2,860** |
| Bad Hosts – ProConOs | **224** |
| Bad Hosts – MySQL | **687** |
| Bad Hosts – FTP | **649** |
| Bad Hosts – PostgreSQL | **503** |
| Bad Hosts – Kubernetes | **890** |
| Bad Hosts – CouchDB | **1,146** |
| Bad Hosts – Redis | **472** |
| Bad Hosts – Elasticsearch | **656** |
| Bad Hosts – Oracle | **293** |
| Bad Hosts – ClickhouseHTTP | **308** |
| Bad Hosts – Modbus | **281** |
| Bad Hosts – Memcached | **282** |
| Bad Hosts – LDAP | **317** |
| Bad Hosts – RAW | **240** |
| Bad Hosts – MQTT | **245** |
| Bad Hosts – IPP | **104** |
| Bad Hosts – HashCountRandom | **99** |
| Bad Hosts – LPD | **93** |
| Bad Hosts – MOTD | **64** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-23)**: **11,911** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-24 | **5** |
| 2026-09-23 | **11,911** |
| 2026-09-22 | **536** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,262** |
| Kandidaten dieses Abrufs | **15,262** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+174** |
| Entfernt | **-237** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-24 00:17 CEST (Berlin)*