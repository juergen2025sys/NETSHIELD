# Honigtopf – Report
**Aktualisiert:** 2026-09-24 08:18 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-24 08:18 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,682** |
| Bad Hosts – SIP | **174** |
| Bad Hosts – RDP | **1,169** |
| Bad Hosts – SSH | **3,932** |
| Bad Hosts – MSSQL | **637** |
| Bad Hosts – VNC | **403** |
| Bad Hosts – HTTP | **3,349** |
| Bad Hosts – SNMP | **325** |
| Bad Hosts – TFTP | **187** |
| Bad Hosts – Telnet | **2,939** |
| Bad Hosts – ProConOs | **213** |
| Bad Hosts – MySQL | **710** |
| Bad Hosts – PostgreSQL | **434** |
| Bad Hosts – FTP | **622** |
| Bad Hosts – Kubernetes | **962** |
| Bad Hosts – CouchDB | **1,125** |
| Bad Hosts – Elasticsearch | **696** |
| Bad Hosts – Redis | **456** |
| Bad Hosts – ClickhouseHTTP | **302** |
| Bad Hosts – Oracle | **271** |
| Bad Hosts – RAW | **212** |
| Bad Hosts – Modbus | **319** |
| Bad Hosts – Memcached | **304** |
| Bad Hosts – LDAP | **277** |
| Bad Hosts – MQTT | **248** |
| Bad Hosts – HashCountRandom | **85** |
| Bad Hosts – IPP | **107** |
| Bad Hosts – LPD | **61** |
| Bad Hosts – MOTD | **63** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-24)**: **4,368** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-24 | **4,368** |
| 2026-09-23 | **8,314** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,466** |
| Kandidaten dieses Abrufs | **15,466** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+361** |
| Entfernt | **-390** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-24 08:18 CEST (Berlin)*