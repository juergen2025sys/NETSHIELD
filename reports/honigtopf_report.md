# Honigtopf – Report
**Aktualisiert:** 2026-09-23 09:14 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 09:14 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,352** |
| Bad Hosts – SIP | **234** |
| Bad Hosts – RDP | **994** |
| Bad Hosts – SSH | **4,022** |
| Bad Hosts – MSSQL | **604** |
| Bad Hosts – SNMP | **398** |
| Bad Hosts – HTTP | **2,845** |
| Bad Hosts – VNC | **425** |
| Bad Hosts – Telnet | **2,777** |
| Bad Hosts – TFTP | **193** |
| Bad Hosts – MySQL | **709** |
| Bad Hosts – ProConOs | **154** |
| Bad Hosts – PostgreSQL | **571** |
| Bad Hosts – FTP | **622** |
| Bad Hosts – Kubernetes | **713** |
| Bad Hosts – Redis | **469** |
| Bad Hosts – Elasticsearch | **609** |
| Bad Hosts – CouchDB | **282** |
| Bad Hosts – ClickhouseHTTP | **279** |
| Bad Hosts – Oracle | **318** |
| Bad Hosts – RAW | **274** |
| Bad Hosts – LDAP | **338** |
| Bad Hosts – Modbus | **219** |
| Bad Hosts – Memcached | **269** |
| Bad Hosts – MQTT | **243** |
| Bad Hosts – IPP | **137** |
| Bad Hosts – LPD | **109** |
| Bad Hosts – HashCountRandom | **111** |
| Bad Hosts – MOTD | **53** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-23)**: **4,568** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-23 | **4,568** |
| 2026-09-22 | **6,784** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,394** |
| Kandidaten dieses Abrufs | **14,394** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+528** |
| Entfernt | **-699** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 09:14 CEST (Berlin)*