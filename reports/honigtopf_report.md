# Honigtopf – Report
**Aktualisiert:** 2026-09-18 17:00 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 17:00 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **39,676** |
| Bad Hosts – SIP | **172** |
| Bad Hosts – MSSQL | **900** |
| Bad Hosts – VNC | **1,611** |
| Bad Hosts – SSH | **3,850** |
| Bad Hosts – RDP | **1,093** |
| Bad Hosts – SNMP | **443** |
| Bad Hosts – HTTP | **4,442** |
| Bad Hosts – TFTP | **243** |
| Bad Hosts – FTP | **26,442** |
| Bad Hosts – Telnet | **2,997** |
| Bad Hosts – ProConOs | **171** |
| Bad Hosts – PostgreSQL | **540** |
| Bad Hosts – MySQL | **669** |
| Bad Hosts – Kubernetes | **741** |
| Bad Hosts – Redis | **412** |
| Bad Hosts – Elasticsearch | **403** |
| Bad Hosts – CouchDB | **246** |
| Bad Hosts – Oracle | **296** |
| Bad Hosts – ClickhouseHTTP | **271** |
| Bad Hosts – RAW | **289** |
| Bad Hosts – LDAP | **240** |
| Bad Hosts – Modbus | **161** |
| Bad Hosts – Memcached | **235** |
| Bad Hosts – MQTT | **240** |
| Bad Hosts – IPP | **92** |
| Bad Hosts – HashCountRandom | **211** |
| Bad Hosts – LPD | **72** |
| Bad Hosts – MOTD | **56** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **24,353** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **24,353** |
| 2026-09-17 | **15,323** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **43,235** |
| Kandidaten dieses Abrufs | **43,235** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+884** |
| Entfernt | **-917** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 17:00 CEST (Berlin)*