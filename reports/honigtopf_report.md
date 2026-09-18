# Honigtopf – Report
**Aktualisiert:** 2026-09-18 17:12 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 17:12 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **39,616** |
| Bad Hosts – SIP | **172** |
| Bad Hosts – MSSQL | **903** |
| Bad Hosts – VNC | **1,611** |
| Bad Hosts – SSH | **3,860** |
| Bad Hosts – RDP | **1,080** |
| Bad Hosts – SNMP | **441** |
| Bad Hosts – HTTP | **4,425** |
| Bad Hosts – TFTP | **245** |
| Bad Hosts – FTP | **26,444** |
| Bad Hosts – Telnet | **2,995** |
| Bad Hosts – ProConOs | **167** |
| Bad Hosts – PostgreSQL | **544** |
| Bad Hosts – MySQL | **666** |
| Bad Hosts – Kubernetes | **739** |
| Bad Hosts – Redis | **420** |
| Bad Hosts – Elasticsearch | **403** |
| Bad Hosts – CouchDB | **248** |
| Bad Hosts – Oracle | **296** |
| Bad Hosts – ClickhouseHTTP | **278** |
| Bad Hosts – RAW | **279** |
| Bad Hosts – LDAP | **239** |
| Bad Hosts – Modbus | **160** |
| Bad Hosts – Memcached | **216** |
| Bad Hosts – MQTT | **237** |
| Bad Hosts – HashCountRandom | **211** |
| Bad Hosts – IPP | **93** |
| Bad Hosts – LPD | **72** |
| Bad Hosts – MOTD | **56** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **24,829** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **24,829** |
| 2026-09-17 | **14,787** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **43,078** |
| Kandidaten dieses Abrufs | **43,078** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+372** |
| Entfernt | **-529** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 17:12 CEST (Berlin)*