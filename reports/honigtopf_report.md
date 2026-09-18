# Honigtopf – Report
**Aktualisiert:** 2026-09-18 23:18 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 23:18 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **38,502** |
| Bad Hosts – SIP | **191** |
| Bad Hosts – MSSQL | **925** |
| Bad Hosts – SSH | **3,823** |
| Bad Hosts – VNC | **1,602** |
| Bad Hosts – RDP | **1,055** |
| Bad Hosts – SNMP | **443** |
| Bad Hosts – HTTP | **4,499** |
| Bad Hosts – TFTP | **239** |
| Bad Hosts – FTP | **25,572** |
| Bad Hosts – Telnet | **2,917** |
| Bad Hosts – ProConOs | **158** |
| Bad Hosts – PostgreSQL | **554** |
| Bad Hosts – MySQL | **572** |
| Bad Hosts – Kubernetes | **698** |
| Bad Hosts – Redis | **458** |
| Bad Hosts – Elasticsearch | **421** |
| Bad Hosts – CouchDB | **249** |
| Bad Hosts – ClickhouseHTTP | **256** |
| Bad Hosts – Oracle | **242** |
| Bad Hosts – Modbus | **171** |
| Bad Hosts – RAW | **256** |
| Bad Hosts – LDAP | **240** |
| Bad Hosts – MQTT | **217** |
| Bad Hosts – Memcached | **221** |
| Bad Hosts – IPP | **106** |
| Bad Hosts – HashCountRandom | **194** |
| Bad Hosts – LPD | **87** |
| Bad Hosts – MOTD | **54** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **35,322** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **35,322** |
| 2026-09-17 | **3,180** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **42,158** |
| Kandidaten dieses Abrufs | **42,158** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+603** |
| Entfernt | **-373** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 23:18 CEST (Berlin)*