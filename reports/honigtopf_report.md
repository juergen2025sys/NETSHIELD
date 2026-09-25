# Honigtopf – Report
**Aktualisiert:** 2026-09-25 21:04 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-25 21:04 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,159** |
| Bad Hosts – SIP | **150** |
| Bad Hosts – SSH | **3,371** |
| Bad Hosts – RDP | **795** |
| Bad Hosts – HTTP | **3,595** |
| Bad Hosts – MSSQL | **496** |
| Bad Hosts – VNC | **326** |
| Bad Hosts – TFTP | **203** |
| Bad Hosts – SNMP | **355** |
| Bad Hosts – ProConOs | **129** |
| Bad Hosts – Telnet | **2,881** |
| Bad Hosts – PostgreSQL | **448** |
| Bad Hosts – MySQL | **615** |
| Bad Hosts – FTP | **489** |
| Bad Hosts – Kubernetes | **652** |
| Bad Hosts – Elasticsearch | **559** |
| Bad Hosts – Redis | **435** |
| Bad Hosts – CouchDB | **216** |
| Bad Hosts – ClickhouseHTTP | **230** |
| Bad Hosts – Oracle | **257** |
| Bad Hosts – Memcached | **178** |
| Bad Hosts – MQTT | **182** |
| Bad Hosts – Modbus | **169** |
| Bad Hosts – LDAP | **204** |
| Bad Hosts – RAW | **129** |
| Bad Hosts – IPP | **85** |
| Bad Hosts – LPD | **55** |
| Bad Hosts – HashCountRandom | **24** |
| Bad Hosts – MOTD | **15** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-25)**: **9,442** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-25 | **9,442** |
| 2026-09-24 | **1,717** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,577** |
| Kandidaten dieses Abrufs | **13,577** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+116** |
| Entfernt | **-800** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-25 21:04 CEST (Berlin)*