# Honigtopf – Report
**Aktualisiert:** 2026-09-23 07:17 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 07:17 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,309** |
| Bad Hosts – SIP | **237** |
| Bad Hosts – RDP | **966** |
| Bad Hosts – SSH | **3,975** |
| Bad Hosts – MSSQL | **569** |
| Bad Hosts – SNMP | **398** |
| Bad Hosts – HTTP | **2,896** |
| Bad Hosts – VNC | **420** |
| Bad Hosts – Telnet | **2,877** |
| Bad Hosts – TFTP | **189** |
| Bad Hosts – MySQL | **685** |
| Bad Hosts – ProConOs | **156** |
| Bad Hosts – PostgreSQL | **530** |
| Bad Hosts – FTP | **594** |
| Bad Hosts – Kubernetes | **711** |
| Bad Hosts – Redis | **458** |
| Bad Hosts – Elasticsearch | **576** |
| Bad Hosts – CouchDB | **259** |
| Bad Hosts – ClickhouseHTTP | **279** |
| Bad Hosts – Oracle | **281** |
| Bad Hosts – RAW | **269** |
| Bad Hosts – LDAP | **324** |
| Bad Hosts – Modbus | **225** |
| Bad Hosts – MQTT | **237** |
| Bad Hosts – Memcached | **236** |
| Bad Hosts – IPP | **136** |
| Bad Hosts – LPD | **106** |
| Bad Hosts – HashCountRandom | **109** |
| Bad Hosts – MOTD | **57** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-23)**: **3,642** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-23 | **3,642** |
| 2026-09-22 | **7,667** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,206** |
| Kandidaten dieses Abrufs | **14,206** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+233** |
| Entfernt | **-326** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 07:17 CEST (Berlin)*