# Honigtopf – Report
**Aktualisiert:** 2026-09-22 23:34 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-22 23:34 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,230** |
| Bad Hosts – SIP | **270** |
| Bad Hosts – RDP | **963** |
| Bad Hosts – MSSQL | **548** |
| Bad Hosts – SSH | **3,940** |
| Bad Hosts – SNMP | **410** |
| Bad Hosts – HTTP | **2,942** |
| Bad Hosts – VNC | **342** |
| Bad Hosts – Telnet | **2,830** |
| Bad Hosts – TFTP | **221** |
| Bad Hosts – MySQL | **670** |
| Bad Hosts – ProConOs | **152** |
| Bad Hosts – PostgreSQL | **618** |
| Bad Hosts – FTP | **554** |
| Bad Hosts – Kubernetes | **732** |
| Bad Hosts – Redis | **421** |
| Bad Hosts – Elasticsearch | **567** |
| Bad Hosts – CouchDB | **269** |
| Bad Hosts – ClickhouseHTTP | **271** |
| Bad Hosts – MQTT | **243** |
| Bad Hosts – Oracle | **291** |
| Bad Hosts – Modbus | **225** |
| Bad Hosts – LDAP | **300** |
| Bad Hosts – RAW | **227** |
| Bad Hosts – Memcached | **261** |
| Bad Hosts – IPP | **129** |
| Bad Hosts – LPD | **102** |
| Bad Hosts – HashCountRandom | **106** |
| Bad Hosts – MOTD | **62** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-22)**: **10,426** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-22 | **10,426** |
| 2026-09-21 | **804** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,153** |
| Kandidaten dieses Abrufs | **14,153** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+300** |
| Entfernt | **-268** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-22 23:34 CEST (Berlin)*