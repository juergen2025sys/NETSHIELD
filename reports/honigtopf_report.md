# Honigtopf – Report
**Aktualisiert:** 2026-10-06 08:56 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ unklar (410) – im Pool belassen |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 08:56 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,431** |
| Bad Hosts – SSH | **3,727** |
| Bad Hosts – SIP | **167** |
| Bad Hosts – SNMP | **420** |
| Bad Hosts – MSSQL | **514** |
| Bad Hosts – RDP | **875** |
| Bad Hosts – HTTP | **3,684** |
| Bad Hosts – VNC | **379** |
| Bad Hosts – TFTP | **225** |
| Bad Hosts – Telnet | **2,630** |
| Bad Hosts – MySQL | **595** |
| Bad Hosts – Memcached | **209** |
| Bad Hosts – ProConOs | **132** |
| Bad Hosts – Kubernetes | **810** |
| Bad Hosts – Redis | **447** |
| Bad Hosts – PostgreSQL | **545** |
| Bad Hosts – FTP | **555** |
| Bad Hosts – CouchDB | **394** |
| Bad Hosts – Elasticsearch | **700** |
| Bad Hosts – ClickhouseHTTP | **366** |
| Bad Hosts – Oracle | **268** |
| Bad Hosts – LDAP | **254** |
| Bad Hosts – Modbus | **204** |
| Bad Hosts – MQTT | **232** |
| Bad Hosts – IPP | **119** |
| Bad Hosts – RAW | **124** |
| Bad Hosts – LPD | **80** |
| Bad Hosts – HashCountRandom | **88** |
| Bad Hosts – MOTD | **71** |
| Bad Hosts – Echo | **6** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **4,572** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **4,572** |
| 2026-10-05 | **6,859** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,224** |
| Kandidaten dieses Abrufs | **14,224** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,778** |
| Entfernt | **-2,050** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 08:56 CEST (Berlin)*