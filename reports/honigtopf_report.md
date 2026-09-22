# Honigtopf – Report
**Aktualisiert:** 2026-09-22 12:18 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-22 12:18 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,242** |
| Bad Hosts – SIP | **262** |
| Bad Hosts – RDP | **967** |
| Bad Hosts – SSH | **4,351** |
| Bad Hosts – MSSQL | **525** |
| Bad Hosts – SNMP | **387** |
| Bad Hosts – HTTP | **3,731** |
| Bad Hosts – TFTP | **223** |
| Bad Hosts – VNC | **359** |
| Bad Hosts – Telnet | **2,854** |
| Bad Hosts – MySQL | **590** |
| Bad Hosts – PostgreSQL | **619** |
| Bad Hosts – ProConOs | **135** |
| Bad Hosts – FTP | **583** |
| Bad Hosts – Kubernetes | **705** |
| Bad Hosts – Redis | **401** |
| Bad Hosts – CouchDB | **243** |
| Bad Hosts – Elasticsearch | **550** |
| Bad Hosts – ClickhouseHTTP | **289** |
| Bad Hosts – MQTT | **227** |
| Bad Hosts – Oracle | **278** |
| Bad Hosts – LDAP | **280** |
| Bad Hosts – Memcached | **232** |
| Bad Hosts – Modbus | **205** |
| Bad Hosts – RAW | **149** |
| Bad Hosts – IPP | **97** |
| Bad Hosts – LPD | **89** |
| Bad Hosts – HashCountRandom | **90** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-22)**: **5,992** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-22 | **5,992** |
| 2026-09-21 | **6,250** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,197** |
| Kandidaten dieses Abrufs | **15,197** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+226** |
| Entfernt | **-234** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-22 12:18 CEST (Berlin)*