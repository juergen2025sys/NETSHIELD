# Honigtopf – Report
**Aktualisiert:** 2026-09-22 02:57 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-22 02:57 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,091** |
| Bad Hosts – SIP | **194** |
| Bad Hosts – RDP | **1,003** |
| Bad Hosts – SSH | **4,306** |
| Bad Hosts – MSSQL | **503** |
| Bad Hosts – SNMP | **401** |
| Bad Hosts – HTTP | **3,766** |
| Bad Hosts – TFTP | **203** |
| Bad Hosts – VNC | **386** |
| Bad Hosts – MySQL | **576** |
| Bad Hosts – Telnet | **2,857** |
| Bad Hosts – ProConOs | **129** |
| Bad Hosts – PostgreSQL | **563** |
| Bad Hosts – FTP | **568** |
| Bad Hosts – Kubernetes | **682** |
| Bad Hosts – Redis | **379** |
| Bad Hosts – Elasticsearch | **506** |
| Bad Hosts – CouchDB | **291** |
| Bad Hosts – Oracle | **261** |
| Bad Hosts – ClickhouseHTTP | **221** |
| Bad Hosts – LDAP | **227** |
| Bad Hosts – MQTT | **182** |
| Bad Hosts – Memcached | **190** |
| Bad Hosts – Modbus | **157** |
| Bad Hosts – RAW | **181** |
| Bad Hosts – IPP | **102** |
| Bad Hosts – LPD | **93** |
| Bad Hosts – HashCountRandom | **67** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – MOTD | **47** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-22)**: **1,001** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-22 | **1,001** |
| 2026-09-21 | **11,090** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,950** |
| Kandidaten dieses Abrufs | **14,950** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+343** |
| Entfernt | **-279** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-22 02:57 CEST (Berlin)*