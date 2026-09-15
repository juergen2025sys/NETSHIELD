# Honigtopf – Report
**Aktualisiert:** 2026-09-15 23:33 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-15 23:33 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **47,750** |
| Bad Hosts – SIP | **198** |
| Bad Hosts – RDP | **1,261** |
| Bad Hosts – SSH | **3,973** |
| Bad Hosts – MSSQL | **602** |
| Bad Hosts – VNC | **1,616** |
| Bad Hosts – HTTP | **4,985** |
| Bad Hosts – FTP | **33,877** |
| Bad Hosts – SNMP | **501** |
| Bad Hosts – TFTP | **223** |
| Bad Hosts – ProConOs | **229** |
| Bad Hosts – Telnet | **3,384** |
| Bad Hosts – MySQL | **746** |
| Bad Hosts – PostgreSQL | **620** |
| Bad Hosts – Kubernetes | **746** |
| Bad Hosts – Redis | **458** |
| Bad Hosts – CouchDB | **281** |
| Bad Hosts – Elasticsearch | **515** |
| Bad Hosts – ClickhouseHTTP | **334** |
| Bad Hosts – Oracle | **310** |
| Bad Hosts – Modbus | **229** |
| Bad Hosts – Memcached | **244** |
| Bad Hosts – LDAP | **224** |
| Bad Hosts – MQTT | **271** |
| Bad Hosts – HashCountRandom | **241** |
| Bad Hosts – IPP | **141** |
| Bad Hosts – RAW | **186** |
| Bad Hosts – LPD | **95** |
| Bad Hosts – MOTD | **68** |
| Bad Hosts – Echo | **5** |
| Bad Hosts – WebLogic | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-15)**: **44,678** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-15 | **44,678** |
| 2026-09-14 | **3,072** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **51,520** |
| Kandidaten dieses Abrufs | **51,520** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,419** |
| Entfernt | **-2,510** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-15 23:33 CEST (Berlin)*